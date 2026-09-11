"""
Unit and integration-style tests for Attack-Surface Risk-Mapper.

These tests deliberately do not invoke real Sherlock, theHarvester, or Amass.
External tools are exercised through their runners during manual/end-to-end
validation; here we test normalization, correlation, scoring, report writing,
and CLI dispatch using synthetic results and mocked runner calls.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aggregator import cli
from aggregator.report import builder


class TestNormalizationHelpers(unittest.TestCase):
    def test_hostname_normalization(self):
        self.assertEqual(builder.normalize_hostname("  WWW.Example.COM. "), "www.example.com")

    def test_email_normalization(self):
        self.assertEqual(builder.normalize_email("  USER@Example.COM "), "user@example.com")

    def test_ip_normalization(self):
        self.assertEqual(builder.normalize_ip("  192.0.2.10 "), "192.0.2.10")

    def test_ipv6_normalization(self):
        self.assertEqual(
            builder.normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1",
        )

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(builder.normalize_ip("not-an-ip"))

    def test_netblock_normalization(self):
        self.assertEqual(builder.normalize_netblock("203.0.113.5/24"), "203.0.113.0/24")

    def test_invalid_netblock_returns_none(self):
        self.assertIsNone(builder.normalize_netblock("not-a-network"))

    def test_target_subdomain_membership(self):
        self.assertTrue(builder.is_target_subdomain("api.example.com", "example.com"))
        self.assertFalse(builder.is_target_subdomain("example.com", "example.com"))
        self.assertFalse(builder.is_target_subdomain("example.com.evil.test", "example.com"))


class TestSherlockNormalization(unittest.TestCase):
    def test_sherlock_account_match(self):
        raw = {
            "tool": "sherlock",
            "target": "redpandabytes1",
            "found": [
                {"site": "GitHub", "url": "https://github.com/redpandabytes1"},
                {"site": "Example", "url": "https://example.test/redpandabytes1"},
            ],
        }
        findings = builder.normalize_sherlock(raw)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["type"], "account_match")
        self.assertEqual(findings[0]["value"], "https://github.com/redpandabytes1")
        self.assertEqual(findings[0]["sources"], ["sherlock"])

    def test_sherlock_ignores_malformed_entries(self):
        raw = {
            "found": [
                {"site": "MissingURL"},
                "not-a-dict",
                {"site": "Valid", "url": "https://example.test/user"},
            ]
        }
        findings = builder.normalize_sherlock(raw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["value"], "https://example.test/user")


class TestTheHarvesterNormalization(unittest.TestCase):
    def test_hosts_are_filtered_to_target_subdomains(self):
        raw = {
            "tool": "theharvester",
            "target": "example.com",
            "hosts": [
                "API.Example.COM.",
                "example.com",
                "www.example.com",
                "other.example.net",
                "malicious-example.com",
            ],
            "emails": [" ADMIN@Example.COM ", "User@example.com"],
        }
        findings = builder.normalize_theharvester(raw)
        subdomains = {f["value"] for f in findings if f["type"] == "subdomain"}
        emails = {f["value"] for f in findings if f["type"] == "email"}
        self.assertEqual(subdomains, {"api.example.com", "www.example.com"})
        self.assertEqual(emails, {"admin@example.com", "user@example.com"})

    def test_theharvester_without_target_does_not_invent_membership(self):
        raw = {"hosts": ["api.example.com"], "emails": []}
        self.assertEqual(builder.normalize_theharvester(raw), [])


class TestAmassNormalization(unittest.TestCase):
    def test_amass_extracts_both_relationship_endpoints(self):
        raw = {
            "tool": "amass",
            "target": "example.com",
            "subdomains": [
                "api.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)",
                "192.0.2.0/24 (Netblock) --> contains --> 192.0.2.10 (IPAddress)",
                "64500 (ASN) --> announces --> 192.0.2.0/24 (Netblock)",
                "64500 (ASN) --> managed_by --> Example Org (RIROrganization)",
                "api.example.com (FQDN) --> cname_record --> cdn.example.net (FQDN)",
            ],
        }
        findings = builder.normalize_amass(raw)
        keys = {(f["type"], f["value"]) for f in findings}
        self.assertIn(("subdomain", "api.example.com"), keys)
        self.assertIn(("ip_address", "192.0.2.10"), keys)
        self.assertIn(("netblock", "192.0.2.0/24"), keys)
        self.assertIn(("asn", "64500"), keys)
        self.assertIn(("organization", "Example Org"), keys)
        self.assertIn(("external_hostname", "cdn.example.net"), keys)

    def test_root_domain_is_not_a_finding(self):
        raw = {
            "target": "example.com",
            "subdomains": ["example.com (FQDN) --> node --> api.example.com (FQDN)"],
        }
        keys = {(f["type"], f["value"]) for f in builder.normalize_amass(raw)}
        self.assertNotIn(("subdomain", "example.com"), keys)
        self.assertNotIn(("external_hostname", "example.com"), keys)
        self.assertIn(("subdomain", "api.example.com"), keys)

    def test_reverse_dns_hostname_is_ignored(self):
        raw = {
            "target": "example.com",
            "subdomains": [
                "api.example.com (FQDN) --> ptr_record --> 10.2.0.192.in-addr.arpa (FQDN)"
            ],
        }
        keys = {(f["type"], f["value"]) for f in builder.normalize_amass(raw)}
        self.assertIn(("subdomain", "api.example.com"), keys)
        self.assertNotIn(("external_hostname", "10.2.0.192.in-addr.arpa"), keys)

    def test_plain_hostname_fallback_is_normalized(self):
        raw = {"target": "example.com", "subdomains": ["MiXeD.Example.COM."]}
        self.assertEqual(
            builder.normalize_amass(raw),
            [{"type": "subdomain", "value": "mixed.example.com", "sources": ["amass"]}],
        )


class TestMergeAndConfidence(unittest.TestCase):
    def test_dedup_merges_distinct_sources(self):
        findings = [
            {"type": "subdomain", "value": "api.example.com", "sources": ["theharvester"]},
            {"type": "subdomain", "value": "api.example.com", "sources": ["amass"]},
            {"type": "subdomain", "value": "api.example.com", "sources": ["amass"]},
        ]
        merged = builder.merge_findings(findings)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["sources"], ["theharvester", "amass"])
        self.assertEqual(merged[0]["confidence"], "high")

    def test_single_source_is_medium(self):
        merged = builder.merge_findings([
            {"type": "email", "value": "user@example.com", "sources": ["theharvester"]}
        ])
        self.assertEqual(merged[0]["confidence"], "medium")

    def test_malformed_findings_are_skipped(self):
        merged = builder.merge_findings([
            {},
            {"type": "subdomain"},
            {"value": "api.example.com"},
            {"type": "subdomain", "value": "api.example.com", "sources": ["amass"]},
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["value"], "api.example.com")


class TestScoring(unittest.TestCase):
    def test_supported_types_have_expected_base_scores(self):
        expected = {
            "account_match": 2.0,
            "subdomain": 3.0,
            "email": 2.0,
            "ip_address": 3.0,
            "netblock": 1.5,
            "asn": 1.5,
            "organization": 1.0,
            "external_hostname": 2.5,
        }
        for finding_type, base in expected.items():
            with self.subTest(finding_type=finding_type):
                self.assertEqual(
                    builder.score_finding({"type": finding_type, "confidence": "medium"}),
                    base,
                )
                self.assertEqual(
                    builder.score_finding({"type": finding_type, "confidence": "high"}),
                    round(base * 1.5, 1),
                )

    def test_low_confidence_multiplier(self):
        self.assertEqual(
            builder.score_finding({"type": "subdomain", "confidence": "low"}),
            2.1,
        )

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            builder.score_finding({"type": "not_a_real_type", "confidence": "medium"})

    def test_unknown_confidence_raises(self):
        with self.assertRaises(ValueError):
            builder.score_finding({"type": "subdomain", "confidence": "unknown"})


class TestReportGeneration(unittest.TestCase):
    def test_generate_report_deduplicates_and_sorts(self):
        results = {
            "sherlock": {
                "tool": "sherlock",
                "target": "redpandabytes1",
                "found": [{"site": "GitHub", "url": "https://github.com/redpandabytes1"}],
            },
            "theharvester": {
                "tool": "theharvester",
                "target": "example.com",
                "hosts": ["api.example.com"],
                "emails": [],
            },
            "amass": {
                "tool": "amass",
                "target": "example.com",
                "subdomains": [
                    "api.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)"
                ],
            },
        }
        findings = builder.generate_report(results)["findings"]
        scores = [f["score"] for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))
        api = [f for f in findings if f["type"] == "subdomain" and f["value"] == "api.example.com"]
        self.assertEqual(len(api), 1)
        self.assertEqual(api[0]["sources"], ["theharvester", "amass"])
        self.assertEqual(api[0]["confidence"], "high")
        self.assertEqual(api[0]["score"], 4.5)

    def test_empty_results_are_not_findings(self):
        report = builder.generate_report({
            "sherlock": {"found": []},
            "theharvester": {"target": "example.com", "hosts": [], "emails": []},
            "amass": {"target": "example.com", "subdomains": []},
        })
        self.assertEqual(report, {"findings": []})

    def test_write_report_escapes_pipes(self):
        report = {
            "findings": [
                {
                    "score": 2.0,
                    "type": "email",
                    "value": "foo|bar@example.com",
                    "confidence": "medium",
                    "sources": ["theharvester"],
                },
                {
                    "score": 4.5,
                    "type": "subdomain",
                    "value": "api.example.com",
                    "confidence": "high",
                    "sources": ["amass", "theharvester"],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.md"
            builder.write_report(report, str(output))
            text = output.read_text(encoding="utf-8")
        self.assertIn("**2 findings** — 1 high-confidence, 1 medium-confidence", text)
        self.assertIn(r"foo\|bar@example.com", text)
        self.assertIn("| Score | Type | Value | Confidence | Sources |", text)


class TestCLI(unittest.TestCase):
    def test_parser_accepts_final_arguments(self):
        parser = cli.build_arg_parser()
        args = parser.parse_args([
            "--username", "alice",
            "--domain", "example.com",
            "--tools", "sherlock,theharvester",
            "--output", "report.md",
        ])
        self.assertEqual(args.username, "alice")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.tools, "sherlock,theharvester")
        self.assertEqual(args.output, "report.md")

    @patch("aggregator.cli.builder.write_report")
    @patch("aggregator.cli.builder.generate_report")
    @patch("aggregator.cli.amass_runner.run")
    @patch("aggregator.cli.theharvester_runner.run")
    @patch("aggregator.cli.sherlock_runner.run")
    def test_cli_dispatches_each_tool_to_correct_target(
        self, sherlock_run, theharvester_run, amass_run, generate_report, write_report
    ):
        sherlock_run.return_value = {"tool": "sherlock", "found": []}
        theharvester_run.return_value = {
            "tool": "theharvester", "target": "example.com", "hosts": [], "emails": []
        }
        amass_run.return_value = {"tool": "amass", "target": "example.com", "subdomains": []}
        generate_report.return_value = {"findings": []}
        argv = [
            "cli.py", "--username", "alice", "--domain", "example.com",
            "--tools", "sherlock,theharvester,amass", "--output", "report.md",
        ]
        with patch("sys.argv", argv):
            exit_code = cli.main()
        self.assertEqual(exit_code, 0)
        sherlock_run.assert_called_once_with("alice")
        theharvester_run.assert_called_once_with("example.com")
        amass_run.assert_called_once_with("example.com")
        generate_report.assert_called_once()
        write_report.assert_called_once_with({"findings": []}, "report.md")

    @patch("aggregator.cli.builder.write_report")
    @patch("aggregator.cli.builder.generate_report")
    @patch("aggregator.cli.sherlock_runner.run")
    def test_cli_can_run_username_only(self, sherlock_run, generate_report, write_report):
        sherlock_run.return_value = {"tool": "sherlock", "target": "alice", "found": []}
        generate_report.return_value = {"findings": []}
        argv = ["cli.py", "--username", "alice", "--tools", "sherlock", "--output", "report.md"]
        with patch("sys.argv", argv):
            exit_code = cli.main()
        self.assertEqual(exit_code, 0)
        sherlock_run.assert_called_once_with("alice")

    @patch("aggregator.cli.builder.write_report")
    @patch("aggregator.cli.builder.generate_report")
    @patch("aggregator.cli.theharvester_runner.run")
    @patch("aggregator.cli.amass_runner.run")
    def test_cli_can_run_domain_only(self, amass_run, theharvester_run, generate_report, write_report):
        theharvester_run.return_value = {
            "tool": "theharvester", "target": "example.com", "hosts": [], "emails": []
        }
        amass_run.return_value = {"tool": "amass", "target": "example.com", "subdomains": []}
        generate_report.return_value = {"findings": []}
        argv = ["cli.py", "--domain", "example.com", "--tools", "theharvester,amass", "--output", "report.md"]
        with patch("sys.argv", argv):
            exit_code = cli.main()
        self.assertEqual(exit_code, 0)
        theharvester_run.assert_called_once_with("example.com")
        amass_run.assert_called_once_with("example.com")

    def test_cli_with_no_targets_returns_error(self):
        argv = ["cli.py", "--tools", "sherlock,theharvester,amass", "--output", "report.md"]
        with patch("sys.argv", argv):
            exit_code = cli.main()
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
