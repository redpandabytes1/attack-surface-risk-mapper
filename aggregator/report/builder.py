"""
Combines raw results from each OSINT tool runner into a single,
normalized, deduplicated report.

The normalization rules implemented here are defined in schema_notes.md.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def normalize_hostname(value: str) -> str:
    """
    Normalize a DNS hostname for consistent comparison.

    Rules:
    - remove surrounding whitespace
    - lowercase
    - remove a trailing DNS dot
    """
    value = value.strip().lower()

    if value.endswith("."):
        value = value[:-1]

    return value


def normalize_email(value: str) -> str:
    """Normalize an email address for consistent comparison."""
    return value.strip().lower()


def normalize_ip(value: str) -> Optional[str]:
    """
    Validate and normalize an IPv4/IPv6 address.

    Returns None when the value is not a valid IP address.
    """
    value = value.strip()

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_netblock(value: str) -> Optional[str]:
    """
    Validate and normalize an IPv4/IPv6 network in CIDR notation.

    strict=False allows a network such as 203.0.113.5/24 to normalize to
    203.0.113.0/24 instead of rejecting it.
    """
    value = value.strip()

    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def is_target_subdomain(value: str, target: str) -> bool:
    """
    Return True when value is a hostname strictly below the target domain.

    The target itself returns False on purpose — the root domain is not
    itself a "discovered subdomain". Moved here (from the Amass section)
    because theHarvester's normalizer now uses the same rule, for
    consistency between the two DNS-based sources.
    """
    value = normalize_hostname(value)
    target = normalize_hostname(target)

    if value == target:
        return False

    return value.endswith("." + target)


# ---------------------------------------------------------------------------
# Sherlock
# ---------------------------------------------------------------------------

def normalize_sherlock(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert Sherlock account matches into the common finding structure.
    """

    findings: List[Dict[str, Any]] = []

    for item in raw.get("found", []):
        if not isinstance(item, dict):
            continue

        url = item.get("url")

        if not url:
            continue

        findings.append(
            {
                "type": "account_match",
                "value": url.strip(),
                "sources": ["sherlock"],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# theHarvester
# ---------------------------------------------------------------------------

def normalize_theharvester(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert theHarvester hosts and emails into common findings.

    Hosts become subdomains. Emails become email findings.

    FIX: now applies the same target-membership rule used for Amass
    (via is_target_subdomain) instead of accepting every returned host
    unconditionally — this excludes the bare target root and anything
    theHarvester might return that isn't actually under the target,
    keeping both DNS-based sources consistent.
    """

    findings: List[Dict[str, Any]] = []
    target = raw.get("target", "").strip()

    for host in raw.get("hosts", []):
        if not isinstance(host, str):
            continue

        host = normalize_hostname(host)

        if not host:
            continue

        if not target or not is_target_subdomain(host, target):
            continue

        findings.append(
            {
                "type": "subdomain",
                "value": host,
                "sources": ["theharvester"],
            }
        )

    for email in raw.get("emails", []):
        if not isinstance(email, str):
            continue

        email = normalize_email(email)

        if email:
            findings.append(
                {
                    "type": "email",
                    "value": email,
                    "sources": ["theharvester"],
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Amass
# ---------------------------------------------------------------------------

AMASS_RELATIONSHIP_PATTERN = re.compile(
    r"^\s*(.*?)\s+\(([^)]+)\)\s+-->\s+(\S+)\s+-->\s+(.*?)\s+\(([^)]+)\)\s*$"
)


def add_finding(
    findings: List[Dict[str, Any]],
    finding_type: str,
    value: str,
    source: str = "amass",
) -> None:
    """Append a valid normalized finding."""

    if not value:
        return

    findings.append(
        {
            "type": finding_type,
            "value": value,
            "sources": [source],
        }
    )


def classify_amass_entity(
    value: str,
    entity_kind: str,
    target: str,
    findings: List[Dict[str, Any]],
) -> None:
    """
    Convert one Amass graph entity into a normalized finding.

    entity_kind comes from Amass's labels, for example:
    FQDN, IPAddress, Netblock, ASN, RIROrganization.
    """

    value = value.strip()

    if not value:
        return

    normalized_kind = entity_kind.strip().lower()

    if normalized_kind == "fqdn":
        hostname = normalize_hostname(value)

        if not hostname:
            return

        normalized_target = normalize_hostname(target)

        # FIX: the target root itself was previously falling into the
        # "else" branch below and being misclassified as external_hostname.
        # It's neither a subdomain nor external infrastructure — it's the
        # target itself, and isn't a finding at all.
        if hostname == normalized_target:
            return

        # A target-domain FQDN is a subdomain.
        if is_target_subdomain(hostname, target):
            add_finding(findings, "subdomain", hostname)

        # A non-target FQDN discovered through an Amass relationship is
        # external infrastructure/service context.
        else:
            # Ignore reverse-DNS infrastructure names as standalone findings.
            if hostname.endswith(".in-addr.arpa") or hostname.endswith(
                ".ip6.arpa"
            ):
                return

            add_finding(findings, "external_hostname", hostname)

    elif normalized_kind == "ipaddress":
        normalized_ip = normalize_ip(value)

        if normalized_ip:
            add_finding(findings, "ip_address", normalized_ip)

    elif normalized_kind == "netblock":
        normalized_network = normalize_netblock(value)

        if normalized_network:
            add_finding(findings, "netblock", normalized_network)

    elif normalized_kind == "asn":
        # Amass represents ASN values as identifiers such as 55847.
        asn = value.strip()

        if asn:
            add_finding(findings, "asn", asn)

    elif normalized_kind == "rirorganization":
        # FIX: was "riroorganization" (extra "o") — never matched the real
        # entity kind, so every organization entity was silently dropped.
        organization = value.strip()

        if organization:
            add_finding(findings, "organization", organization)


def normalize_amass(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse Amass's graph-style relationship strings into normalized findings.

    Example input:

        host.example.com (FQDN) --> a_record --> 203.0.113.10 (IPAddress)

    produces:

        {
            "type": "subdomain",
            "value": "host.example.com",
            ...
        }

        {
            "type": "ip_address",
            "value": "203.0.113.10",
            ...
        }

    The target domain is obtained from raw["target"].
    """

    findings: List[Dict[str, Any]] = []
    target = raw.get("target", "").strip()

    if not target:
        return findings

    for record in raw.get("subdomains", []):
        if not isinstance(record, str):
            continue

        match = AMASS_RELATIONSHIP_PATTERN.match(record)

        if not match:
            # Defensive fallback for a future/plain hostname output format.
            possible_hostname = record.strip()

            if is_target_subdomain(possible_hostname, target):
                add_finding(
                    findings,
                    "subdomain",
                    normalize_hostname(possible_hostname),
                )

            continue

        left_value, left_kind, _relationship, right_value, right_kind = (
            match.groups()
        )

        # Extract both endpoints. This is important because records such as:
        #
        #   ASN --> announces --> Netblock
        #
        # contain useful information on both sides.
        classify_amass_entity(
            left_value,
            left_kind,
            target,
            findings,
        )

        classify_amass_entity(
            right_value,
            right_kind,
            target,
            findings,
        )

    return findings


# ---------------------------------------------------------------------------
# Deduplication and confidence
# ---------------------------------------------------------------------------

def merge_findings(all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings using:

        (type, normalized value)

    When the same finding is seen by multiple tools, their source names are
    merged. Repeated observations from the same tool do not create duplicate
    source entries.
    """

    merged: Dict[tuple, Dict[str, Any]] = {}

    for finding in all_findings:
        finding_type = finding.get("type")
        value = finding.get("value")

        if not finding_type or not value:
            continue

        key = (finding_type, value)

        if key not in merged:
            merged[key] = {
                "type": finding_type,
                "value": value,
                "sources": list(finding.get("sources", [])),
            }

            continue

        for source in finding.get("sources", []):
            if source not in merged[key]["sources"]:
                merged[key]["sources"].append(source)

    for finding in merged.values():
        finding["confidence"] = (
            "high"
            if len(finding["sources"]) >= 2
            else "medium"
        )

    return list(merged.values())


# ---------------------------------------------------------------------------
# The Scoring Function
# ---------------------------------------------------------------------------

BASE_SCORES = {
    "account_match": 2.0,
    "subdomain": 3.0,
    "email": 2.0,
    "ip_address": 3.0,
    "netblock": 1.5,
    "asn": 1.5,
    "organization": 1.0,
    "external_hostname": 2.5,
}

CONFIDENCE_MULTIPLIER = {
    "high": 1.5,
    "medium": 1.0,
    "low": 0.7,
}

def score_finding(finding: Dict[str, Any]) -> float:
    finding_type = finding["type"]
    confidence = finding["confidence"]

    if finding_type not in BASE_SCORES:
        raise ValueError(
            f"Unsupported finding type for scoring: {finding_type!r}"
        )

    if confidence not in CONFIDENCE_MULTIPLIER:
        raise ValueError(
            f"Unsupported confidence value: {confidence!r}"
        )

    base = BASE_SCORES[finding_type]
    multiplier = CONFIDENCE_MULTIPLIER[confidence]

    return round(base * multiplier, 1)


# ---------------------------------------------------------------------------
# Public report API
# ---------------------------------------------------------------------------

def generate_report(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize, deduplicate, and assign confidence to all tool findings.
    """

    all_findings: List[Dict[str, Any]] = []

    if "sherlock" in results:
        all_findings.extend(
            normalize_sherlock(results["sherlock"])
        )

    if "theharvester" in results:
        all_findings.extend(
            normalize_theharvester(results["theharvester"])
        )

    if "amass" in results:
        all_findings.extend(
            normalize_amass(results["amass"])
        )

    findings = merge_findings(all_findings)

    # FIX: merge_findings() already assigns confidence above — this used to
    # redundantly recompute the identical value a second time here.
    for f in findings:
        f["score"] = score_finding(f)

    findings_sorted = sorted(
        findings,
        key=lambda f: f["score"],
        reverse=True,
    )

    return {"findings": findings_sorted}


def _escape_md(value: str) -> str:
    """
    Escape Markdown table-breaking characters in a value.
    """
    return str(value).replace("|", "\\|")


def write_report(report: Dict[str, Any], output_path: str) -> None:
    """
    Write the normalized, scored findings as a readable Markdown report.
    """
    findings = report["findings"]

    high = sum(
        1
        for finding in findings
        if finding["confidence"] == "high"
    )

    medium = len(findings) - high

    lines = [
        "# Attack-Surface Risk Report",
        "",
        (
            f"**{len(findings)} findings** — "
            f"{high} high-confidence, "
            f"{medium} medium-confidence"
        ),
        "",
        "| Score | Type | Value | Confidence | Sources |",
        "|---|---|---|---|---|",
    ]

    for finding in findings:
        sources_str = ", ".join(finding["sources"])

        lines.append(
            f"| {finding['score']} "
            f"| {finding['type']} "
            f"| {_escape_md(finding['value'])} "
            f"| {finding['confidence']} "
            f"| {_escape_md(sources_str)} |"
        )

    with open(output_path, "w", encoding="utf-8") as out:
        out.write("\n".join(lines))
