# Attack-Surface Risk-Mapper - Passive OSINT Aggregation Pipeline

## Date & Scope

- **Date:** September 2026
- **Target/scope:** Development and practice data used to validate a passive OSINT aggregation pipeline. The final public example is intended to use an explicitly authorized practice target rather than publishing the richer institutional development dataset.
- **Authorization:** Authorized OSINT research only — personal/practice targets, CTF environments, explicitly permitted bug-bounty scope, or contracted engagements.

## Objective

The objective was to build a small but defensible OSINT aggregation pipeline that could run Sherlock, theHarvester, and Amass from one command, normalize their very different outputs into a common finding model, correlate overlapping observations, assign confidence based on independent tool corroboration, apply heuristic priority scoring, and produce one readable Markdown report.

The practical problem was simple: running the tools separately meant manually comparing unrelated output formats and deciding which results represented the same underlying entity. The project was built to automate that correlation rather than treating each tool's output as an isolated list.

## Tools Used

### OSINT / enumeration tools

- **Sherlock** - username/account discovery
- **theHarvester** - passive hostname and email discovery
- **Amass** - passive/domain intelligence and graph-style relationship discovery

### Development tools

- Python 3
- Python virtual environment
- `subprocess` for invoking external tools
- `argparse` for the command-line interface
- Project regression/unit tests
- Git for version control
- Markdown for report generation

## Methodology

### 1. Define separate target types

The first design decision was to separate username and domain inputs instead of treating all targets as one generic string.

The final CLI therefore accepts:

```bash
python -m aggregator.cli --username <username> --domain <domain> --output report.md
```

Sherlock receives the username, while theHarvester and Amass receive the domain.

This avoids the original design problem where one `--target` value would be passed indiscriminately to all tools even though they expect different target types.

### 2. Verify the external tools independently

Before building the aggregation layer, each external tool was run manually to understand its real output and runtime behavior.

This was particularly important because the tools did not produce interchangeable data:

- Sherlock produced account/profile matches.
- theHarvester produced host and email collections.
- Amass produced relationship-oriented records rather than a simple list of subdomains.

The real command-line behavior was treated as the implementation contract rather than relying on an assumed output format.

### 3. Build tool-specific runners

Each external tool was placed behind its own runner:

```text
aggregator/runners/
├── sherlock_runner.py
├── theharvester_runner.py
└── amass_runner.py
```

The runners are responsible for invoking the external program, collecting its output, handling failures/timeouts, and returning structured raw results.

This isolates tool-specific parsing from the rest of the project.

### 4. Design a unified finding schema

The normalization layer uses eight finding categories:

```text
account_match
subdomain
email
ip_address
netblock
asn
organization
external_hostname
```

The normalized `value` is the canonical representation of the entity.

Examples:

```text
account_match      -> complete account/profile URL
subdomain         -> target-domain FQDN
email             -> complete email address
ip_address        -> canonical IP address
netblock          -> CIDR notation
asn               -> ASN identifier
organization       -> organization name
external_hostname -> external FQDN
```

The identity of a finding is:

```text
(type, normalized_value)
```

Normalization happens before deduplication.

### 5. Normalize Sherlock output

Sherlock results were represented as `account_match` findings using the complete profile URL.

For example:

```text
site: GitHub
url: https://www.github.com/<username>
```

becomes one finding whose type is `account_match` and whose value is the complete account URL.

### 6. Normalize theHarvester output

theHarvester hosts belonging to the target domain become `subdomain` findings, while discovered email addresses become `email` findings.

The implementation also avoids treating the bare target root as a subdomain and filters hostnames according to the target-domain relationship.

### 7. Parse Amass as a graph rather than a flat list

This was the most important normalization problem.

Amass exposed relationships involving:

- FQDNs
- IPv4/IPv6 addresses
- netblocks
- ASNs
- organizations
- external hostnames

Example relationship shape:

```text
host.example.com (FQDN) --> a_record --> 203.0.113.10 (IPAddress)
```

The parser extracts both endpoints instead of treating the whole relationship string as one opaque value.

For example, the relationship above can contribute:

```text
subdomain: host.example.com
ip_address: 203.0.113.10
```

Likewise, an ASN-to-netblock relationship can contribute both an `asn` and a `netblock` finding.

Relationship labels such as `a_record`, `contains`, `announces`, and `managed_by` are treated as context rather than as independent finding types.

### 8. Handle edge cases explicitly

Several normalization rules were added after observing real data and implementation failures.

The root target domain itself is ignored as a finding.

Reverse DNS names such as `.in-addr.arpa` and `.ip6.arpa` are not retained as standalone external hostnames.

Unknown or unsupported tool output is not silently converted into a valid finding category.

Normal completion messages from a tool are not supposed to become findings or genuine errors.

### 9. Deduplicate and correlate findings

After source-specific normalization, findings are merged using:

```text
(type, normalized_value)
```

When the same normalized finding appears in more than one tool, the source names are merged rather than creating duplicate table rows.

This turns multiple observations into one correlated finding with provenance.

### 10. Assign confidence

Confidence is based on the number of distinct source tools reporting the same finding:

```text
1 distinct source -> medium
2+ distinct sources -> high
```

Repeated observations by the same tool do not count as independent corroboration.

This makes confidence represent cross-tool corroboration rather than simply frequency of observation.

### 11. Apply heuristic priority scoring

Each finding type receives a base score, then the score is adjusted using the confidence multiplier:

```text
score = base_score × confidence_multiplier
```

Current base scores:

| Finding type | Base |
|---|---:|
| subdomain | 3.0 |
| ip_address | 3.0 |
| external_hostname | 2.5 |
| account_match | 2.0 |
| email | 2.0 |
| netblock | 1.5 |
| asn | 1.5 |
| organization | 1.0 |

Confidence multipliers:

| Confidence | Multiplier |
|---|---:|
| high | 1.5 |
| medium | 1.0 |
| low | 0.7 |

The score is intentionally a prioritization heuristic rather than a vulnerability severity rating.

### 12. Generate a unified report

The builder sorts findings by score and writes a Markdown table containing:

- score
- finding type
- normalized value
- confidence
- contributing source tools

A summary count is included so the report gives an immediate overview of the result set.

### 13. Expose the pipeline through the CLI

The final CLI supports:

```text
--username
--domain
--tools
--output
```

Individual tools can therefore be selected without changing the normalization or reporting code.

### 14. Validate with sparse and rich datasets

The pipeline was deliberately tested against datasets with very different result densities.

One sparse practice run produced six Sherlock account matches and no domain findings from the other tools.

A richer development dataset produced 50 theHarvester hosts and 631 Amass graph records.

The contrast was useful because it verified that the application could distinguish:

```text
empty result
```

from:

```text
tool execution failure
```

rather than assuming that every successful run must produce a large result set.

## Findings

### 1) Tool outputs differ significantly

The three tools expose fundamentally different data models.

Sherlock is centered on account/profile discovery, theHarvester exposes hosts/emails, and Amass produces graph-style relationships involving multiple infrastructure entity types.

**Evidence:** the unified schema ultimately required eight distinct finding categories rather than a single generic `result` field.

### 2) Amass contains substantially richer relationship data than a simple subdomain enumeration

A richer development run contained 631 Amass relationship records. The relationships covered DNS-style records, graph nodes, netblocks, ASNs, and organization associations.

The implementation therefore had to parse both sides of graph relationships.

### 3) Cross-tool overlap is useful for confidence

The aggregation model was designed so that a finding independently reported by multiple distinct tools receives higher confidence than a finding seen by only one source.

This allows the final report to surface corroborated observations without treating repeated observations from one source as independent evidence.

### 4) Silent normalization bugs can produce false reports without crashing

Two concrete implementation bugs demonstrated this:

1. A typo in the `RIROrganization` entity-type check caused organization entities to be silently discarded.
2. The target root domain was briefly classified as an `external_hostname` instead of being ignored as the target itself.

These were more dangerous than ordinary syntax/runtime failures because the program could still complete and generate output while the output was wrong.

### 5) A successful tool run can legitimately have zero findings

The sparse practice data demonstrated that an empty result is not automatically evidence of a broken pipeline.

The project therefore keeps tool-level execution status/error information separate from normalized findings.

## Impact

This project's impact is primarily operational rather than vulnerability-oriented.

Without aggregation, a recon workflow requires the operator to:

1. run several tools independently;
2. understand different output formats;
3. manually identify duplicate entities;
4. decide whether multiple observations corroborate one another;
5. prioritize the resulting information;
6. construct a final report.

The project compresses those manual correlation steps into one repeatable workflow.

For a security practitioner, the main benefit is therefore **faster and more consistent passive attack-surface triage**, not an automatic declaration that any discovered entity is vulnerable.

## Improvements

Because this is an aggregation tool rather than a vulnerability finding report, remediation applies to the project itself.

### 1. Expand regression coverage

The normalization layer should have dedicated regression tests for every supported Amass entity type.

A test asserting the correct handling of `RIROrganization` would have caught the organization-dropping typo immediately.

### 2. Improve report grouping

The current report prioritizes findings using one score-sorted table. A future version could group findings by type while still preserving score ordering within each group.

### 3. Support multiple targets

The current CLI intentionally separates one username from one domain. A future version could accept multiple usernames/domains in one invocation.

### 4. Add additional passive sources

Additional passive OSINT sources could increase coverage, provided their rate limits, API requirements, and output models are handled explicitly.

### 5. Preserve more Amass provenance

The current model keeps the normalized entity and contributing tools. A future version could also retain richer relationship context so an analyst can see why a particular IP, netblock, or external hostname was associated with a finding.

### 6. Keep public test data safe

The richer institutional dataset used during development should not be treated as public example material without explicit authorization. Public examples should prefer explicitly authorized practice data.

## Notes

### The biggest lesson: parsing is the real problem

Invoking the tools was comparatively straightforward. The harder engineering problem was deciding what each output actually meant and how to represent those meanings consistently.

The project became more reliable when the normalization layer was treated as a schema with explicit contracts rather than a collection of ad-hoc string transformations.

### Data richness is target-dependent

A target can legitimately produce almost no useful domain findings while another can produce hundreds of relationships. A robust pipeline must therefore tolerate both sparse and rich outputs.

### Correctness includes information not reported

A parser is not only responsible for finding valid entities; it is also responsible for avoiding false classifications.

Ignoring the target root, filtering reverse-DNS artifacts, and separating external hostnames from target-domain subdomains are examples of correctness rules that prevent misleading output.

### Cross-source confidence is more meaningful than repetition

Two different tools reporting the same entity provide a stronger signal than the same tool producing that entity multiple times. That principle drove the confidence model.

### Heuristic scoring must be explained honestly

The scores are useful for ordering observations, but they are not scientifically validated vulnerability ratings. The report explicitly keeps those concepts separate.

### The most valuable debugging discoveries were silent failures

The `RIROrganization` typo and root-domain classification bug demonstrated that a security-oriented pipeline can be wrong even when it exits cleanly.

That changed the way I think about testing this type of software: output validation and regression tests are just as important as catching exceptions.

## References

- Sherlock — username/account discovery tool used by the project
- theHarvester — passive host/email discovery tool used by the project
- Amass — passive network/domain intelligence tool used by the project
- Project `schema_notes.md` — internal design notes defining the unified finding model
- Project `README.md` — implementation overview, architecture, usage, and design decisions