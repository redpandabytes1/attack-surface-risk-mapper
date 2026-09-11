# Design Notes

This document consolidates the notes, questions, design decisions, observations, and important implementation findings for the Attack-Surface Risk-Mapper project.

The schema decisions below were derived from the actual runner output files:
- `combined_raw.json`
- `combined_raw2.json`

The purpose of this document is to provide the design contract that the normalization and deduplication layer in `builder.py` will implement in the next milestone.

# Source Data Reviewed

## `combined_raw.json`

Domain target:

```text
zonetransfer.me
```

Sherlock username target:

```text
redpandabytes1
```

The dataset contains:

- 6 Sherlock account matches
- 0 theHarvester hosts
- 0 theHarvester emails
- 0 Amass findings
- an Amass timeout recorded by the current runner

The Sherlock section contains six discovered account/profile URLs, including GitHub and several other platforms.

The theHarvester section is empty for this run.

The Amass section contains no findings because the current runner timed out.

### Important observation

This dataset is useful as a **failure/empty-result test case**. It demonstrates that a tool can execute but return no findings, and that a tool timeout should be represented separately from successful findings.

The normalization layer must not treat an empty result or a timeout as an actual finding.

## `combined_raw2.json`

Domain target:

```text
iitxxp.ac.in
```

Sherlock username target:

```text
redpandabytes1
```

The dataset contains:

- 6 Sherlock account matches
- 50 theHarvester hosts
- 0 theHarvester emails
- 631 Amass graph records

The Amass output is substantially richer than a simple list of subdomains. It contains relationships involving:

- FQDNs/hostnames
- IPv4 addresses
- IPv6 addresses
- netblocks
- ASNs
- organizations
- external hostnames

The 631 Amass records include relationship types such as:

- `a_record`
- `aaaa_record`
- `cname_record`
- `mx_record`
- `ns_record`
- `ptr_record`
- `node`
- `contains`
- `announces`
- `managed_by`

A useful breakdown of the observed Amass record types is:

| Relationship type | Observed records |
|---|---:|
| `a_record` | 200 |
| `contains` | 159 |
| `node` | 116 |
| `mx_record` | 41 |
| `announces` | 32 |
| `cname_record` | 29 |
| `aaaa_record` | 21 |
| `managed_by` | 12 |
| `ns_record` | 11 |
| `ptr_record` | 10 |
| **Total** | **631** |

### Important observation

The current Amass runner calls this collection `subdomains`, but it is actually a set of **graph relationship strings**. Therefore:

> The normalization layer must not simply convert every item in
> `raw["subdomains"]` into `{"type": "subdomain", ...}`.

Doing so would incorrectly classify IP addresses, netblocks, ASNs, organizations, and external hostnames as subdomains and would lose useful semantic information.

# Distinct categories of findings that appear

## Sherlock

Sherlock returns records containing:

```text
site
url
```

Each record represents a discovered account/profile associated with the tested username.

### Normalized category

```text
account_match
```

Example:

```text
site: GitHub
url: https://www.github.com/redpandabytes1
```

This should become one `account_match` finding, not separate findings for the site and URL.

## theHarvester

The current runner exposes:

```text
hosts
emails
```

The supplied data contains hostnames but no emails.

### Normalized categories

```text
subdomain
email
```

A target-domain hostname is normalized as:

```text
subdomain
```

An email address, if discovered, is normalized as:

```text
email
```

The `email` category remains part of the schema even though these specific runs produced zero email findings. It is part of the defined theHarvester output model and is required for the runner to support future results.

## Amass

The actual Amass data requires multiple normalized categories.
### `subdomain`

A discovered FQDN belonging to the target domain.

Example:

```text
host.example.com
```

### `ip_address`

An IPv4 or IPv6 address associated with discovered infrastructure.

```text
203.110.x.x
2a00:1450:....
```

### `netblock`

A CIDR network associated with discovered infrastructure.

```text
203.110.240.0/21
```

### `asn`

An Autonomous System Number associated with a network.

```text
55847
```

### `organization`

An organization associated with an ASN or network.

Example conceptually:

```text
NKN-EXXX-NW NXN EXXX Network
```

### `external_hostname`

A hostname discovered through a relationship that does not belong to the target domain.

Examples of this class include cloud/load-balancer/CDN/service hostnames.

# Final Normalized Finding Categories

The final schema supports these eight categories:

1. `account_match`
2. `subdomain`
3. `email`
4. `ip_address`
5. `netblock`
6. `asn`
7. `organization`
8. `external_hostname`

These categories describe **entities** rather than raw Amass relationship edges.

# Normalized `value`s 

The `value` field stores the canonical representation of the entity.

| Finding type | Normalized `value` |
|---|---|
| `account_match` | Complete account/profile URL |
| `subdomain` | Bare target-domain FQDN |
| `email` | Complete email address |
| `ip_address` | Canonical IPv4/IPv6 address |
| `netblock` | CIDR notation |
| `asn` | ASN identifier |
| `organization` | Organization name |
| `external_hostname` | Bare external FQDN |

## `account_match`

Keep the complete account URL

```text
https://www.github.com/redpandabytes1
```

not reduce this to only:

```text
github.com
```

that would remove the account identity and URL path.

# `subdomain`

Store only the hostname.

an Amass relationship such as:

```text
target.example --> node --> api.target.example
```

should produce:

```python
{
    "type": "subdomain",
    "value": "api.target.example"
}
```

The relationship text itself is context, not the normalized value.

## `ip_address`

Store only the IP address.

```text
host.example --> a_record --> 203.0.113.10
```

becomes:

```python
{
    "type": "ip_address",
    "value": "203.0.113.10"
}
```

## `netblock`

Store only the CIDR block:

```text
203.0.113.0/24
```

not the entire Amass relationship.

## `asn`

Store the ASN identifier:

```text
55847
```

The organization associated with the ASN belongs in a separate `organization` finding.

## `organization`

Store the organization name associated with the infrastructure.

## external_hostname`

Storing the external hostname itself.

```text
admin-alb.example.amazonaws.com
```

The hostname remains useful because it may identify a cloud service, load balancer, CDN, external dependency, or other infrastructure boundary.

# What makes two entries the same finding?

Two findings are considered identical when their normalized:

```text
(type, value)
```

pairs are identical.

So,

```text
("subdomain", "api.example.com")
```

from theHarvester and:

```text
("subdomain", "api.example.com")
```

from Amass represent the same finding.

They should become one normalized finding with both tools recorded in `sources`.

# Normalization Rules

Normalization must occur before deduplication.

## Trim surrounding whitespace

```text
" api.example.com "
```

becomes:

```text
"api.example.com"
```

## Lowercase hostnames

DNS hostnames are normalized consistently to lowercase.

```text
API.EXAMPLE.COM
```

becomes:

```text
api.example.com
```

## Remove a trailing DNS dot

These are normalized to the same value:

```text
api.example.com
api.example.com.
```

The canonical form does not contain the final DNS dot.

## Normalize email case

For this project, email values are stored in lowercase.

## Preserve Sherlock account URLs

Sherlock's complete account URL is retained because the URL path identifies the discovered account.

Only insignificant formatting differences should be normalized where safe.

# Amass Relationship Handling

Amass produces graph-style records such as:

```text
a_record
aaaa_record
cname_record
mx_record
ns_record
ptr_record
node
contains
announces
managed_by
```

These are **relationships between entities**, not necessarily independent findings.

The normalization layer should extract useful entities from those relationships.

```text
host.example --> a_record --> 203.0.113.10
```

produces:

```text
type: ip_address
value: 203.0.113.10
```

and:

```text
host.example --> cname_record --> external.service.example
```

may produce an `external_hostname` finding when the destination is outside the target domain.

Similarly:

```text
ASN --> managed_by --> Organization
```

produces:

```text
type: asn
value: <ASN>
```

and:

```text
type: organization
value: <Organization>
```

The relationship itself can remain available as metadata later if the report needs provenance or graph context.

# What is NOT a separate finding?

The following relationship labels should not automatically become finding types:

```text
a_record
aaaa_record
cname_record
mx_record
ns_record
ptr_record
node
contains
announces
managed_by
```

```text
host.example --> a_record --> 203.0.113.10
```

does not become:

```text
type: a_record
```

Instead, the entity discovered is:

```text
type: ip_address
value: 203.0.113.10
```

This keeps the final report focused on attack-surface entities rather than turning it into a raw list of graph edges.

# Same Entity vs Same Finding

The merge key is intentionally:

```python
(type, normalized_value)
```

This means the same string can still be two different findings when its semantic type differs.

```text
("subdomain", "api.example.com")
```

and:

```text
("external_hostname", "api.example.com")
```

would remain distinct if they represent different semantic roles in the normalization process.

The type is therefore part of the identity.

# Duplicate Observations From One Tool

Repeated observations by one tool do not count as independent corroboration.

if Amass reaches the same IP through several graph relationships:

```text
host1 --> a_record --> 203.0.113.10
host2 --> a_record --> 203.0.113.10
```

the normalized representation is still one finding:

```python
{
    "type": "ip_address",
    "value": "203.0.113.10",
    "sources": ["amass"]
}
```

The source list represents **distinct tools**, not the number of times one tool emitted the entity.

This is particularly important for Amass because its graph-style output naturally repeats entities across different relationships.

# Merge-Key Rule

The canonical merge key is:

```python
(type, normalized_value)
```

Normalization occurs before comparing keys.

Conceptually:

```text
Raw findings
    ↓
Normalize type/value
    ↓
Construct (type, value)
    ↓
Use key for deduplication
    ↓
Merge source names
```

# What determines confidence?

Confidence is based on corroboration by **distinct tools**.
## Single-source finding

```text
1 distinct tool → medium confidence
```
## Multi-source finding

```text
2 or more distinct tools → high confidence
```

Repeated observations from one tool do not increase confidence.

# Confidence Rationale

The aggregator's value is not merely concatenating output from multiple programs. It also allows the same normalized entity to be corroborated across independent tools.

A finding observed by multiple tools is less likely to be only a source-specific false positive or source-specific artifact.

A single-source finding is still useful and should not be discarded, but it should receive lower confidence under the initial scoring model.

The rule is intentionally simple so that it is:
- easy to explain;
- easy to test;
- easy to reproduce;
- directly connected to the aggregator's purpose.

# Final Proposed Finding Schema

Every normalized finding uses this base structure:

```python
{
    "type": "...",
    "value": "...",
    "sources": [...],
    "confidence": "..."
}
```

## Sherlock example

```python
{
    "type": "account_match",
    "value": "https://www.github.com/redpandabytes1",
    "sources": ["sherlock"],
    "confidence": "medium"
}
```

## Single-source subdomain example

```python
{
    "type": "subdomain",
    "value": "api.example.com",
    "sources": ["amass"],
    "confidence": "medium"
}
```

## Corroborated subdomain example

```python
{
    "type": "subdomain",
    "value": "api.example.com",
    "sources": ["theharvester", "amass"],
    "confidence": "high"
}
```

## IP address example

```python
{
    "type": "ip_address",
    "value": "203.0.113.10",
    "sources": ["amass"],
    "confidence": "medium"
}
```

## Netblock example

```python
{
    "type": "netblock",
    "value": "203.0.113.0/24",
    "sources": ["amass"],
    "confidence": "medium"
}
```

## ASN example

```python
{
    "type": "asn",
    "value": "55847",
    "sources": ["amass"],
    "confidence": "medium"
}
```

## Organization example

```python
{
    "type": "organization",
    "value": "Example Organization",
    "sources": ["amass"],
    "confidence": "medium"
}
```

## External hostname example

```python
{
    "type": "external_hostname",
    "value": "service.example.net",
    "sources": ["amass"],
    "confidence": "medium"
}
```

# Important Findings From the Actual Data

## Sherlock produces a different kind of result

Sherlock is username-oriented and produces account/profile URLs, so it should not be forced into the same representation as DNS/infrastructure findings.

This is why `account_match` is a distinct category.

## theHarvester and Amass overlap meaningfully

The real `combined_raw2.json` data contains theHarvester hosts that also occur as FQDNs in Amass's graph data.

This demonstrates the exact use case for cross-tool normalization:

```text
theHarvester
      ↓
hostname
      ↓
normalize
      ↓
subdomain
      ↓
            same (type, value)
      ↑
normalize
      ↑
Amass
```

The final finding can therefore carry multiple source names and become a corroborated finding.

## Amass - not a simple subdomain list

This is the most important schema discovery.

The Amass output contains entities and relationships involving:

```text
FQDN
IPv4
IPv6
Netblock
ASN
Organization
External hostname
```

a generic:

```python
{
    "type": "subdomain",
    "value": raw_string
}
```

implementation would be incorrect.

The normalization layer must parse the Amass graph relationship string.

## Empty results and tool failures are different

`combined_raw.json` demonstrates that a tool can produce:

```text
hosts: []
emails: []
```

without necessarily indicating that the whole pipeline failed.

It also demonstrates a timeout:

```text
Amass timed out after 400 seconds.
```

These are execution/status conditions, not findings.

They should therefore remain in tool-level `errors`/status information and should not become normalized findings.

## Normal completion must not be treated as an error

The second dataset currently contains:

```text
"The enumeration has finished"
```

inside the Amass `errors` array.

This is a runner-level bug/incorrect interpretation.

Normal successful completion should not be reported as an error.

The runner should distinguish:

```text
successful completion
```

from:

```text
actual failure
```

before the final report is generated.

# Scope of the Schema

The schema is intended to normalize passive OSINT/attack-surface findings from the three selected tools.

It is not intended to claim that:

- every discovered entity is vulnerable;
- every discovered hostname is live;
- every external hostname is controlled by the target;
- every association returned by an OSINT source is authoritative.

The schema represents **observed OSINT findings**, not confirmed vulnerabilities.

That distinction should remain explicit in the final report.

# Privacy and Publishing Note

`combined_raw2.json` was generated with `iitxxp.ac.in` as the domain target and contains numerous real infrastructure records.

It should therefore be treated as development/test data.

# Final Design Decision Summary

The unified schema represents entities rather than raw tool output.

Sherlock account matches are represented as `account_match` findings. TheHarvester hosts that belong to the target domain are represented as `subdomain` findings, while emails are represented separately.

Amass receives special treatment because its output is graph-oriented. FQDNs, IP addresses, netblocks, ASNs, organizations, and external hostnames are represented as separate entity categories, while relationship labels are treated as contextual information instead of independent findings.

Finding identity is based on:

```python
(type, normalized_value)
```

and normalization occurs before deduplication.

A finding reported by one distinct tool receives `medium` confidence, while a finding independently reported by two or more distinct tools receives `high` confidence.

Repeated records from the same tool do not count as independent corroboration.