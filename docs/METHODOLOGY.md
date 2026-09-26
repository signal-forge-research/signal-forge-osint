## Signal Forge OSINT Research Methodology

This document describes the research methodology used by Signal Forge OSINT.

Signal Forge Research is an independent, non-commercial research project focused
on lawful open-source intelligence (OSINT), public-data analysis, source
provenance, reproducibility, and transparent research reporting.

The methodology is designed around a simple principle:

**A research conclusion should remain traceable to the evidence that supports it.**

The project therefore attempts to preserve a clear distinction between:

- the original research question;
- the sources queried;
- information returned by those sources;
- normalization performed by the software;
- relationships identified between records;
- analyst observations; and
- final published conclusions.

Signal Forge OSINT is currently in the proof-of-concept and development stage.

---

## Methodology Objectives

The methodology is intended to support research that is:

- lawful;
- reproducible;
- transparent;
- source-aware;
- provenance-preserving;
- minimally invasive;
- technically auditable; and
- respectful of provider terms and data-licensing requirements.

The project is not intended to produce unexplained or "black box" intelligence.

Where practicable, another researcher reviewing a Signal Forge Research report
should be able to understand:

1. what question was investigated;
2. what information was queried;
3. which sources were used;
4. when those sources were queried;
5. what those sources returned;
6. how returned information was normalized;
7. what relationships were identified;
8. what evidence supported those relationships; and
9. which statements represent analyst interpretation.

---

## High-Level Research Process

The general Signal Forge OSINT workflow is:

    Research Question
        ↓
    Define Scope
        ↓
    Classify Research Input
        ↓
    Select Appropriate Sources
        ↓
    Collect Source Records
        ↓
    Preserve Provenance
        ↓
    Normalize Records
        ↓
    Compare and Correlate
        ↓
    Identify Conflicts and Gaps
        ↓
    Analyst Review
        ↓
    Generate Research Output
        ↓
    Preserve Citations and Audit Trail

Not every investigation will require every available source.

Sources should be selected according to the research question rather than queried
merely because they are available.

---

## 1. Research Question

Research begins with a defined question.

Examples of appropriate proof-of-concept research questions might include:

- What legal entity corresponds to a particular public company name?
- In which jurisdiction is a company registered?
- What public corporate identifier belongs to an entity?
- What publicly documented domain is associated with an organization?
- What infrastructure information is publicly associated with a domain?
- Do two public records appear to refer to the same legal entity?
- Can information from two independent public sources corroborate the same
  factual claim?

A research question should be sufficiently specific that the resulting
collection can remain proportionate to the research purpose.

---

## 2. Scope Definition

Before collecting information, the project should define the scope of the
research.

The scope may identify:

- the subject being researched;
- the factual question being investigated;
- the types of records needed;
- the relevant jurisdictions;
- the time period, if applicable;
- the permitted sources;
- known limitations; and
- the intended research output.

Scope definition helps prevent unnecessary collection.

The existence of additional available information does not by itself justify
collecting it.

---

## 3. Input Classification

Signal Forge OSINT may classify a research input before selecting sources.

Potential input types include:

- legal entity name;
- company number;
- jurisdiction code;
- SEC CIK;
- domain name;
- URL;
- IP address;
- ASN;
- certificate fingerprint;
- public filing identifier; and
- other lawful public-record identifiers.

The classification determines which source modules are appropriate.

For example:

    Input:
    Example Company LLC

    Classification:
    legal_entity_name

    Potential Sources:
    OpenCorporates
    SEC EDGAR
    appropriate official registries

Another example:

    Input:
    example.com

    Classification:
    domain

    Potential Sources:
    WhoisXML API
    DNSDumpster
    Shodan
    VirusTotal
    relevant public DNS information

This input-routing model is intended to avoid unnecessary API requests.

---

## 4. Source Selection

Sources should be selected according to their relevance to the research
question.

Potential Signal Forge OSINT sources include:

- OpenCorporates;
- SEC EDGAR;
- GreyNoise;
- WhoisXML API;
- DNSDumpster;
- Shodan;
- VirusTotal;
- Brave Search; and
- other lawful public-data sources added later.

Different sources answer different types of questions.

OpenCorporates may provide structured legal-entity information.

SEC EDGAR may provide public filing information for relevant issuers.

WhoisXML API may provide domain-related records.

DNSDumpster may provide DNS and infrastructure information.

GreyNoise may provide contextual information about observable Internet
infrastructure activity.

Shodan may provide publicly indexed Internet-service information.

VirusTotal may provide permitted domain, URL, IP, or related security context.

Brave Search may assist with discovery of publicly available web information.

The inclusion of a provider in this methodology does not mean that every source
will be queried during every investigation.

---

## 5. Source Authority

Sources differ in purpose and authority.

Signal Forge OSINT should preserve the identity of the source rather than flatten
all returned information into an undifferentiated database.

For example, an official registry record, a structured data aggregator, an
Internet search result, and an infrastructure intelligence provider may each
describe different aspects of the same subject.

The project should therefore record:

- who supplied the information;
- what type of source supplied it;
- whether the source identifies an underlying publisher;
- when the information was retrieved; and
- whether another source independently supports the same claim.

A source should not be described as authoritative beyond what the source itself
supports.

---

## 6. Collection

Collection should use documented and authorized interfaces whenever practical.

These may include:

- public APIs;
- official government interfaces;
- public websites;
- licensed research services; and
- other lawful public-data mechanisms.

Collection methods should respect:

- authentication requirements;
- API rate limits;
- provider access policies;
- applicable terms of service;
- licensing requirements; and
- technical restrictions.

Signal Forge OSINT is not intended to bypass access controls or provider
restrictions.

---

## 7. API Request Discipline

Automated collection should be conservative and predictable.

The software may implement:

- provider-specific rate limiting;
- request delays;
- retry limits;
- exponential backoff;
- response caching where permitted;
- timeout handling;
- request logging; and
- explicit handling of HTTP status codes.

A failed API request should not automatically be interpreted as "no record
exists."

The system should distinguish among conditions such as:

- successful response;
- no matching record;
- authentication failure;
- authorization failure;
- rate limitation;
- client request error;
- server error;
- network timeout; and
- provider unavailable.

---

## 8. Request Logging

Where provider terms permit it, request metadata may be recorded for audit and
troubleshooting purposes.

A request log may contain:

    Provider: OpenCorporates
    Query Type: company_name
    Query Value: Example Company LLC
    Request Time: 2026-09-25T15:42:18Z
    Response Status: 200
    Result: success

Authentication information must not be included in public logs.

Secrets that appear in URLs, headers, cookies, or query parameters must be
removed or redacted before logging.

---

## 9. Raw Source Records

Where provider terms permit retention, a copy of a raw source response may be
stored locally.

The raw record represents what the source returned at collection time.

Raw records are useful for:

- debugging;
- reproducibility;
- later normalization review;
- detecting parser errors; and
- verifying that subsequent processing did not unintentionally alter the source
  information.

Retention of a raw response does not imply permission to publish that response.

Publication remains subject to the provider's applicable terms.

---

## 10. Raw Record Integrity

Where raw responses are lawfully retained, the project may calculate a
cryptographic hash.

Example:

    Algorithm: SHA-256
    File: opencorporates-response-0001.json
    SHA-256: <hash-value>

This allows the locally retained copy to be checked for subsequent alteration.

A cryptographic hash establishes integrity of the retained copy.

It does not establish the truth or accuracy of the information contained in the
source response.

---

## 11. Normalization

Different providers represent similar information differently.

Normalization converts provider-specific information into a consistent internal
structure while attempting to preserve the original factual meaning.

Normalization may include:

- converting timestamps to ISO 8601;
- normalizing whitespace;
- separating identifiers from names;
- standardizing field labels;
- representing domains consistently;
- representing IP addresses consistently;
- preserving jurisdiction codes;
- assigning internal record identifiers; and
- separating source metadata from record content.

Example:

    Original:
    EXAMPLE COMPANY, L.L.C.

    Normalized:
    Example Company LLC

    Transformation:
    capitalization and punctuation normalization

Both the source value and normalized value may be retained when useful.

---

## 12. Non-Destructive Normalization

Normalization should not silently replace the original evidence.

Where practical, the project should preserve:

    original_value
    normalized_value
    transformation_notes

This makes it possible to review how a normalized value was produced.

Normalization should not alter substantive facts merely to make two records
appear to match.

---

## 13. Internal Record Identification

Signal Forge OSINT may assign local identifiers to collected records.

Example:

    SF-RECORD-000001

A local identifier allows later records and research observations to reference
the evidence without depending exclusively on a provider-specific format.

The local identifier does not replace the provider's original identifier.

Both may be preserved.

---

## 14. Provenance Preservation

Every significant normalized record should retain provenance where practicable.

A record may identify:

    Provider
    Provider Record ID
    Source URL
    Original Source URL
    Query Type
    Query Value
    Retrieved At
    Jurisdiction
    Licence / Terms Reference
    Local Record ID

Detailed provenance requirements are documented in:

`docs/PROVENANCE.md`

---

## 15. Correlation

Correlation involves comparing independently obtained records to determine
whether a meaningful relationship may exist.

Potential correlations include:

- legal entity ↔ company number;
- legal entity ↔ jurisdiction;
- legal entity ↔ SEC filing;
- legal entity ↔ domain;
- domain ↔ IP address;
- IP address ↔ ASN;
- domain ↔ public infrastructure;
- company record ↔ official registry record.

Correlation is an analytical operation.

It should remain distinct from the original source data.

---

## 16. Correlation Criteria

A relationship should not be created solely because two records contain
superficially similar text.

Depending on the type of research, useful matching factors may include:

- exact legal name;
- company number;
- jurisdiction;
- CIK;
- registered address;
- official website;
- domain ownership information;
- source-provided relationships;
- stable identifiers;
- independently corroborating records; and
- temporal consistency.

Different matching factors have different evidentiary value.

---

## 17. Correlation Does Not Equal Causation

Two records appearing together does not automatically establish a meaningful
relationship.

Examples include:

- two domains sharing infrastructure;
- two entities having similar names;
- multiple services using the same cloud-hosting provider;
- several domains resolving to the same shared server;
- two records containing the same common address.

Signal Forge OSINT should avoid treating technical co-location or name similarity
as proof of organizational ownership or control.

---

## 18. Evidence Relationships

Where practical, a derived relationship should identify the records supporting
it.

Example:

    Relationship:
    domain_associated_with_company

    Subject:
    example.com

    Object:
    Example Company LLC

    Supporting Records:
    SF-RECORD-000001
    SF-RECORD-000014
    SF-RECORD-000021

    Analyst Review:
    required

This creates a traceable path from a derived relationship back to its evidence.

---

## 19. Independent Corroboration

Where a material fact is important to a research conclusion, independent
corroboration should be sought when practical.

For example, a corporate identifier returned by an aggregator may be compared
with:

- an official registry;
- SEC EDGAR;
- an official organization website; or
- another appropriate independent public source.

Multiple sources repeating the same information do not necessarily constitute
independent corroboration if they all obtained the information from the same
underlying source.

---

## 20. Conflicting Information

Sources may disagree.

Signal Forge OSINT should preserve meaningful conflicts rather than silently
selecting one value.

A conflict record may identify:

    Source A:
    value

    Source B:
    different value

    Source A Retrieved:
    timestamp

    Source B Retrieved:
    timestamp

    Analyst Note:
    explanation or unresolved conflict

Potential reasons for disagreement include:

- different update schedules;
- historical records;
- stale information;
- jurisdictional differences;
- provider parsing errors;
- changes to the underlying entity; and
- differences in source definitions.

---

## 21. Missing Information

Missing information must be distinguished from negative evidence.

The project should distinguish among:

- field absent;
- explicit null value;
- zero results;
- source unavailable;
- query failed;
- authorization denied;
- rate limit reached;
- timeout;
- parsing failure; and
- information genuinely reported as nonexistent.

"No result returned" does not necessarily mean "does not exist."

---

## 22. Analyst Review

Automated correlation should not automatically become a published conclusion.

Material findings should be reviewed before publication.

Analyst review may consider:

- source reliability;
- identifier consistency;
- temporal consistency;
- alternative explanations;
- conflicting information;
- completeness;
- source independence; and
- evidentiary limitations.

The analyst should distinguish clearly between what the sources report and what
the analyst infers.

---

## 23. Confidence

Where useful, an analyst observation may include a descriptive confidence level.

Potential levels include:

- low;
- moderate; and
- high.

A confidence label should not substitute for supporting evidence.

The evidence supporting the assessment should remain visible.

Example:

    Observation:
    The domain appears associated with Example Company LLC.

    Confidence:
    Moderate

    Supporting Evidence:
    SF-RECORD-000001
    SF-RECORD-000014

    Limitation:
    No direct registry record identifying the domain was located.

Confidence criteria may become more formalized as the project matures.

---

## 24. Separating Fact From Analysis

Published reports should distinguish at least four categories:

### Source Fact

Information directly reported by a source.

### Normalized Fact

Source information reformatted without materially changing its meaning.

### Derived Relationship

A relationship created by comparing records.

### Analyst Observation

An interpretation or conclusion derived from the evidence.

This separation helps prevent analysis from being mistaken for original source
data.

---

## 25. Research Notes

Analyst notes may document reasoning that is useful for understanding a finding.

Notes should avoid altering the underlying record.

Examples include:

- reason two entities were treated as separate;
- explanation for a normalization decision;
- description of conflicting records;
- reason a potential relationship was rejected;
- limitations affecting confidence.

Research notes should remain attributable to the analyst or analysis process
rather than the original provider.

---

## 26. Data Minimization

Signal Forge Research should collect and publish only information reasonably
necessary for the research purpose.

A public record containing additional personal information does not automatically
justify reproducing that information.

Where personal information is not material to a finding, it may be:

- omitted;
- summarized;
- redacted; or
- excluded from public output.

This principle is especially important when producing public example reports.

---

## 27. Benign Proof-of-Concept Subjects

During early development, testing should favor benign examples where practical.

Examples may include:

- well-known public companies;
- synthetic organizations;
- reserved example domains;
- documentation addresses;
- government public datasets; and
- other subjects suitable for demonstrating methodology without unnecessary
  privacy impact.

The goal of the initial proof of concept is to demonstrate the research
architecture, not to investigate a private individual.

---

## 28. Reserved Technical Examples

Technical documentation should use reserved or documentation-specific values
where possible.

Examples include:

    example.com

and documentation IP ranges such as:

    192.0.2.0/24
    198.51.100.0/24
    203.0.113.0/24

These values help demonstrate technical functionality without unintentionally
targeting an unrelated system.

---

## 29. Provider Terms

Every integrated provider remains subject to its own terms.

Before adding a provider module, the project should determine, where practical:

- whether automated API access is permitted;
- authentication requirements;
- rate limits;
- storage restrictions;
- redistribution restrictions;
- attribution requirements;
- permitted research uses; and
- whether raw responses may be published.

Provider rules should be reflected in implementation decisions.

---

## 30. Data Licensing

Licensing requirements are documented separately in:

`DATA_LICENSE.md`

Combining information from multiple sources does not erase or replace the
licensing requirements associated with each source.

OpenCorporates-derived information should remain identifiable as
OpenCorporates-derived information.

Third-party proprietary information should not be represented as openly licensed
merely because it appears alongside open data.

---

## 31. Credential Security

API credentials must not appear in public source code, provenance records,
screenshots, reports, or diagnostic logs.

Secrets include:

- API keys;
- passwords;
- access tokens;
- OAuth refresh tokens;
- bearer tokens;
- session cookies;
- authentication headers;
- private cryptographic keys; and
- other authentication material.

Local credentials should be stored outside version control.

Environment variables or a local `.env` file excluded by `.gitignore` may be
used where appropriate.

---

## 32. Error Logging

Errors are part of the research audit trail.

A sanitized error record may preserve:

    Provider
    Query Type
    Query Value
    Timestamp
    HTTP Status
    Error Category
    Retry Count
    Local Request ID

Credentials must be removed from diagnostic information.

Error logging helps distinguish a failed collection attempt from a legitimate
absence of data.

---

## 33. Rate Limiting

Signal Forge OSINT should respect provider rate limits.

Provider modules may independently define:

- minimum request interval;
- maximum retry count;
- backoff behavior;
- daily or monthly request limits;
- cache duration; and
- response handling rules.

The software should not deliberately circumvent rate limits by rotating
credentials or otherwise attempting to evade provider controls.

---

## 34. Caching

Where provider terms permit it, caching may reduce unnecessary repeated
requests.

A cache record should retain information such as:

    Provider
    Query
    Retrieval Time
    Expiration or Review Time
    Source Record ID

Cached information should not be assumed to remain current indefinitely.

Time-sensitive research may require a new retrieval.

---

## 35. Reproducibility

A reproducible research report should provide enough information to understand
how the result was produced.

This may include:

- research question;
- scope;
- input;
- providers queried;
- query types;
- timestamps;
- relevant source identifiers;
- normalization rules;
- correlation criteria;
- supporting record identifiers;
- analyst observations;
- limitations; and
- citations.

Reproducibility does not require disclosure of credentials.

It also does not require redistribution of data that a provider prohibits from
being redistributed.

---

## 36. Audit Trail

The intended evidence chain is:

    Research Question
        ↓
    Query
        ↓
    Source Request
        ↓
    Source Record
        ↓
    Raw Response
        ↓
    Normalized Record
        ↓
    Correlation
        ↓
    Analyst Review
        ↓
    Published Finding

Each stage should reference the preceding stage where practical.

This helps establish how a published conclusion was produced.

---

## 37. Publication

Signal Forge Research may publish:

- project methodology;
- provenance specifications;
- source-attribution examples;
- sanitized example records;
- example queries;
- sample intelligence reports;
- permitted derived datasets;
- software source code; and
- documentation.

Public output should not contain authentication secrets.

Third-party information should be published only to the extent permitted by the
applicable provider terms.

---

## 38. Report Structure

A future Signal Forge Research report may contain sections such as:

    Research Question

    Scope

    Executive Summary

    Sources Consulted

    Findings

    Supporting Evidence

    Conflicting Information

    Analyst Observations

    Limitations

    Provenance

    Attribution

    Retrieval Timestamps

    Methodology

This format is expected to evolve during proof-of-concept development.

---

## 39. Limitations

Every research process has limitations.

Potential limitations include:

- incomplete provider coverage;
- stale records;
- rate limits;
- unavailable records;
- inconsistent identifiers;
- provider parsing errors;
- ambiguous names;
- shared Internet infrastructure;
- changes occurring after collection;
- inaccessible primary records; and
- differences between legal and operational identities.

Important limitations should be disclosed when they materially affect a finding.

---

## 40. No Automatic Truth Determination

Signal Forge OSINT is intended to assist research.

It is not intended to automatically determine that a claim is true merely
because multiple sources contain similar information.

Sources can:

- repeat one another;
- contain stale information;
- contain errors;
- derive data from the same upstream source; or
- use different definitions.

Human review remains an important part of material analytical conclusions.

---

## 41. Proof-of-Concept Validation

The initial proof of concept should test whether the system can successfully:

1. classify a research input;
2. select appropriate sources;
3. issue lawful API requests;
4. record request metadata;
5. preserve source provenance;
6. normalize returned records;
7. correlate compatible records;
8. preserve conflicting information;
9. distinguish failed requests from absent records;
10. generate source-aware output;
11. preserve licensing metadata; and
12. produce a reproducible sample report.

Successful completion of these steps will provide a foundation for later
development.

---

## 42. Development Philosophy

Signal Forge OSINT should favor modular development.

Each provider integration should ideally operate as an independent module with a
consistent interface to the larger research framework.

A conceptual provider workflow is:

    Input
        ↓
    Provider Module
        ↓
    Provider Response
        ↓
    Provider-Specific Parser
        ↓
    Normalized Record
        ↓
    Provenance Layer
        ↓
    Correlation Engine

This approach allows additional lawful data providers to be added without
requiring the entire application to be redesigned.

---

## 43. Methodology Changes

This methodology is expected to evolve.

Material changes should be documented through the repository's version history.

Future changes may address:

- additional source types;
- improved normalization schemas;
- automated report generation;
- evidence graphs;
- confidence criteria;
- provider-specific compliance rules;
- additional integrity mechanisms; and
- improved reproducibility tooling.

The Git history provides a record of changes to this methodology over time.

---

## Related Documentation

Data licensing and attribution:

`DATA_LICENSE.md`

Provenance and evidence tracking:

`docs/PROVENANCE.md`

Project overview:

`README.md`

---

## Project Status

Signal Forge OSINT is currently in early development and proof-of-concept
testing.

This methodology represents the intended research process and will be refined as
the software framework is implemented and tested.

Last reviewed: September 2026

---

## Contact

Signal Forge Research

Email: research@signalforgeresearch.com

Website: https://signalforgeresearch.com

GitHub: https://github.com/signal-forge-research
