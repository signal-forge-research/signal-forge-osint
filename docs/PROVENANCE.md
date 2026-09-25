# Provenance and Evidence Tracking

This document defines how Signal Forge OSINT records where information came from,
when it was obtained, how it was transformed, and how it was used in research
outputs.

The purpose of provenance tracking is to make findings traceable, reproducible,
auditable, and clearly distinguishable from analyst interpretation.

Signal Forge Research is designed so that significant factual findings should
retain enough source information for another researcher to determine where the
information originated.

---

## Core Principle

Every research result should preserve, where practicable:

- the provider or source name;
- the source URL or API endpoint family;
- the original entity or record identifier;
- the query or lookup value used;
- the retrieval date and time;
- the applicable licence or provider terms;
- the raw or normalized value returned;
- any transformation applied to the value;
- relationships to supporting records; and
- any later analyst interpretation.

Source data and analyst conclusions should remain distinguishable.

---

## Provenance Layers

Signal Forge OSINT may represent information in four primary layers.

### 1. Raw Source Data

Raw source data is information returned directly by an API, public record, or
other lawful research source.

Examples include:

- an OpenCorporates company record;
- a GreyNoise IP classification;
- a WhoisXML domain-registration record;
- a DNSDumpster DNS result;
- a Shodan host result;
- a VirusTotal record; or
- an SEC EDGAR filing record.

Where provider terms permit retention, raw responses may be stored locally for
reproducibility, troubleshooting, and integrity verification.

Raw responses should not automatically be published.

---

### 2. Normalized Data

Normalized data is source information converted into a consistent internal
format.

Examples include:

- converting timestamps to ISO 8601;
- separating a company name from its company number;
- representing IP addresses consistently;
- standardizing provider names;
- converting provider-specific field names into a common schema; and
- separating source metadata from factual record content.

Normalization should preserve the factual meaning of the original source.

---

### 3. Correlated or Derived Data

Correlated data is produced when information from two or more records is linked.

Examples include:

- associating a company with a domain using separately sourced evidence;
- associating a domain with an IP address;
- matching a legal entity across corporate and public filing records;
- connecting an IP address to an ASN;
- identifying multiple records that appear to refer to the same organization.

Derived relationships should identify the source records that support them.

A correlation should not automatically be treated as a verified fact merely
because two values appear similar.

---

### 4. Analyst Observation

An analyst observation is an interpretation, assessment, or conclusion based on
source or correlated data.

Analyst observations should be clearly distinguishable from source facts.

Where appropriate, an observation should identify:

- the evidence supporting it;
- the reasoning or matching criteria;
- the level of confidence;
- important limitations; and
- plausible alternative explanations.

---

## Recommended Record Structure

A normalized research record may contain fields similar to:

    {
      "record_type": "legal_entity",
      "value": "Example Company LLC",
      "source": {
        "provider": "OpenCorporates",
        "source_url": "https://opencorporates.com/...",
        "original_source_url": "https://...",
        "record_id": "example-id",
        "retrieved_at": "2026-09-25T15:00:00Z",
        "license": "Applicable provider terms"
      },
      "query": {
        "type": "company_name",
        "value": "Example Company LLC"
      },
      "normalization": {
        "applied": true,
        "notes": "Company name normalized for whitespace only"
      },
      "relationships": [],
      "analyst_notes": [],
      "confidence": null
    }

The exact schema may evolve as the software develops.

---

## Time and Date Handling

Research timestamps should use ISO 8601 format whenever practical.

Preferred format:

    YYYY-MM-DDTHH:MM:SSZ

Example:

    2026-09-25T15:42:18Z

UTC is preferred for stored research timestamps because it avoids ambiguity
between time zones.

Where a source supplies its own timestamp, both the source timestamp and the
local retrieval timestamp may be retained.

---

## Stable Identifiers

Where available, research records should preserve stable identifiers such as:

- OpenCorporates company URLs;
- jurisdiction codes;
- company numbers;
- SEC CIK numbers;
- filing accession numbers;
- domain names;
- IP addresses;
- ASN numbers;
- official registry URLs;
- certificate fingerprints;
- provider-specific record identifiers; and
- document identifiers.

Stable identifiers improve reproducibility and reduce ambiguity.

---

## OpenCorporates Provenance

Where OpenCorporates information is used, Signal Forge Research intends to
preserve, where available:

- OpenCorporates company URL;
- legal entity name;
- jurisdiction code;
- company number;
- original registry or publisher source;
- retrieval timestamp;
- relevant provenance metadata; and
- applicable attribution and licensing information.

OpenCorporates-derived information should remain identifiable as
OpenCorporates-derived information in published outputs.

---

## Third-Party API Provenance

For third-party APIs, provenance records should retain enough information to
identify the provider and lookup performed without exposing credentials.

Example:

    {
      "provider": "GreyNoise",
      "query_type": "ip",
      "query_value": "203.0.113.10",
      "retrieved_at": "2026-09-25T15:42:18Z",
      "endpoint_family": "community",
      "license": "Applicable GreyNoise API terms"
    }

API keys, bearer tokens, passwords, private keys, session cookies, and other
secrets must not appear in public provenance records.

---

## Request Logging

Where permitted by provider terms, the application may log metadata about API
requests.

Recommended request-log fields include:

- provider;
- endpoint family;
- request timestamp;
- response timestamp;
- HTTP status code;
- query type;
- query value;
- request success or failure;
- rate-limit information;
- error category; and
- local research-record identifier.

Sensitive authentication information must be excluded.

If a URL contains an API key or other secret query parameter, that value must be
removed or redacted before the URL is logged.

---

## Raw Response Integrity

Where provider terms permit local retention of raw responses, Signal Forge OSINT
may calculate a cryptographic hash of the retained response.

Example:

    SHA-256: <hash-value>

A cryptographic hash can help demonstrate that a retained response has not been
changed after collection.

A hash verifies the integrity of the stored copy. It does not independently prove
that the source itself was accurate.

---

## Source Reliability and Confidence

The existence of a source record and the correctness of an analytical conclusion
are different questions.

For example:

- "Provider X returned value Y" can be documented as a source fact.
- "Value Y identifies the same real-world entity as value Z" may require an
  analytical confidence assessment.

Confidence should be based on documented evidence rather than intuition alone.

A future implementation may use descriptive confidence levels such as:

- low;
- moderate; and
- high.

Any confidence system should document the criteria used.

---

## Conflicting Sources

Sources may disagree.

Signal Forge OSINT should not silently choose one value and discard the others.

Where material conflicts occur, the project should preserve:

- each conflicting value;
- the source associated with each value;
- retrieval timestamps;
- source-record dates where available;
- relevant identifiers; and
- an analyst note describing the disagreement.

A newer source should not automatically be assumed to be more accurate than an
older source.

---

## Missing Data

Missing or unavailable information should not be transformed into a factual
claim.

The project should distinguish between:

- a field not returned by a provider;
- a field explicitly returned as null;
- a lookup that failed;
- a provider rate-limit response;
- a record that did not exist;
- a request that timed out; and
- a source that could not be reached.

These conditions have different meanings and should be recorded separately.

---

## Report Citations

Published research reports should, where practicable, allow material factual
claims to be traced back to their sources.

An attribution record may contain:

    Source: OpenCorporates
    Entity: Example Company LLC
    Jurisdiction: us_tx
    Company Number: 1234567
    Record: https://opencorporates.com/...
    Retrieved: 2026-09-25T15:42:18Z

Other providers should receive attribution according to their applicable terms
and the nature of the source.

---

## Reproducibility

A published proof of concept should provide enough information for another
researcher to understand:

1. what was queried;
2. which source was queried;
3. when the query occurred;
4. what information was returned;
5. what normalization or transformation occurred;
6. what correlations were made;
7. what evidence supported those correlations; and
8. which statements were analyst interpretations.

Reproducibility does not require publishing API credentials or redistributing
data that a provider prohibits from redistribution.

---

## Evidence Referencing

Where practical, derived records should retain references to the source records
that support them.

An eventual correlation record might contain information similar to:

    {
      "relationship": "domain_associated_with_company",
      "subject": "example.com",
      "object": "Example Company LLC",
      "supporting_records": [
        "record-0001",
        "record-0007"
      ],
      "confidence": "moderate"
    }

This creates an evidence path between the conclusion and the underlying records.

---

## Privacy and Data Minimization

Provenance tracking should collect only information reasonably necessary for the
research purpose.

The project should avoid unnecessarily reproducing sensitive personal
information in public outputs.

Where source material contains personal information that is not needed to
support the research finding, the information may be omitted, summarized, or
redacted from published reports where appropriate.

---

## Credential Safety

The following must never be committed to the public repository:

- API keys;
- passwords;
- access tokens;
- OAuth refresh tokens;
- session cookies;
- private cryptographic keys;
- authentication headers; or
- configuration files containing secrets.

Local secrets should be stored outside version control, for example in
environment variables or a local `.env` file excluded by `.gitignore`.

---

## Error Provenance

Errors should also be traceable.

Where useful, the system may preserve:

- provider name;
- query value;
- request timestamp;
- HTTP status;
- exception type;
- rate-limit condition;
- retry count; and
- sanitized diagnostic message.

Authentication secrets should never appear in error logs.

This makes it possible to distinguish "no result exists" from "the research
request failed."

---

## Transformation History

Where practical, significant transformations may retain a brief history.

Example:

    Source value:
    "EXAMPLE COMPANY, L.L.C."

    Normalized value:
    "Example Company LLC"

    Transformation:
    punctuation and capitalization normalization

Transformations should not silently alter substantive factual meaning.

---

## Audit Trail

The long-term goal is for each significant report finding to have an auditable
path similar to:

    Source Record
        ↓
    Raw Response
        ↓
    Normalized Record
        ↓
    Correlation
        ↓
    Analyst Observation
        ↓
    Published Report

Each stage should preserve references to the stage before it where practical.

This allows a reviewer to distinguish original evidence from later processing
and interpretation.

---

## Publication

Public proof-of-concept materials may contain:

- sanitized example records;
- provenance metadata;
- attribution examples;
- methodology documentation;
- correlation examples;
- sample reports; and
- permitted source references.

Publication does not require disclosure of credentials or unrestricted
redistribution of third-party API data.

---

## Relationship to DATA_LICENSE.md

This document describes evidence provenance and traceability.

Data licensing and redistribution policy are documented separately in:

`DATA_LICENSE.md`

The provenance record may reference a provider's licence or terms, but the
provider's authoritative agreement remains controlling.

---

## Project Status

Signal Forge OSINT is currently in early development and proof-of-concept
testing.

This provenance model is a working specification and may evolve as:

- additional data providers are integrated;
- the normalized schema develops;
- report formats mature; and
- research methodology becomes more formalized.

Material changes to provenance practices should be documented in this
repository.

Last reviewed: September 2026

---

## Contact

Signal Forge Research

Email: research@signalforgeresearch.com

GitHub: https://github.com/signal-forge-research
