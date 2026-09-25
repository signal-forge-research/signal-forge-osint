# Data Licensing and Attribution

This document describes how Signal Forge OSINT handles licensing, attribution,
provenance, and redistribution requirements for data obtained from different
research sources.

Signal Forge Research uses public-data sources and properly licensed APIs whose
terms may differ substantially.

The presence of information in this repository does not mean that the underlying
information is owned by Signal Forge Research or may be freely redistributed.

This document is intended to describe project policy and is not a substitute for
the authoritative licence or terms issued by each data provider.

---

## General Principle

Every data source remains subject to its own:

- licence;
- terms of service;
- API agreement;
- attribution requirements;
- access restrictions;
- rate limits; and
- redistribution restrictions.

Signal Forge Research will not assume that information is open data merely
because it can be accessed through an API, website, public record, or search
interface.

Where multiple sources are correlated, the applicable rights and restrictions
of each source remain separate.

---

## OpenCorporates Data

OpenCorporates is being considered as a structured legal-entity data source for
Signal Forge OSINT.

OpenCorporates documentation describes free API access for qualifying open-data
projects as being subject to open/share-alike attribution conditions.

OpenCorporates also describes its rights in the data as being provided under the
Open Database Licence framework.

Where OpenCorporates-derived information is published by this project, Signal
Forge Research intends to:

- identify OpenCorporates as the source;
- preserve the relevant OpenCorporates entity URL where available;
- preserve jurisdiction codes and company numbers where useful;
- preserve available source and provenance information;
- preserve retrieval timestamps;
- identify OpenCorporates-derived information separately from analyst-created
  material;
- comply with applicable attribution requirements; and
- comply with applicable share-alike requirements.

Signal Forge Research will not represent OpenCorporates-derived records as
proprietary Signal Forge Research data.

Where required by the applicable OpenCorporates terms, published
OpenCorporates-derived database content will be made available under the
Open Database License (ODbL) 1.0 or other applicable licence specified by
OpenCorporates.

The authoritative OpenCorporates terms and licence should always control over
this project summary.

OpenCorporates licensing information:

https://opencorporates.com/legal/licence

---

## OpenCorporates Attribution

Where practicable, a published OpenCorporates-derived record or research report
should contain attribution similar to:

    Data source: OpenCorporates
    Entity: Example Company LLC
    Jurisdiction: us_tx
    Company Number: 1234567
    OpenCorporates Record: https://opencorporates.com/...
    Retrieved: YYYY-MM-DDTHH:MM:SSZ

Where OpenCorporates supplies information about the underlying company registry
or original publisher, that provenance should also be preserved when useful.

---

## Source Provenance

Signal Forge Research is designed to preserve the origin of research information.

A structured record may contain fields similar to:

    {
      "provider": "OpenCorporates",
      "source_url": "https://opencorporates.com/...",
      "original_source_url": "https://...",
      "record_id": "example-id",
      "retrieved_at": "YYYY-MM-DDTHH:MM:SSZ",
      "jurisdiction": "example",
      "company_number": "example",
      "license": "Applicable provider terms"
    }

These fields are intended to make research findings traceable and independently
reviewable.

The presence of source information in a Signal Forge Research report does not
transfer ownership of the original data to Signal Forge Research.

Additional provenance practices are documented in:

`docs/PROVENANCE.md`

---

## Third-Party API Data

Signal Forge OSINT may use information obtained from services including:

- GreyNoise;
- WhoisXML API;
- DNSDumpster;
- Shodan;
- VirusTotal;
- Brave Search;
- other properly licensed research APIs.

Information obtained from these providers remains subject to each provider's
applicable terms.

Nothing in this repository automatically relicenses third-party proprietary
data.

Third-party information does not become ODbL-licensed merely because it is
displayed, analyzed, normalized, or correlated alongside OpenCorporates-derived
information.

Where a provider does not permit redistribution of raw API responses, public
Signal Forge Research outputs may instead contain permitted summaries,
observations, identifiers, citations, or links to the original source.

---

## Government and Public-Record Sources

Signal Forge OSINT may also use government and official public-record sources
such as SEC EDGAR.

Such information will be accessed and used in accordance with:

- applicable law;
- the source agency's access policies;
- automated-access requirements;
- fair-use or fair-access policies where applicable; and
- any third-party rights that may exist in material contained within the public
  record.

Public accessibility does not automatically mean that every element of a public
record is free of all copyright, privacy, contractual, or other restrictions.

---

## Data Versus Software

Data licensing and software licensing are separate.

This document primarily concerns datasets, database contents, research records,
and source-derived information.

Python source code in this repository may be licensed separately under an
appropriate software licence.

A software licence does not override the licence or terms governing data
obtained from OpenCorporates or any other provider.

Similarly, a data licence does not automatically apply to the project's Python
source code.

---

## Raw API Responses

Raw API responses may be retained locally for research, troubleshooting,
integrity checking, or reproducibility only when permitted by the applicable
provider terms.

Raw responses should not automatically be published.

Before a raw response is included in a public repository or research output,
the applicable provider's redistribution terms should be reviewed.

Sensitive authentication information must be removed.

---

## Credentials and Secrets

The following must never be published in this repository:

- API keys;
- passwords;
- bearer tokens;
- OAuth access tokens;
- OAuth refresh tokens;
- session cookies;
- private keys;
- authentication headers; or
- configuration files containing secrets.

Credentials should be stored locally using mechanisms such as environment
variables or local `.env` files excluded from version control.

---

## Derived and Correlated Information

Signal Forge OSINT may combine information from multiple sources to produce
normalized records, correlations, or analyst observations.

The project should distinguish between:

1. facts returned directly by a source;
2. normalized representations of those facts;
3. relationships inferred from multiple sources; and
4. analyst interpretations or conclusions.

Combining multiple sources does not erase the licensing or attribution
requirements attached to each source.

Where practicable, derived relationships should retain references to the source
records supporting them.

---

## Published Research Reports

A Signal Forge Research report may contain information from several providers.

Where practicable, material factual claims should retain:

- provider name;
- source URL;
- record identifier;
- retrieval timestamp;
- relevant entity identifier;
- attribution statement; and
- applicable licensing information.

Reports should distinguish source facts from analysis.

A report should not imply that Signal Forge Research independently verified a
fact merely because a third-party provider returned it.

---

## Redistribution

Signal Forge Research will not knowingly redistribute third-party data in a
manner prohibited by the relevant provider.

Where redistribution rights are uncertain, the project should prefer publishing:

- citations;
- source links;
- provider names;
- limited permitted excerpts;
- normalized identifiers;
- research methodology; or
- independently derived observations

rather than reproducing an entire third-party dataset.

---

## Data Minimization

Public research outputs should include only information reasonably necessary to
support the research purpose.

Sensitive personal information that is unrelated to the research question
should not be unnecessarily reproduced.

Where appropriate, personal information may be omitted, summarized, or redacted
while preserving enough provenance to support the underlying research finding.

---

## No Transfer of Third-Party Rights

Signal Forge Research can grant rights only to material for which it has the
legal authority to do so.

Nothing in this repository should be interpreted as granting additional rights
to information owned, licensed, or controlled by another organization.

Users who independently access a referenced third-party source remain
responsible for complying with that provider's terms.

---

## Licence Metadata

Where practical, normalized research records may contain a field identifying
the applicable source terms.

Example:

    {
      "provider": "Example Provider",
      "source_url": "https://example.com/record",
      "retrieved_at": "YYYY-MM-DDTHH:MM:SSZ",
      "license": "Applicable provider terms",
      "redistribution": "Check provider terms before publication"
    }

This metadata is informational.

The actual provider agreement or licence remains authoritative.

---

## Changes to Provider Terms

API terms and licences may change.

Signal Forge Research should periodically review provider terms and update this
document when material changes affect:

- access;
- storage;
- attribution;
- redistribution;
- publication; or
- permitted research use.

Historical research records may retain information identifying which terms were
understood to apply when the record was collected.

---

## Proof-of-Concept Publication

During the initial proof-of-concept phase, Signal Forge Research intends to
publish primarily:

- methodology;
- provenance documentation;
- sanitized example records;
- sample intelligence reports;
- permitted source references;
- attribution examples; and
- software code where appropriate.

The proof of concept does not require publication of complete raw third-party API
responses.

---

## OpenCorporates Public-Benefit Project

If Signal Forge Research receives OpenCorporates public-benefit API access, the
project intends to honor the associated open-data and attribution obligations.

The public GitHub repository is intended to provide a publication location for
permitted OpenCorporates-derived proof-of-concept outputs, methodology,
attribution, and supporting documentation.

Where applicable, OpenCorporates-derived database content published as part of
the project will follow the required share-alike conditions.

---

## Project Status

Signal Forge OSINT is currently in early development and proof-of-concept
testing.

This document may be revised as:

- additional providers are integrated;
- provider terms are reviewed;
- the software architecture matures; or
- publication requirements become more specific.

Last reviewed: September 2026

---

## Contact

Signal Forge Research

Email: research@signalforgeresearch.com

GitHub: https://github.com/signal-forge-research
