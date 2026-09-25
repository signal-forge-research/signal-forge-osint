# Signal Forge OSINT

Signal Forge OSINT is an independent, non-commercial research project focused on open-source intelligence (OSINT), public-data research, source provenance, and reproducible intelligence reporting.

The project is currently in the proof-of-concept and development stage.

## Purpose

The goal of this project is to develop a Python-based research framework capable of querying lawful public-data and OSINT sources, normalizing returned information, preserving source provenance, correlating related records, and producing transparent research reports.

Rather than presenting information as an unexplained result, the project is being designed so that significant findings can retain information about:

- the source provider;
- the original source URL, where available;
- the retrieval date and time;
- relevant identifiers;
- licensing or usage restrictions;
- attribution requirements;
- transformations applied to source data; and
- relationships to information obtained from other sources.

This allows findings to be independently reviewed and helps distinguish source data from analysis, correlation, and inference.

## Research Goals

Signal Forge Research intends to explore methods for:

1. Legal-entity identification and verification
2. Corporate-record research
3. Domain and DNS research
4. Internet-infrastructure research
5. Public-source correlation
6. Provenance-aware intelligence reporting
7. Reproducible OSINT methodology
8. Transparent attribution of research sources
9. Structured comparison of information from multiple independent sources

A specific investigative subject has not yet been selected.

Initial work will focus on benign proof-of-concept examples demonstrating the research framework, data provenance, attribution, normalization, correlation, and reporting methodology.

## Research Model

The intended research workflow is:

    Research Query
        ↓
    Source Selection
        ↓
    API / Public-Data Collection
        ↓
    Raw Source Records
        ↓
    Normalization
        ↓
    Provenance Preservation
        ↓
    Cross-Source Correlation
        ↓
    Analyst Review
        ↓
    Research Report

The project is designed to preserve a distinction between:

- facts returned directly by a source;
- normalized or transformed data;
- relationships inferred from multiple sources; and
- analyst observations or conclusions.

## Data Sources

Potential and planned integrations include public or properly licensed sources such as:

- OpenCorporates
- SEC EDGAR
- GreyNoise
- WhoisXML API
- DNSDumpster
- Shodan
- VirusTotal
- Brave Search
- other lawful public-data sources

Each source remains subject to its own terms of service, licensing conditions, rate limits, attribution requirements, and redistribution restrictions.

The inclusion of a source in this project does not imply that its underlying data may be freely redistributed.

## OpenCorporates

OpenCorporates is being considered as the project's structured legal-entity data source.

If public-benefit API access is approved, OpenCorporates-derived information published by this project will retain appropriate attribution and provenance, including OpenCorporates URLs and source information where available.

Relevant information may include:

- legal entity name;
- jurisdiction;
- company number;
- incorporation information;
- registered addresses;
- company status;
- officers or related records where available;
- original registry information; and
- OpenCorporates provenance information.

Any published database or dataset incorporating OpenCorporates-derived data will be handled in accordance with the applicable OpenCorporates open-data, attribution, and share-alike requirements.

The project is intended to demonstrate transparent and reproducible use of legal-entity data rather than create a proprietary copy of the OpenCorporates database.

## Source Provenance

Source provenance is a core design requirement of Signal Forge OSINT.

Where practicable, research records will preserve information such as:

- provider name;
- source URL;
- original source or registry URL;
- provider record identifier;
- query value;
- retrieval timestamp;
- relevant entity identifiers;
- applicable licensing information; and
- notes describing any normalization or transformation.

Detailed provenance methodology is documented in:

`docs/PROVENANCE.md`

## Data Licensing

Different research sources may have different licensing and redistribution requirements.

Signal Forge Research will not assume that information is freely redistributable simply because it is accessible through an API or public website.

OpenCorporates-derived data, government-source information, and data from commercial or freemium intelligence providers will remain subject to their respective applicable terms.

Additional information is documented in:

`DATA_LICENSE.md`

## Publication and Reproducibility

This public repository is intended to serve as the primary publication location for Signal Forge Research proof-of-concept work.

Planned public materials include:

- research methodology;
- source and provenance documentation;
- example queries;
- sanitized sample outputs;
- sample intelligence reports;
- data-attribution documentation;
- data-licensing documentation; and
- Python source code where appropriate.

Published examples will avoid exposing API credentials, authentication tokens, private keys, session information, or other secrets.

The goal is to make published research sufficiently documented that another researcher can understand:

1. what was queried;
2. which source was used;
3. when the information was retrieved;
4. what information was returned;
5. how the information was normalized;
6. what correlations were made; and
7. which statements represent analysis rather than source facts.

## Repository Structure

    signal-forge-osint/
    ├── README.md
    ├── DATA_LICENSE.md
    ├── docs/
    │   ├── README.md
    │   ├── PROVENANCE.md
    │   └── METHODOLOGY.md
    ├── examples/
    ├── sample_reports/
    └── src/

Additional directories and documentation may be added as the project develops.

## Credential Security

API credentials must never be committed to this public repository.

This includes:

- API keys;
- passwords;
- access tokens;
- OAuth refresh tokens;
- session cookies;
- private cryptographic keys; and
- configuration files containing secrets.

Credentials used during development should instead be stored locally using mechanisms such as environment variables or a `.env` file excluded from version control.

The repository's Python `.gitignore` is intended to exclude `.env` files from commits.

## Research Ethics

Signal Forge Research is intended for:

- lawful research;
- education;
- public-data analysis;
- open-source intelligence research; and
- authorized security research.

The project is not intended to facilitate:

- unauthorized access to computer systems;
- circumvention of access controls;
- credential theft;
- harassment;
- unlawful surveillance; or
- unlawful collection or distribution of private information.

Public availability of information does not by itself remove all legal, ethical, contractual, or privacy considerations surrounding its use.

## Data Minimization

Published research should include only information reasonably necessary to support the research purpose.

Sensitive personal information that is unrelated to the research question should not be unnecessarily reproduced in public reports.

Where appropriate, information may be summarized, omitted, or redacted while still preserving sufficient provenance to support the underlying finding.

## Conflicting Information

Different sources may return different information.

Signal Forge OSINT is intended to preserve meaningful disagreements between sources rather than silently selecting one value and discarding the others.

Where appropriate, reports may identify:

- each conflicting value;
- the source associated with each value;
- relevant source dates;
- retrieval timestamps; and
- limitations affecting interpretation.

A correlation or repeated value across multiple sources does not automatically establish that the information is correct.

## Proof-of-Concept Publication

The initial public proof of concept is intended to demonstrate:

- lawful API and public-data collection;
- provenance preservation;
- structured normalization;
- source attribution;
- cross-source correlation;
- reproducible research methodology; and
- transparent intelligence-report generation.

The initial proof of concept does not require an investigative target.

A benign public example may be used to demonstrate the system architecture and reporting process.

## Project Status

**Status:** Early development / proof of concept

The initial goal is to publish a documented proof of concept showing how multiple lawful public sources can be correlated while retaining attribution, licensing information, source provenance, and a clear distinction between evidence and analysis.

The project's architecture, documentation, and supported sources are expected to evolve during development.

## Organization

**Signal Forge Research**

Independent research project focused on OSINT, public-data analysis, provenance, and reproducible research methodology.

## Contact

Email: research@signalforgeresearch.com

Website: https://signalforgeresearch.com

GitHub Organization: https://github.com/signal-forge-research
