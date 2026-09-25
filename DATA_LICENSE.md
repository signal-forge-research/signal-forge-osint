# Data Licensing and Attribution

This document explains how data used or published by the Signal Forge OSINT
project is licensed, attributed, and separated according to its original source.

Signal Forge Research uses multiple public-data and properly licensed OSINT
sources. Each source retains its own licensing, attribution, access, and
redistribution requirements.

This repository does not imply that all data collected or referenced by the
project is freely redistributable.

---

## OpenCorporates Data

OpenCorporates data used by this project will be handled in accordance with the
applicable OpenCorporates open-data, attribution, and share-alike requirements.

OpenCorporates states that free API access for open-data projects is provided
where the product or database incorporating OpenCorporates data is also released
under an open licence using share-alike attribution conditions.

Where OpenCorporates-derived data is published by this project, the project will:

- clearly identify OpenCorporates as the data source;
- preserve the OpenCorporates URL associated with the entity where available;
- preserve source and provenance information where available;
- preserve retrieval timestamps where available;
- identify relevant jurisdiction codes and company identifiers where appropriate;
- provide attribution to OpenCorporates;
- comply with applicable share-alike requirements; and
- avoid representing OpenCorporates-derived data as proprietary Signal Forge
  Research data.

OpenCorporates-derived database content published through this project is intended
to be made available under the Open Database License (ODbL) 1.0 where required by
the applicable OpenCorporates licensing terms.

For authoritative licensing terms, users should consult OpenCorporates directly:

https://opencorporates.com/legal/licence

---

## Source Provenance

Signal Forge Research is designed to preserve the origin of information whenever
practicable.

Structured records may contain provenance fields such as:

```json
{
  "provider": "OpenCorporates",
  "source_url": "https://opencorporates.com/...",
  "original_source_url": "https://...",
  "retrieved_at": "YYYY-MM-DDTHH:MM:SSZ",
  "jurisdiction": "example",
  "company_number": "example",
  "license": "Applicable provider terms"
}
