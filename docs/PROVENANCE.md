# Provenance and Evidence Tracking

This document defines how Signal Forge OSINT records where information came from,
when it was obtained, how it was transformed, and how it was used in research
outputs.

The purpose of provenance tracking is to make findings traceable, reproducible,
auditable, and clearly distinguishable from analyst interpretation.

Signal Forge Research is designed so that significant facts should not appear in
a report without enough source information to determine where they originated.

---

## Core Principle

Every research result should preserve, where practicable:

- the provider or source name;
- the source URL or API endpoint;
- the original entity or record identifier;
- the query or lookup value used;
- the retrieval date and time;
- the applicable licence or provider terms;
- the raw or normalized value returned;
- any transformation applied to the value; and
- any later correlation or analyst interpretation.

Source data and analyst conclusions should remain separate.

---

## Provenance Layers

Signal Forge OSINT may represent information in four layers.

### 1. Raw Source Data

Raw source data is information returned directly by an API, public record, or
other lawful research source.

Examples include:

- an OpenCorporates company record;
- a GreyNoise IP classification;
- a WhoisXML domain registration record;
- a DNSDumpster DNS result;
- an SEC EDGAR filing record.

Where provider terms permit storage, raw responses may be retained for
reproducibility and troubleshooting.

### 2. Normalized Data

Normalized data is source information converted into a consistent internal
format.

Examples include:

- converting dates into ISO 8601 format;
- separating a company name from a company identifier;
- representing IP addresses consistently;
- converting provider-specific field names into a common schema.

Normalization must not change the factual meaning of the source record.

### 3. Correlated or Derived Data

Correlated data is produced when information from two or more sources is linked.

Examples include:

- associating a company with a domain using separately sourced evidence;
- associating a domain with an IP address;
- matching a legal entity across corporate and public filing records.

Derived relationships should identify the source records that support them.

A correlation is not automatically treated as a verified fact merely because
multiple values appear similar.

### 4. Analyst Observation

An analyst observation is an interpretation, assessment, or conclusion based on
source or correlated data.

Analyst observations must be clearly distinguishable from source facts.

Where appropriate, the report should identify:

- the evidence supporting the observation;
- the level of confidence;
- important limitations; and
- alternative explanations.

---

## Recommended Record Structure

A normalized research record may use fields similar to:

```json
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
