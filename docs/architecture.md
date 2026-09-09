# Architecture

## Objective

The project demonstrates a safe, explainable vulnerability-intelligence correlation workflow. It joins normalized vulnerability findings with a synthetic KEV-style catalog, then produces prioritization signals and management-ready output.

## Components

1. `src/models.py` defines immutable canonical data models.
2. `src/correlator.py` validates inputs, joins by CVE, calculates explainable risk, and assigns priorities.
3. `src/reporting.py` produces aggregate metrics and Markdown output.
4. `src/cli.py` provides a reproducible command-line workflow.
5. `data/` contains synthetic test fixtures only.
6. `tests/` validates deterministic behavior and failure handling.

## Trust boundaries

External scanner exports and threat-intelligence feeds are untrusted inputs. Production implementations should validate schema, provenance, freshness, and source integrity before correlation. This lab intentionally performs no live API calls and contains no credentials.

## Data flow

Scanner findings -> validation/normalization -> CVE join -> KEV enrichment -> contextual scoring -> priority tier -> report -> remediation/revalidation workflow.

## Production extension points

- signed feed retrieval and provenance checks
- CISA KEV ingestion adapter
- EPSS enrichment
- asset CMDB integration
- exception governance
- ticketing/SOAR integration
- historical trend storage
- ownership and business-service mapping
