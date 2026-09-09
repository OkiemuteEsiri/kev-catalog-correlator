# KEV Catalog Correlator

A recruiter-facing Vulnerability Management / Exposure Management project that demonstrates how vulnerability findings can be correlated with a known-exploited-vulnerability catalog, enriched with asset context, prioritized using explainable risk logic, and carried through remediation and revalidation.

> This repository uses synthetic data only. It performs no production scanning, contains no credentials, and does not claim that vulnerability presence is evidence of compromise.

## Problem statement

Traditional vulnerability queues often over-prioritize scanner severity while under-weighting real exploitation evidence and asset context. A stronger workflow should answer:

- Is the CVE known to be exploited?
- Is the affected asset business-critical?
- Is the service internet exposed?
- Is remediation already overdue?
- Is ransomware use associated with the catalog entry?
- How old is the finding?
- Can an analyst explain exactly why the finding received its priority?

This project turns those questions into a deterministic defensive engineering workflow.

## Architecture

```text
Synthetic scanner findings
        |
        v
Input validation / normalization
        |
        +------ Synthetic KEV catalog
        |                |
        +-------- CVE correlation
                         |
                         v
              Explainable risk scoring
                         |
                         v
                    P0-P3 priority
                         |
              +----------+----------+
              |                     |
       Fleet metrics          Markdown report
              |                     |
              +----------+----------+
                         |
              Remediation / revalidation
```

### Repository structure

```text
.github/workflows/ci.yml   Least-privilege CI
src/models.py              Canonical immutable models
src/correlator.py          Validation, matching and scoring
src/reporting.py           Portfolio metrics and Markdown reporting
src/cli.py                 Reproducible CLI workflow
data/findings.json         Synthetic vulnerability findings
data/kev_catalog.json      Synthetic KEV-style catalog
tests/test_correlator.py   Unit tests
docs/architecture.md       Components, trust boundaries, extensions
docs/methodology.md        Correlation and risk methodology
docs/remediation-validation.md  Closure and revalidation workflow
reports/example-report.md  Synthetic executive assessment
```

## Risk model

Every KEV-correlated finding starts with a known-exploitation base score. Context adds weight for:

| Signal | Why it matters |
|---|---|
| KEV membership | Evidence that exploitation is known in the wild |
| CVSS severity | Technical impact signal, not a complete risk score |
| Asset criticality | Business consequence and service importance |
| Internet exposure | Reachability and attack-surface context |
| Ransomware-use flag | Additional threat urgency where catalog evidence exists |
| Overdue due date | Governance / remediation urgency |
| Finding age | Persistent exposure and remediation debt |

Scores are capped at 100 and mapped to P0-P3. The scoring engine also preserves a human-readable rationale so prioritization is auditable rather than opaque.

## Usage

Requires Python 3.11+ and only the standard library.

```bash
python -m src.cli \
  --findings data/findings.json \
  --kev data/kev_catalog.json \
  --output kev-report.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Example output

The synthetic example produces a prioritized table of catalog-matched findings and portfolio-level metrics such as:

- matched KEV findings
- P0-P3 distribution
- internet-exposed KEV count
- ransomware-flagged KEV count
- ownership distribution

See `reports/example-report.md` for an executive-style walkthrough.

## Remediation workflow

1. Validate CVE applicability and affected product/version.
2. Confirm asset identity, ownership, criticality, and reachability.
3. Apply vendor-supported remediation or documented temporary controls.
4. Re-scan or independently validate configuration/version state.
5. Confirm exposure reduction, not just ticket completion.
6. Close only with evidence and documented residual risk.

## MITRE ATT&CK context

This project maps vulnerability exposure defensively to:

- **T1190 - Exploit Public-Facing Application**
- **T1210 - Exploitation of Remote Services**

These mappings describe plausible attacker techniques associated with vulnerable services. They are not used to infer that exploitation has occurred.

## Design decisions

- **Deterministic correlation:** CVE is the explicit join key.
- **Explainability first:** every score includes a rationale.
- **No false downgrading:** non-KEV findings are excluded from KEV-specific output rather than labeled low risk.
- **No live offensive behavior:** the project performs analysis only.
- **Synthetic fixtures:** no employer, customer, scanner, CMDB, or production data is included.
- **Standard-library implementation:** keeps the lab easy to audit and execute.

## Limitations

This is a portfolio implementation, not a production vulnerability platform. It does not currently include live CISA ingestion, EPSS, SBOM/package matching, product-version applicability logic, scanner APIs, CMDB ownership reconciliation, ticketing integrations, historical storage, or compensating-control telemetry.

Those omissions are deliberate: production integrations require source authentication, schema contracts, freshness monitoring, error handling, authorization, and data-governance controls that should not be simulated as if they were deployed.

## Skills demonstrated

- Risk-based Vulnerability Management
- Threat-informed vulnerability prioritization
- Exposure Management
- Python security engineering
- Defensive data modeling and validation
- Explainable scoring design
- Security metrics and reporting
- Remediation governance
- Revalidation / closure evidence
- MITRE ATT&CK contextual mapping
- Unit testing
- GitHub Actions CI

## Roadmap

- Add a signed CISA KEV ingestion adapter with freshness checks
- Add EPSS enrichment and confidence-aware scoring
- Add product/version applicability normalization
- Add asset/CMDB ownership reconciliation
- Add exception-expiry governance
- Add historical backlog and aging trends
- Add export formats for ticketing and BI pipelines
- Add data-quality scorecards and feed-health monitoring

## Security and ethical scope

The repository is intentionally defensive. It contains no exploit code, credential attacks, persistence, command-and-control functionality, malware, production targets, real secrets, or confidential organizational data.
