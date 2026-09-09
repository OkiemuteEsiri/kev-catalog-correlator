# Example KEV Correlation Assessment

> Synthetic demonstration output. No production or client data is represented.

## Executive summary

The sample dataset contains five vulnerability findings, three of which correlate to the synthetic KEV catalog. Two correlated findings are internet-exposed and two carry the synthetic ransomware-use flag, making them the highest remediation priorities.

| Priority | Score | CVE | Asset | Owner | Internet Exposed | Ransomware Use |
|---|---:|---|---|---|---|---|
| P0 | 100 | CVE-2024-0001 | WEB-001 | Digital Platforms | True | True |
| P0 | 100 | CVE-2021-3333 | API-002 | API Engineering | True | True |
| P1 | 89 | CVE-2023-1111 | APP-014 | Business Apps | False | False |

## Interpretation

The first two findings combine known exploitation, high/critical severity, business-critical assets, external exposure, overdue remediation dates, and ransomware-use context. Their priority is driven by the combination of threat intelligence and asset context rather than CVSS alone.

The third finding is also known-exploited and overdue, but it is not internet-facing and has a lower asset-criticality score. It remains urgent but ranks below the externally exposed P0 findings.

## Recommended sequence

1. Validate product/version applicability and external reachability for WEB-001 and API-002.
2. Apply supported vendor remediation or remove vulnerable external exposure.
3. Re-scan and independently validate the changed service state.
4. Address APP-014 and confirm the vulnerable component is removed or patched.
5. Record evidence and residual risk before closure.

## Residual-risk note

Catalog membership alone is not evidence of compromise. Incident-response escalation should be based on telemetry, indicators, anomalous behavior, or other evidence of malicious activity.
