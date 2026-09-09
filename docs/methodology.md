# Methodology

## Correlation

The correlator treats CVE equality as the deterministic join key between normalized vulnerability findings and the KEV-style intelligence catalog. Findings not present in the catalog remain outside this project's KEV-priority output rather than being falsely downgraded to low risk.

## Risk model

Every KEV match begins with a known-exploitation base score. Context then modifies priority using:

- CVSS severity
- asset criticality (1-5)
- internet exposure
- ransomware-use flag
- overdue remediation date
- finding age

Scores are capped at 100 and mapped to P0-P3. The rationale list is preserved so an analyst can explain why a finding received its priority.

## Governance principles

KEV membership is an urgency signal, not proof that a specific asset was compromised. CVSS alone is not treated as business risk. Asset context must be validated against authoritative inventory. Missing ownership should trigger data-quality remediation rather than arbitrary risk inflation.

## MITRE ATT&CK context

KEV vulnerabilities commonly create defensive relevance to **T1190 - Exploit Public-Facing Application** and **T1210 - Exploitation of Remote Services** when affected services are reachable. These mappings provide threat-context only; the project does not infer adversary activity from vulnerability presence.

## Validation

A production workflow should validate the catalog's source and freshness, confirm affected product/version state, verify asset reachability, inspect compensating controls, and re-scan after remediation before closure.
