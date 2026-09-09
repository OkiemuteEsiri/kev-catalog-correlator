# Remediation and Revalidation Workflow

## 1. Validate scope
Confirm the CVE, affected product/version, asset identity, service exposure, business criticality, and ownership. Do not treat a scanner match as sufficient evidence by itself.

## 2. Prioritize
Escalate KEV findings based on exploitation evidence plus contextual factors such as internet exposure, business criticality, overdue remediation dates, and ransomware-use indicators.

## 3. Remediate
Prefer the vendor-supported fix. Where immediate patching is not possible, document temporary compensating controls, exception owner, expiry date, and residual risk.

## 4. Validate implementation
Verify the installed version/configuration and confirm that the vulnerable condition is no longer present. Re-scan with an appropriate scanner or configuration-control source.

## 5. Validate exposure reduction
For externally reachable services, confirm the vulnerable path is no longer exposed. Review firewall, reverse-proxy, WAF, segmentation, or access-control changes where relevant.

## 6. Close with evidence
A finding should close only when remediation evidence, re-scan/revalidation evidence, asset ownership, and exception status are reconciled.

## Suggested evidence fields
- finding ID and CVE
- asset ID / service
- remediation action
- change or ticket reference
- validation timestamp
- validating control/source
- pre/post state
- residual risk
- reviewer

## Strategic controls
Track KEV backlog age, internet-exposed KEV count, overdue KEV count, ransomware-associated KEV count, ownership completeness, and time-to-revalidate. These metrics help distinguish remediation throughput from actual exposure reduction.
