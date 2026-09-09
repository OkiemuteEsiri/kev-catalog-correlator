from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Iterable

from .models import CorrelatedFinding, KevEntry, VulnerabilityFinding


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return date.fromisoformat(value)


def load_findings(path: str | Path) -> list[VulnerabilityFinding]:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    findings: list[VulnerabilityFinding] = []
    for record in records:
        cve = str(record["cve"]).upper().strip()
        cvss = float(record["cvss"])
        criticality = int(record["asset_criticality"])
        if not cve.startswith("CVE-"):
            raise ValueError(f"Invalid CVE identifier: {cve}")
        if not 0 <= cvss <= 10:
            raise ValueError(f"CVSS out of range for {cve}")
        if not 1 <= criticality <= 5:
            raise ValueError(f"Asset criticality out of range for {cve}")
        findings.append(
            VulnerabilityFinding(
                finding_id=str(record["finding_id"]),
                asset_id=str(record["asset_id"]),
                cve=cve,
                cvss=cvss,
                asset_criticality=criticality,
                internet_exposed=bool(record["internet_exposed"]),
                owner=str(record["owner"]).strip(),
                first_seen=date.fromisoformat(record["first_seen"]),
                remediation_status=str(record.get("remediation_status", "open")),
            )
        )
    return findings


def load_kev_catalog(path: str | Path) -> list[KevEntry]:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        KevEntry(
            cve=str(record["cve"]).upper().strip(),
            vendor=str(record["vendor"]),
            product=str(record["product"]),
            date_added=date.fromisoformat(record["date_added"]),
            due_date=_parse_date(record.get("due_date")),
            ransomware_use=bool(record.get("ransomware_use", False)),
            required_action=str(record["required_action"]),
        )
        for record in records
    ]


def score_finding(finding: VulnerabilityFinding, kev: KevEntry, today: date | None = None) -> tuple[int, tuple[str, ...]]:
    today = today or date.today()
    score = 35
    rationale = ["CVE appears in the known-exploited catalog"]

    if finding.cvss >= 9.0:
        score += 15
        rationale.append("critical CVSS severity")
    elif finding.cvss >= 7.0:
        score += 10
        rationale.append("high CVSS severity")

    score += finding.asset_criticality * 6
    rationale.append(f"asset criticality {finding.asset_criticality}/5")

    if finding.internet_exposed:
        score += 15
        rationale.append("internet-exposed asset")

    if kev.ransomware_use:
        score += 10
        rationale.append("catalog flags known ransomware campaign use")

    if kev.due_date and today > kev.due_date:
        score += 10
        rationale.append("remediation due date exceeded")

    age_days = (today - finding.first_seen).days
    if age_days > 90:
        score += 5
        rationale.append("finding age exceeds 90 days")

    return min(score, 100), tuple(rationale)


def priority_for(score: int) -> str:
    if score >= 90:
        return "P0"
    if score >= 75:
        return "P1"
    if score >= 55:
        return "P2"
    return "P3"


def correlate(findings: Iterable[VulnerabilityFinding], kev_catalog: Iterable[KevEntry], today: date | None = None) -> list[CorrelatedFinding]:
    kev_by_cve = {entry.cve: entry for entry in kev_catalog}
    results: list[CorrelatedFinding] = []
    seen_ids: set[str] = set()

    for finding in findings:
        if finding.finding_id in seen_ids:
            raise ValueError(f"Duplicate finding_id: {finding.finding_id}")
        seen_ids.add(finding.finding_id)
        kev = kev_by_cve.get(finding.cve)
        if not kev:
            continue
        score, rationale = score_finding(finding, kev, today=today)
        results.append(CorrelatedFinding(finding, kev, score, priority_for(score), rationale))

    return sorted(results, key=lambda item: (-item.risk_score, item.finding.asset_id, item.finding.cve))
