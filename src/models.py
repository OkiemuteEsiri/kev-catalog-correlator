from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Optional


@dataclass(frozen=True)
class VulnerabilityFinding:
    finding_id: str
    asset_id: str
    cve: str
    cvss: float
    asset_criticality: int
    internet_exposed: bool
    owner: str
    first_seen: date
    remediation_status: str = "open"


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    date_added: date
    due_date: Optional[date]
    ransomware_use: bool
    required_action: str


@dataclass(frozen=True)
class CorrelatedFinding:
    finding: VulnerabilityFinding
    kev: KevEntry
    risk_score: int
    priority: str
    rationale: tuple[str, ...]
