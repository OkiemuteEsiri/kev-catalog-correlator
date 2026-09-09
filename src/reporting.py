from __future__ import annotations

from collections import Counter
from .models import CorrelatedFinding


def summarize(results: list[CorrelatedFinding]) -> dict[str, object]:
    priorities = Counter(item.priority for item in results)
    owners = Counter((item.finding.owner or "UNASSIGNED") for item in results)
    return {
        "matched_findings": len(results),
        "priority_counts": dict(sorted(priorities.items())),
        "owner_counts": dict(sorted(owners.items())),
        "internet_exposed": sum(1 for item in results if item.finding.internet_exposed),
        "ransomware_flagged": sum(1 for item in results if item.kev.ransomware_use),
    }


def to_markdown(results: list[CorrelatedFinding]) -> str:
    summary = summarize(results)
    lines = [
        "# KEV Correlation Report",
        "",
        f"Matched findings: **{summary['matched_findings']}**",
        f"Internet-exposed matches: **{summary['internet_exposed']}**",
        f"Ransomware-flagged matches: **{summary['ransomware_flagged']}**",
        "",
        "| Priority | Score | CVE | Asset | Owner | Internet Exposed | Ransomware Use |",
        "|---|---:|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(
            f"| {item.priority} | {item.risk_score} | {item.finding.cve} | {item.finding.asset_id} | "
            f"{item.finding.owner or 'UNASSIGNED'} | {item.finding.internet_exposed} | {item.kev.ransomware_use} |"
        )
    return "\n".join(lines) + "\n"
