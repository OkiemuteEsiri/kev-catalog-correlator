import unittest
from datetime import date

from src.correlator import correlate, priority_for, score_finding
from src.models import KevEntry, VulnerabilityFinding
from src.reporting import summarize, to_markdown


class KevCorrelatorTests(unittest.TestCase):
    def setUp(self):
        self.finding = VulnerabilityFinding(
            finding_id="F-1",
            asset_id="WEB-1",
            cve="CVE-2024-0001",
            cvss=9.8,
            asset_criticality=5,
            internet_exposed=True,
            owner="Web Team",
            first_seen=date(2026, 1, 1),
        )
        self.kev = KevEntry(
            cve="CVE-2024-0001",
            vendor="Example",
            product="Gateway",
            date_added=date(2026, 1, 10),
            due_date=date(2026, 2, 1),
            ransomware_use=True,
            required_action="Patch",
        )

    def test_known_exploited_internet_facing_critical_is_p0(self):
        score, rationale = score_finding(self.finding, self.kev, today=date(2026, 9, 9))
        self.assertEqual(score, 100)
        self.assertEqual(priority_for(score), "P0")
        self.assertIn("internet-exposed asset", rationale)

    def test_non_kev_findings_are_not_returned(self):
        other = VulnerabilityFinding("F-2", "HOST-2", "CVE-2099-9999", 8.0, 3, False, "Ops", date(2026, 8, 1))
        self.assertEqual(correlate([other], [self.kev], today=date(2026, 9, 9)), [])

    def test_duplicate_finding_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            correlate([self.finding, self.finding], [self.kev], today=date(2026, 9, 9))

    def test_results_are_sorted_by_risk(self):
        lower = VulnerabilityFinding("F-2", "APP-2", self.kev.cve, 7.2, 2, False, "Apps", date(2026, 8, 1))
        results = correlate([lower, self.finding], [self.kev], today=date(2026, 9, 9))
        self.assertGreaterEqual(results[0].risk_score, results[1].risk_score)

    def test_summary_counts_exposure_and_ransomware(self):
        results = correlate([self.finding], [self.kev], today=date(2026, 9, 9))
        summary = summarize(results)
        self.assertEqual(summary["matched_findings"], 1)
        self.assertEqual(summary["internet_exposed"], 1)
        self.assertEqual(summary["ransomware_flagged"], 1)

    def test_markdown_contains_asset_and_cve(self):
        results = correlate([self.finding], [self.kev], today=date(2026, 9, 9))
        report = to_markdown(results)
        self.assertIn("WEB-1", report)
        self.assertIn("CVE-2024-0001", report)


if __name__ == "__main__":
    unittest.main()
