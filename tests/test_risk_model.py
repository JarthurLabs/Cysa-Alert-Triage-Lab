import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from prioritize_vulnerabilities import risk_score, priority


def test_internet_exposed_known_exploited_item_is_high_priority():
    finding = {
        "cvss": "9.1",
        "known_exploited": "yes",
        "exploit_available": "yes",
        "internet_exposed": "yes",
        "control_status": "partial_waf_rule",
    }
    asset = {"asset_criticality": "high"}
    score = risk_score(finding, asset)
    assert score >= 90
    assert priority(score) == "P1 - Fix now"


def test_segmented_internal_finding_is_not_automatically_p1():
    finding = {
        "cvss": "8.2",
        "known_exploited": "no",
        "exploit_available": "no",
        "internet_exposed": "no",
        "control_status": "segmented_internal",
    }
    asset = {"asset_criticality": "critical"}
    score = risk_score(finding, asset)
    assert score < 90
