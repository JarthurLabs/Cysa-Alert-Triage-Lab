#!/usr/bin/env python3
"""Prioritize vulnerability findings using business context.

This is not meant to replace a formal enterprise risk model. It is a small,
readable scoring model for a portfolio project: CVSS matters, but so do known
exploitation, internet exposure, available exploit code, and asset criticality.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "outputs"
OUT.mkdir(exist_ok=True)

CRITICALITY = {"low": 0, "medium": 8, "high": 16, "critical": 24}
CONTROL_OFFSET = {
    "none": 0,
    "partial_waf_rule": -4,
    "mfa_enabled_no_push_limits": -2,
    "segmented_internal": -8,
    "edr_present": -6,
}


def yes(value: str) -> bool:
    return value.strip().lower() in {"yes", "true", "1"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def risk_score(finding: dict[str, str], asset: dict[str, str]) -> int:
    score = float(finding["cvss"]) * 8
    if yes(finding["known_exploited"]):
        score += 20
    if yes(finding["exploit_available"]):
        score += 12
    if yes(finding["internet_exposed"]):
        score += 15
    score += CRITICALITY.get(asset["asset_criticality"].lower(), 0)
    score += CONTROL_OFFSET.get(finding["control_status"], 0)
    return max(0, min(100, round(score)))


def priority(score: int) -> str:
    if score >= 90:
        return "P1 - Fix now"
    if score >= 75:
        return "P2 - Fix this week"
    if score >= 55:
        return "P3 - Fix in normal patch cycle"
    return "P4 - Track / accept with owner approval"


def main() -> None:
    assets = {row["asset_id"]: row for row in read_csv(DATA / "asset_inventory.csv")}
    findings = read_csv(DATA / "vulnerability_findings.csv")
    enriched = []
    for finding in findings:
        asset = assets[finding["asset_id"]]
        score = risk_score(finding, asset)
        enriched.append({
            **finding,
            "asset_name": asset["name"],
            "asset_criticality": asset["asset_criticality"],
            "business_context": asset["business_context"],
            "risk_score": score,
            "priority": priority(score),
        })

    enriched.sort(key=lambda row: row["risk_score"], reverse=True)
    out = OUT / "prioritized_vulnerabilities.csv"
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(enriched[0].keys()))
        writer.writeheader()
        writer.writerows(enriched)

    lines = [
        "# Vulnerability Prioritization Notes",
        "",
        "I did not rank findings by CVSS alone. The lab uses a small context-based model: CVSS + known exploitation + exploit availability + exposure + asset criticality - existing controls.",
        "",
        "| Priority | Score | Finding | Asset | Why it matters |",
        "|---|---:|---|---|---|",
    ]
    for row in enriched:
        lines.append(f"| {row['priority']} | {row['risk_score']} | {row['title']} | {row['asset_name']} | {row['business_context']} |")
    (OUT / "vulnerability_prioritization.md").write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(enriched)} prioritized findings to {out}")


if __name__ == "__main__":
    main()
