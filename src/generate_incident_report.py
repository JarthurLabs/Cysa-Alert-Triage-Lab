#!/usr/bin/env python3
"""Build the final incident report from generated CSV outputs."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
DOCS = ROOT / "docs"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    alerts = read_csv(OUT / "alert_summary.csv")
    vulns = read_csv(OUT / "prioritized_vulnerabilities.csv")
    metrics = json.loads((OUT / "kpi_metrics.json").read_text())

    lines = [
        "# Incident Report - HarborCare Portal Suspicious Access",
        "",
        "> Synthetic portfolio case. No real customer, patient, or company data is used.",
        "",
        "## Executive summary",
        "",
        "The lab data shows a likely account compromise beginning with password spraying, followed by repeated MFA prompts, a successful VPN login from an unknown device, scripted access to admin/export routes, and suspicious process activity on the application server.",
        "",
        f"- Total correlated alerts: **{metrics['total_alerts']}**",
        f"- Highest severity: **{metrics['highest_severity']}**",
        f"- Recommended status: **{metrics['recommended_status']}**",
        "",
        "## Evidence table",
        "",
        "| Time | Severity | Alert | Entity | Evidence | MITRE mapping |",
        "|---|---|---|---|---|---|",
    ]
    for alert in alerts:
        lines.append(f"| {alert['timestamp']} | {alert['severity']} | {alert['title']} | {alert['entity']} | {alert['evidence']} | {alert['mitre_mapping']} |")

    lines.extend([
        "",
        "## Containment and recovery plan",
        "",
        "1. Disable active sessions for the affected account and require password reset.",
        "2. Temporarily isolate the application server from non-essential outbound traffic while evidence is preserved.",
        "3. Review admin export logs and confirm whether any regulated data left the environment.",
        "4. Patch the outdated upload component and enforce stricter MFA controls.",
        "5. Add detections for scripted admin exports, web-worker process spawning, and repeated MFA deny/approve patterns.",
        "",
        "## Vulnerability work tied to this incident",
        "",
        "| Priority | Score | Finding | Recommended action |",
        "|---|---:|---|---|",
    ])
    for vuln in vulns[:3]:
        lines.append(f"| {vuln['priority']} | {vuln['risk_score']} | {vuln['title']} | {vuln['recommended_action']} |")

    lines.extend([
        "",
        "## Lessons learned",
        "",
        "- CVSS alone was not enough. The riskiest item was dangerous because it was exposed, tied to a high-value asset, and had exploitation indicators.",
        "- MFA is not magic. Push fatigue can turn a strong control into a user-experience problem if prompts are unlimited and unclear.",
        "- Detection logic needs tuning. My first password-spray rule was too noisy, so I moved to unique-account behavior over a time window.",
        "- The report has to be understandable by technical and non-technical readers. A perfect query is not useful if nobody understands the risk or next action.",
        "",
    ])
    report = "\n".join(lines) + "\n"
    (DOCS / "incident_report.md").write_text(report)
    (OUT / "incident_report.md").write_text(report)
    print(f"Wrote report to {DOCS / 'incident_report.md'}")


if __name__ == "__main__":
    main()
