#!/usr/bin/env python3
"""Analyze synthetic security logs for a small CySA+-style portfolio lab.

This script intentionally uses only the Python standard library so a reviewer can
clone the repo and run it without fighting dependency issues.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "outputs"
OUT.mkdir(exist_ok=True)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


@dataclass
class Alert:
    alert_id: str
    severity: str
    title: str
    source: str
    timestamp: str
    entity: str
    evidence: str
    analyst_note: str
    mitre_mapping: str


def detect_password_spray(auth_events: Iterable[dict[str, str]]) -> list[Alert]:
    """Detect one source IP failing against several unique accounts.

    First attempt used a simple threshold of 3 failures. That produced too much
    noise because normal login typos can cluster during the morning. The current
    logic checks unique users in a 20-minute window from the same source.
    """
    failures_by_ip: dict[str, list[dict[str, str]]] = defaultdict(list)
    for event in auth_events:
        if event["event_type"] == "login_failure":
            failures_by_ip[event["src_ip"]].append(event)

    alerts: list[Alert] = []
    for src_ip, events in failures_by_ip.items():
        events = sorted(events, key=lambda e: e["timestamp"])
        for start_idx, start_event in enumerate(events):
            start = parse_time(start_event["timestamp"])
            window = [
                e for e in events[start_idx:]
                if parse_time(e["timestamp"]) <= start + timedelta(minutes=20)
            ]
            unique_users = sorted({e["user"] for e in window})
            if len(unique_users) >= 5:
                alerts.append(Alert(
                    alert_id="AUTH-001",
                    severity="Medium",
                    title="Possible password spray against VPN",
                    source="auth_events.csv",
                    timestamp=start_event["timestamp"],
                    entity=src_ip,
                    evidence=f"{len(window)} failures across {len(unique_users)} users: {', '.join(unique_users[:6])}",
                    analyst_note="Pattern is broader than normal typo behavior. Escalate if followed by MFA approval or successful login.",
                    mitre_mapping="T1110.003 Password Spraying",
                ))
                break
    return alerts


def detect_mfa_fatigue(auth_events: Iterable[dict[str, str]]) -> list[Alert]:
    by_user: dict[str, list[dict[str, str]]] = defaultdict(list)
    for event in auth_events:
        if event["event_type"] in {"mfa_push", "login_success"}:
            by_user[event["user"]].append(event)

    alerts: list[Alert] = []
    for user, events in by_user.items():
        events = sorted(events, key=lambda e: e["timestamp"])
        for event in events:
            if event["event_type"] != "login_success" or event["mfa_result"] != "approved":
                continue
            success_time = parse_time(event["timestamp"])
            recent_denies = [
                e for e in events
                if e["event_type"] == "mfa_push"
                and e["mfa_result"] == "denied"
                and success_time - timedelta(minutes=20) <= parse_time(e["timestamp"]) < success_time
            ]
            unknown_device = event["device"] == "unknown"
            if len(recent_denies) >= 2 and unknown_device:
                alerts.append(Alert(
                    alert_id="AUTH-002",
                    severity="High",
                    title="MFA fatigue pattern followed by approval",
                    source="auth_events.csv",
                    timestamp=event["timestamp"],
                    entity=user,
                    evidence=f"{len(recent_denies)} denied MFA prompts before approved VPN login from {event['src_ip']}",
                    analyst_note="Treat as likely account compromise until user confirmation and session review are complete.",
                    mitre_mapping="T1621 Multi-Factor Authentication Request Generation",
                ))
    return alerts


def detect_sensitive_export(web_events: Iterable[dict[str, str]]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in web_events:
        suspicious_agent = event["user_agent"].lower().startswith(("curl", "python-requests"))
        sensitive_path = "export" in event["path"] or "download/reports" in event["path"]
        large_response = int(event["bytes"]) > 100_000
        if sensitive_path and suspicious_agent and large_response:
            alerts.append(Alert(
                alert_id="WEB-001",
                severity="High",
                title="Sensitive export from scripted user agent",
                source="web_access_events.csv",
                timestamp=event["timestamp"],
                entity=f"{event['user']} from {event['src_ip']}",
                evidence=f"{event['method']} {event['path']} returned {event['status']} with {event['bytes']} bytes via {event['user_agent']}",
                analyst_note="Scripted access after risky authentication increases confidence. Validate business need and review data scope.",
                mitre_mapping="T1530 Data from Cloud Storage / T1005 Data from Local System",
            ))
    return alerts


def detect_suspicious_endpoint(endpoint_events: Iterable[dict[str, str]]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in endpoint_events:
        cmd = event["command_line"].lower()
        parent = event["parent_process"].lower()
        process = event["process"].lower()
        if process == "powershell.exe" and "encodedcommand" in cmd and parent == "w3wp.exe":
            alerts.append(Alert(
                alert_id="EDR-001",
                severity="Critical",
                title="Encoded PowerShell launched by web worker process",
                source="endpoint_events.csv",
                timestamp=event["timestamp"],
                entity=event["host"],
                evidence=f"{event['parent_process']} -> {event['process']} with network connection {event['network_connection']}",
                analyst_note="High-risk process chain on an app server. Isolate host if confirmed and preserve evidence before cleanup.",
                mitre_mapping="T1059.001 PowerShell",
            ))
    return alerts


def write_outputs(alerts: list[Alert]) -> None:
    alerts = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    with (OUT / "alert_summary.csv").open("w", newline="") as f:
        fieldnames = list(asdict(alerts[0]).keys()) if alerts else ["alert_id"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(asdict(alert))

    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    top_severity = max((severity_rank[a.severity] for a in alerts), default=0)
    summary = {
        "total_alerts": len(alerts),
        "highest_severity": next((k for k, v in severity_rank.items() if v == top_severity), "None"),
        "recommended_status": "Declare security incident" if top_severity >= 4 else "Continue triage",
        "generated_from": ["auth_events.csv", "web_access_events.csv", "endpoint_events.csv"],
    }
    (OUT / "kpi_metrics.json").write_text(json.dumps(summary, indent=2))

    lines = [
        "# Alert Triage Summary",
        "",
        f"Total alerts: **{summary['total_alerts']}**",
        f"Highest severity: **{summary['highest_severity']}**",
        f"Recommended status: **{summary['recommended_status']}**",
        "",
        "| Severity | Alert | Entity | Evidence |",
        "|---|---|---|---|",
    ]
    for alert in alerts:
        lines.append(f"| {alert.severity} | {alert.title} | {alert.entity} | {alert.evidence} |")
    (OUT / "alert_triage_summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    auth_events = read_csv(DATA / "auth_events.csv")
    web_events = read_csv(DATA / "web_access_events.csv")
    endpoint_events = read_csv(DATA / "endpoint_events.csv")

    alerts: list[Alert] = []
    alerts.extend(detect_password_spray(auth_events))
    alerts.extend(detect_mfa_fatigue(auth_events))
    alerts.extend(detect_sensitive_export(web_events))
    alerts.extend(detect_suspicious_endpoint(endpoint_events))
    write_outputs(alerts)
    print(f"Wrote {len(alerts)} alerts to {OUT / 'alert_summary.csv'}")


if __name__ == "__main__":
    main()
