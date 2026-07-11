#!/usr/bin/env python3
"""Validate and summarize the public Sysmon telemetry used by this project."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


EXPECTED_SHA256 = "9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
ENCODED_SWITCH = re.compile(
    r"(?:^|\s)-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{5,}",
    re.IGNORECASE,
)
LONG_PADDING = re.compile(r"\s{50,}")


@dataclass(frozen=True)
class ProcessEvent:
    event_id: int
    time_utc: str
    computer: str
    user: str
    image: str
    command_line: str
    parent_image: str
    process_guid: str
    parent_process_guid: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_event(line: str) -> ProcessEvent:
    root = ET.fromstring(line)
    event_id = int(root.findtext("e:System/e:EventID", default="0", namespaces=NS))
    computer = root.findtext("e:System/e:Computer", default="", namespaces=NS)
    created = root.find("e:System/e:TimeCreated", NS)
    time_utc = created.attrib.get("SystemTime", "") if created is not None else ""
    fields = {
        node.attrib.get("Name", ""): (node.text or "")
        for node in root.findall("e:EventData/e:Data", NS)
    }
    return ProcessEvent(
        event_id=event_id,
        time_utc=time_utc,
        computer=computer,
        user=fields.get("User", ""),
        image=fields.get("Image", ""),
        command_line=fields.get("CommandLine", ""),
        parent_image=fields.get("ParentImage", ""),
        process_guid=fields.get("ProcessGuid", ""),
        parent_process_guid=fields.get("ParentProcessGuid", ""),
    )


def load_events(path: Path) -> list[ProcessEvent]:
    return [parse_event(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def is_explorer_child_candidate(event: ProcessEvent) -> bool:
    parent = event.parent_image.lower().replace("/", "\\")
    image = event.image.lower().replace("/", "\\")
    return (
        event.event_id == 1
        and parent.endswith("\\explorer.exe")
        and (image.endswith("\\powershell.exe") or image.endswith("\\cmd.exe"))
    )


def is_tuned_encoded_powershell(event: ProcessEvent) -> bool:
    if not is_explorer_child_candidate(event):
        return False
    return bool(LONG_PADDING.search(event.command_line) and ENCODED_SWITCH.search(event.command_line))


def public_event_summary(event: ProcessEvent) -> dict:
    """Return evidence fields without duplicating the encoded payload."""
    return {
        "event_id": event.event_id,
        "time_utc": event.time_utc,
        "computer": event.computer,
        "user": event.user,
        "image": event.image,
        "parent_image": event.parent_image,
        "process_guid": event.process_guid,
        "parent_process_guid": event.parent_process_guid,
        "command_line_length": len(event.command_line),
        "has_50_plus_space_padding": bool(LONG_PADDING.search(event.command_line)),
        "has_encoded_command_switch": bool(ENCODED_SWITCH.search(event.command_line)),
    }


def build_summary(path: Path) -> dict:
    digest = sha256_file(path)
    events = load_events(path)
    broad = [event for event in events if is_explorer_child_candidate(event)]
    tuned = [event for event in broad if is_tuned_encoded_powershell(event)]
    excluded = [event for event in broad if not is_tuned_encoded_powershell(event)]
    return {
        "source_file": path.name,
        "sha256": digest,
        "expected_sha256": EXPECTED_SHA256,
        "integrity_verified": digest == EXPECTED_SHA256,
        "total_events": len(events),
        "broad_explorer_child_candidates": len(broad),
        "tuned_encoded_powershell_escalations": len(tuned),
        "lower_confidence_candidates_excluded": len(excluded),
        "computers": sorted({event.computer for event in events}),
        "event_ids": sorted({event.event_id for event in events}),
        "tuned_events": [public_event_summary(event) for event in tuned],
        "excluded_events": [public_event_summary(event) for event in excluded],
    }


def write_markdown(summary: dict, path: Path) -> None:
    lines = [
        "# Public Telemetry Validation Results",
        "",
        f"- File integrity verified: **{summary['integrity_verified']}**",
        f"- Total Sysmon events: **{summary['total_events']}**",
        f"- Broad Explorer child-process candidates: **{summary['broad_explorer_child_candidates']}**",
        f"- Tuned encoded-PowerShell escalations: **{summary['tuned_encoded_powershell_escalations']}**",
        f"- Lower-confidence candidates excluded: **{summary['lower_confidence_candidates_excluded']}**",
        f"- Host(s): **{', '.join(summary['computers'])}**",
        "",
        "The tuned rule requires both a run of at least 50 whitespace characters and an encoded-command switch. "
        "That additional context reduces the broad four-event candidate set to two high-confidence escalations.",
        "",
        "These results were reproduced with the repository's Python validator. SPL searches are supplied for "
        "Splunk ingestion, but Splunk screenshots remain a separate manual validation step.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()
    summary = build_summary(args.log)
    if not summary["integrity_verified"]:
        raise SystemExit("Telemetry SHA-256 does not match the pinned upstream object")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(summary, args.markdown_out)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
