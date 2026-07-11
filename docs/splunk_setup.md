# Splunk Validation Runbook

This runbook imports the pinned Sysmon telemetry into a local Splunk lab and
validates the supplied SPL searches. It deliberately separates reproducible
Python validation from SIEM execution evidence.

## Prerequisites

- A user-controlled Splunk Enterprise trial or lab instance.
- Splunk Add-on for Microsoft Windows, so Sysmon XML fields such as `EventCode`,
  `Image`, `ParentImage`, and `CommandLine` are extracted consistently.
- No customer or employer environment is required.

## Import

1. Create an index named `attack_lab`.
2. Open **Settings > Add Data > Upload**.
3. Upload `data/public/splunk_attack_data/explorer_spawns_windows-sysmon.log`.
4. Set the source type to `XmlWinEventLog`.
5. Select the `attack_lab` index and complete the upload.
6. Run `splunk/queries/01_inventory.spl` and confirm four Event ID 1 records.

## Detection sequence

1. Run `02_explorer_child_processes.spl`. Expected result: four Explorer child-process candidates.
2. Run `03_padded_encoded_powershell.spl`. Expected result: two high-confidence encoded-PowerShell events.
3. Run `04_timeline.spl` to compare the two escalations with the two lower-confidence candidates.

## Evidence to capture

- Import settings showing index and source type.
- Inventory result showing four events.
- Broad search showing four candidates.
- Tuned search showing two escalations.
- One event detail with the command line visibly redacted if shared publicly.

Store screenshots under `docs/images/splunk/`. Do not publish local usernames,
license details, host IPs, tokens, or unrelated events.

## Current validation boundary

The repository's Python validator and tests reproduce the 4-to-2 tuning result.
The SPL files are provided for a real Splunk lab, but screenshots should not be
claimed until the searches have actually been run in Splunk.
