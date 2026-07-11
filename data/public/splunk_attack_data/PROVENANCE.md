# Telemetry Provenance

This directory contains one public Sysmon telemetry file from the official
[Splunk Attack Data](https://github.com/splunk/attack_data) project.

- Upstream repository: `splunk/attack_data`
- Pinned commit: `64cb82f9a703a9e5e91aa39c9b0998d838dc632d`
- Upstream path: `datasets/attack_techniques/T1059.001/encoded_powershell/explorer_spawns_windows-sysmon.log`
- Upstream metadata: `encoded_powershell.yml`
- Dataset author listed upstream: Patrick Bareiss
- Collection environment: Splunk Attack Range
- Source: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Sourcetype: `XmlWinEventLog`
- Local SHA-256: `9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22`
- License: Apache License 2.0; a copy is stored under `licenses/`

Pinned source:
https://github.com/splunk/attack_data/blob/64cb82f9a703a9e5e91aa39c9b0998d838dc632d/datasets/attack_techniques/T1059.001/encoded_powershell/explorer_spawns_windows-sysmon.log

## Accuracy language

This is captured telemetry from a controlled attack simulation. It is not
production customer data and is not evidence that the repository owner worked
in a production SOC. The file is kept unchanged and its hash is checked in CI.
