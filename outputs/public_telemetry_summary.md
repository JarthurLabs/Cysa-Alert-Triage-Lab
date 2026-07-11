# Public Telemetry Validation Results

- File integrity verified: **True**
- Total Sysmon events: **4**
- Broad Explorer child-process candidates: **4**
- Tuned encoded-PowerShell escalations: **2**
- Lower-confidence candidates excluded: **2**
- Host(s): **ar-win-3**

The tuned rule requires both a run of at least 50 whitespace characters and an encoded-command switch. That additional context reduces the broad four-event candidate set to two high-confidence escalations.

These results were reproduced with the repository's Python validator. SPL searches are supplied for Splunk ingestion, but Splunk screenshots remain a separate manual validation step.
