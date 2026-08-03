# Public Telemetry Validation Results

- File integrity verified: **True**
- Total Sysmon events: **4**
- Broad Explorer child-process candidates: **4**
- Tuned encoded-PowerShell escalations: **2**
- Lower-confidence candidates excluded: **2**
- Host(s): **ar-win-3**

The tuned rule requires both a run of at least 50 whitespace characters and an encoded-command switch. That additional context reduces the broad four-event candidate set to two high-confidence escalations.

## Sanitized event timeline

This table is generated directly from the pinned Sysmon file. It omits the encoded payload while keeping the fields used to explain the triage decision.

| Time (UTC) | Child process | Command length | 50+ spaces | Encoded switch | Triage |
|---|---|---:|:---:|:---:|---|
| 2025-03-24T14:31:36.813396000Z | `cmd.exe` | 142 | no | no | Keep as context |
| 2025-03-24T14:34:26.227690000Z | `powershell.exe` | 2687 | yes | yes | Escalate |
| 2025-03-24T14:49:00.306273800Z | `powershell.exe` | 60 | no | no | Keep as context |
| 2025-03-24T15:11:49.227455600Z | `powershell.exe` | 2687 | yes | yes | Escalate |

These results were reproduced with the repository's Python validator. SPL searches are supplied for Splunk ingestion, but Splunk screenshots remain a separate manual validation step.
