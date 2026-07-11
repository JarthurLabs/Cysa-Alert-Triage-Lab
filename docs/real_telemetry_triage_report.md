# Real-Telemetry Triage Report

## Question

Can a broad Explorer child-process detection be tuned to distinguish high-confidence
encoded PowerShell from lower-confidence PowerShell or command-shell activity?

## Evidence

The official Splunk Attack Data file contains four Sysmon Event ID 1 records
captured from host `ar-win-3` in Splunk Attack Range. All four records show
`explorer.exe` spawning either PowerShell or `cmd.exe`.

## Broad result

The broad detection returns four candidates. This is useful for investigation,
but it is not specific enough to classify every match as encoded-PowerShell abuse.
One event is a plain PowerShell launch and another is a startup command-shell action.

## Tuned result

The tuned logic adds two independent signals:

1. At least 50 consecutive whitespace characters in the command line.
2. An encoded-command switch followed by Base64-like content.

Two events meet both conditions. Two do not, reducing the candidate set from four
to two without pretending that every Explorer child process is malicious.

## Disposition

- Escalate the two padded encoded-PowerShell events for containment and scoping.
- Retain the two excluded events as lower-confidence context, not confirmed benign activity.
- Correlate with network, user, and endpoint telemetry before declaring a full incident.

## MITRE ATT&CK

- T1059.001 - PowerShell
- T1204.002 - Malicious File, where applicable to the linked detection scenario

## Limitations

- The data comes from a controlled attack simulation, not a production customer environment.
- The file is intentionally small and supports detection-tuning demonstration, not prevalence estimates.
- The local validator confirms the event counts and logic; Splunk screenshots remain pending manual lab execution.
