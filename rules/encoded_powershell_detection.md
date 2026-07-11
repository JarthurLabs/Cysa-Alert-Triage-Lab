# Detection Logic - Padded Encoded PowerShell

## Broad analytic

Identify Sysmon process-creation events where Windows Explorer launches PowerShell
or `cmd.exe`. This is useful investigative context but can include normal activity.

## Tuned analytic

Escalate only when the Explorer child is PowerShell and the command line contains:

- a run of at least 50 whitespace characters; and
- an encoded-command switch (`-e`, `-en`, `-enc`, or `-encodedcommand`) followed by Base64-like text.

## Why both conditions matter

Long padding can conceal the meaningful portion of a command line in process views.
An encoded-command switch adds execution-specific context. Requiring both conditions
reduces this dataset from four broad candidates to two high-confidence escalations.

## Expected false positives and review steps

- Authorized automation or administrative scripts using encoded commands.
- Software installers or endpoint-management tools launching PowerShell.
- Truncated or malformed command lines.

Review the signer, parent process, user, device role, surrounding network events,
and change records before final disposition.

## References

- Splunk Security Content: Windows Explorer spawning PowerShell or Cmd
- Splunk Security Content: Windows Explorer LNK exploit process launch with padding
- MITRE ATT&CK T1059.001 and T1204.002
