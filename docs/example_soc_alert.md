# Example SOC Alert - AUTH-002

This is the single alert I would use to explain the investigation path in an interview.

| Field | Detail |
|---|---|
| Alert | MFA fatigue pattern followed by approval |
| Severity | High |
| Source IP | 203.0.113.77 |
| Affected user | maria.santos |
| Evidence | 3 denied MFA prompts before an approved VPN login from the same source and an unknown device. |
| Reason fired | Repeated MFA prompts followed by approval can indicate MFA fatigue, especially when it follows password spraying. |
| Recommended action | Revoke sessions, confirm with the user, reset password, review exports, and add MFA push limits / number matching. |
| MITRE ATT&CK | T1621 - Multi-Factor Authentication Request Generation |

## Why this alert mattered

By itself, this alert would still need validation. The reason I escalated it was the chain of evidence: password spray activity came first, then MFA fatigue, then a successful login, then scripted admin export activity, then suspicious endpoint behavior on the application server.
