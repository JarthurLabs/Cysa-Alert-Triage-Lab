# Incident Report - HarborCare Portal Suspicious Access

> Synthetic portfolio case. No real customer, patient, or company data is used.

## Executive summary

The lab data shows a likely account compromise beginning with password spraying, followed by repeated MFA prompts, a successful VPN login from an unknown device, scripted access to admin/export routes, and suspicious process activity on the application server.

- Total correlated alerts: **5**
- Highest severity: **Critical**
- Recommended status: **Declare security incident**

## Evidence table

| Time | Severity | Alert | Entity | Evidence | MITRE mapping |
|---|---|---|---|---|---|
| 2026-06-14T09:55:00Z | Medium | Possible password spray against VPN | 203.0.113.77 | 10 failures across 10 users: casey.nguyen, devon.lee, helpdesk.bot, jamal.arthur, li.chen, maria.santos | T1110.003 Password Spraying |
| 2026-06-14T10:41:00Z | High | MFA fatigue pattern followed by approval | maria.santos | 3 denied MFA prompts before approved VPN login from 203.0.113.77 | T1621 Multi-Factor Authentication Request Generation |
| 2026-06-14T10:46:00Z | High | Sensitive export from scripted user agent | maria.santos from 203.0.113.77 | GET /admin/users/export.csv returned 200 with 188420 bytes via curl/8.1 | T1530 Data from Cloud Storage / T1005 Data from Local System |
| 2026-06-14T10:49:00Z | High | Sensitive export from scripted user agent | maria.santos from 203.0.113.77 | GET /download/reports/nightly.zip returned 200 with 942012 bytes via python-requests/2.31 | T1530 Data from Cloud Storage / T1005 Data from Local System |
| 2026-06-14T10:50:00Z | Critical | Encoded PowerShell launched by web worker process | HC-SRV-APP01 | w3wp.exe -> powershell.exe with network connection 203.0.113.77:443 | T1059.001 PowerShell |

## Containment and recovery plan

1. Disable active sessions for the affected account and require password reset.
2. Temporarily isolate the application server from non-essential outbound traffic while evidence is preserved.
3. Review admin export logs and confirm whether any regulated data left the environment.
4. Patch the outdated upload component and enforce stricter MFA controls.
5. Add detections for scripted admin exports, web-worker process spawning, and repeated MFA deny/approve patterns.

## Vulnerability work tied to this incident

| Priority | Score | Finding | Recommended action |
|---|---:|---|---|
| P1 - Fix now | 100 | Outdated file upload component on client portal | Patch component and restrict upload handler to authenticated admin workflow |
| P1 - Fix now | 100 | VPN MFA push fatigue not rate-limited | Enable number matching, push limits, lockout, and user reporting |
| P2 - Fix this week | 82 | Database server missing June cumulative patch | Patch during next approved maintenance window |

## Lessons learned

- CVSS alone was not enough. The riskiest item was dangerous because it was exposed, tied to a high-value asset, and had exploitation indicators.
- MFA is not magic. Push fatigue can turn a strong control into a user-experience problem if prompts are unlimited and unclear.
- Detection logic needs tuning. My first password-spray rule was too noisy, so I moved to unique-account behavior over a time window.
- The report has to be understandable by technical and non-technical readers. A perfect query is not useful if nobody understands the risk or next action.

