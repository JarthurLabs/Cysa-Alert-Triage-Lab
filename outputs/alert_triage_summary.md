# Alert Triage Summary

Total alerts: **5**
Highest severity: **Critical**
Recommended status: **Declare security incident**

| Severity | Alert | Entity | Evidence |
|---|---|---|---|
| Medium | Possible password spray against VPN | 203.0.113.77 | 10 failures across 10 users: casey.nguyen, devon.lee, helpdesk.bot, jamal.arthur, li.chen, maria.santos |
| High | MFA fatigue pattern followed by approval | maria.santos | 3 denied MFA prompts before approved VPN login from 203.0.113.77 |
| High | Sensitive export from scripted user agent | maria.santos from 203.0.113.77 | GET /admin/users/export.csv returned 200 with 188420 bytes via curl/8.1 |
| High | Sensitive export from scripted user agent | maria.santos from 203.0.113.77 | GET /download/reports/nightly.zip returned 200 with 942012 bytes via python-requests/2.31 |
| Critical | Encoded PowerShell launched by web worker process | HC-SRV-APP01 | w3wp.exe -> powershell.exe with network connection 203.0.113.77:443 |
