# Case Study - HarborCare Suspicious Access Review

## The starting point

I treated this like a small SOC ticket: a few authentication alerts came in, but the first job was not to panic. The first job was to answer a few basic questions:

1. Is this activity isolated or connected?
2. Is there a successful login after the failures?
3. Did the successful login lead to sensitive access?
4. Is there endpoint evidence that makes the case stronger?
5. What should be done now, and what can wait?

## Data sources

| Source | Why it matters |
|---|---|
| `auth_events.csv` | Shows login failures, successful logins, MFA results, source IPs, and device context. |
| `web_access_events.csv` | Shows application routes, export activity, user agents, response size, and source IPs. |
| `endpoint_events.csv` | Shows process execution on the app server. |
| `asset_inventory.csv` | Adds business context. An app server is not the same as a random test machine. |
| `vulnerability_findings.csv` | Shows what weaknesses may have made the incident easier or more impactful. |

## My investigation path

I started with authentication because that is where the first suspicious pattern appeared. One source IP had failed attempts across several users. That alone was worth a medium alert, but it was not enough to declare an incident.

The case became more serious when the same user showed repeated denied MFA prompts followed by an approved VPN login from an unknown device. After that, I checked web logs and saw scripted access to admin export paths. Then endpoint logs showed encoded PowerShell launched by a web worker process on the app server.

At that point, I would treat this as a likely compromise rather than a normal login issue.

## Decision

Declare a security incident, preserve evidence, revoke affected sessions, isolate or restrict the application server, and review whether exported data contained sensitive information.
