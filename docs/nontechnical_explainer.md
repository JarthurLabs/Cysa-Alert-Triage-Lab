# Non-Technical Explainer - HarborCare SOC Alert Triage Lab

## The simple version

This project is a practice cybersecurity investigation. I created fake company data and used it to show how a security analyst reviews signs of a possible account compromise.

The fictional company is called HarborCare. The company has a customer portal, employee VPN access, multi-factor authentication, and servers that support the portal.

The project asks one main question:

> Did someone just make a few login mistakes, or does the evidence show a real security incident?

## What happened in the story

A suspicious IP address tried to log in to several employee accounts. That pattern can be a sign of password spraying, which means an attacker tries common passwords against many users instead of attacking only one person.

One employee then received several MFA prompts. The user denied some of them, but eventually one was approved from an unknown device. That matters because attackers sometimes annoy users with repeated MFA prompts until someone accidentally approves one.

After that login, the same suspicious source accessed admin export pages in the customer portal using scripted tools. That is suspicious because normal users usually browse the site with a browser, not with tools like `curl` or `python-requests`.

Finally, the app server showed suspicious command activity. That made the case serious enough to treat as a likely incident.

## What the project demonstrates

It shows that I can:

- Review different types of security logs.
- Connect related events instead of looking at each alert alone.
- Prioritize vulnerabilities based on business risk, not just scanner scores.
- Explain what happened in plain English.
- Recommend practical containment and recovery steps.
- Document mistakes and improve the detection logic.

## The main takeaway

This project demonstrates a structured, evidence-based approach to alert triage, detection tuning, vulnerability prioritization, and security communication while remaining clear about the limitations of synthetic data.