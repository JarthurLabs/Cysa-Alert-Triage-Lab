# Analyst Journal - Iterations, Mistakes, and Corrections

I wanted this project to show the work, not just the final answer. A real analyst rarely gets a clean story immediately. The first pass usually has assumptions that need to be tested.

## Iteration 1 - I over-alerted on failed logins

My first rule was:

> Alert when one source IP has 3 failed logins in 10 minutes.

That sounded reasonable at first, but it caught too much normal noise. People mistype passwords. Password managers fail. Someone may have recently changed a password and still be using the old one on another device.

### Correction

I changed the logic to:

> Alert when one source IP has failed logins across 5 or more unique users within 20 minutes.

That better matches password spraying because the pattern is not just failure volume. The important part is one source trying many accounts.

## Iteration 2 - I almost ranked vulnerabilities by CVSS only

At first, I sorted vulnerability findings by CVSS. That was easy, but it missed the bigger point.

A high CVSS issue on an internal, segmented server may be less urgent than a slightly lower-scored issue on an internet-facing production system with exploit activity.

### Correction

I added context:

- Known exploitation
- Exploit availability
- Internet exposure
- Asset criticality
- Existing compensating controls

That made the priority list more realistic.

## Iteration 3 - I made the report too technical

My first incident report was mostly alert names, MITRE mappings, and log evidence. That is useful for an analyst, but not enough for a manager or recruiter trying to understand the project quickly.

### Correction

I added an executive summary, a plain-English risk explanation, and a short containment plan. I kept the technical evidence, but I stopped leading with it.

## What I learned

- Detection logic needs tuning, not just writing.
- Vulnerability management is a business decision, not only a scanner output.
- Incident response documentation should explain what happened, why it matters, and what to do next.
- Good communication is part of the security work.

## Visual note on tuning

![Detection tuning notes](images/detection-tuning-notes.svg)

![Rule tuning comparison](images/rule-tuning-comparison.png)
