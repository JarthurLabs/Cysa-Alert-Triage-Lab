<div align="center">

# Sysmon Encoded PowerShell Triage Lab

**Captured attack-simulation telemetry + detection tuning + Splunk SPL + reproducible validation**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Telemetry](https://img.shields.io/badge/Telemetry-Splunk%20Attack%20Data-purple)
![Focus](https://img.shields.io/badge/Focus-SOC%20Triage-orange)
![Integrity](https://img.shields.io/badge/SHA--256-Verified-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-T1059.001-red)

</div>

## What changed in version 2

The primary case now uses captured Windows Sysmon telemetry from the official
[Splunk Attack Data](https://github.com/splunk/attack_data) project instead of
fabricated authentication, web, and endpoint CSVs. The telemetry was generated
in Splunk Attack Range during a controlled attack simulation.

The original HarborCare synthetic scenario remains in the repository as legacy
learning material, but it is not the evidence source for the current 4-to-2
detection-tuning result.

## Investigation result

The pinned dataset contains four Sysmon Event ID 1 process-creation records from
host `ar-win-3`:

- Four broad candidates: Explorer launches PowerShell or `cmd.exe`.
- Two high-confidence escalations: PowerShell command lines contain both 50+
  whitespace characters and an encoded-command switch with Base64-like content.
- Two lower-confidence candidates remain available for context instead of being
  mislabeled as malicious or discarded as benign.

This is the useful analyst lesson: a broad rule helps find activity, while a
tuned rule adds enough context to prioritize the events that deserve escalation.

## Evidence and reproducibility

| Evidence | Location |
|---|---|
| Unmodified public Sysmon log | `data/public/splunk_attack_data/explorer_spawns_windows-sysmon.log` |
| Provenance, pinned commit, and SHA-256 | `data/public/splunk_attack_data/PROVENANCE.md` |
| Python XML validator | `src/validate_public_telemetry.py` |
| Automated tests | `tests/test_public_telemetry.py` |
| Generated validation results | `outputs/public_telemetry_summary.json` and `.md` |
| Splunk searches | `splunk/queries/` |
| Splunk import and evidence runbook | `docs/splunk_setup.md` |
| Analyst triage report | `docs/real_telemetry_triage_report.md` |
| Detection rationale | `rules/encoded_powershell_detection.md` |

## Run the validator

```bash
python3 src/validate_public_telemetry.py \
  data/public/splunk_attack_data/explorer_spawns_windows-sysmon.log \
  --json-out outputs/public_telemetry_summary.json \
  --markdown-out outputs/public_telemetry_summary.md

python3 -m unittest discover -s tests -p "test_public_telemetry.py" -v
```

No external Python packages are required.

## Splunk workflow

The `splunk/queries/` directory contains four searches that inventory the data,
find broad Explorer child-process candidates, detect padded encoded PowerShell,
and build a confidence-labeled timeline. Follow `docs/splunk_setup.md` to load
the file into a user-controlled Splunk lab.

The Python result has been reproduced and is tested in CI. The SPL searches are
provided for real SIEM validation, but this repository does not claim that the
current environment executed Splunk or produced screenshots that do not yet exist.

## Skills demonstrated

- Sysmon XML parsing and process-tree analysis
- Detection engineering and false-positive reduction
- Splunk SPL design and onboarding documentation
- Evidence integrity with pinned provenance and SHA-256 validation
- MITRE ATT&CK mapping
- Incident triage and cautious disposition language
- Python testing and GitHub Actions quality control

## Data provenance and license

The public telemetry is copied unchanged from `splunk/attack_data` at commit
`64cb82f9a703a9e5e91aa39c9b0998d838dc632d`. It is licensed under Apache 2.0.
Attribution, the pinned source, and the verified hash are documented in
`data/public/splunk_attack_data/PROVENANCE.md`; the license text is retained in
`licenses/SPLUNK_ATTACK_DATA_APACHE-2.0.txt`.

## Limitations

- This is captured attack-simulation telemetry, not production customer data.
- The dataset is intentionally small and does not support prevalence conclusions.
- The repository demonstrates lab analysis and does not claim production SOC experience.
- The earlier synthetic HarborCare content remains for version history and should
  not be mixed with the current real-telemetry counts.
