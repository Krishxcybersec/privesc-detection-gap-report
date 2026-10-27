# Windows Privilege-Escalation: Detection Gap Report

> A defensive security research project. *Work in progress.*

## The question

If an attacker who already has a normal user account tries five well-known Windows
privilege-escalation techniques, **which common defences actually notice?**

Rather than build another detection tool, this project **measures** how three defences
respond to each technique in an isolated lab, publishes the results as a coverage
matrix, and then **writes detection rules to close whatever the defaults miss.**

All testing is done on a private, isolated virtual machine built by hand. The techniques
are documented by Microsoft and [MITRE ATT&CK](https://attack.mitre.org/); nothing here
is a tool or instructions for attacking systems that are not mine.

## Defences compared

| Defence | Represents |
|---|---|
| Microsoft Defender (built in) | A typical out-of-the-box Windows machine |
| Sysmon + community config | A team that has added extra logging |
| My own detectors (MSc dissertation, **1.0** — separate repo) | Purpose-built detection for these techniques |

*(Wazuh SIEM may be added in a later version.)*

## Techniques tested

| # | Technique | MITRE ATT&CK |
|---|-----------|--------------|
| 1 | AlwaysInstallElevated policy | T1548.002 |
| 2 | Unquoted service path | T1574.009 |
| 3 | Backup-operator privilege abuse | T1003.002 |
| 4 | Saved-credential reuse (cmdkey / runas) | T1078 / T1555.004 |
| 5 | Credentials in an unattended-setup file | T1552.001 |

## Coverage matrix

*To be filled in as testing progresses.*

| Technique | Defender | Sysmon + config | My detectors |
|-----------|----------|-----------------|--------------|
| 1 | — | — | — |
| 2 | — | — | — |
| 3 | — | — | — |
| 4 | — | — | — |
| 5 | — | — | — |

## Repository layout

- [`results/`](results/) — per-technique detection write-ups and the coverage matrix
- [`sigma-rules/`](sigma-rules/) — the detection rules, in Sigma format, with MITRE tags
- [`TESTING-PLAN.md`](TESTING-PLAN.md) — how each technique is tested and recorded
- `screenshots/` — evidence captured from the lab (added during testing)
- `lab-setup.md` — how the isolated test VM was built (added during testing)

## Status

Detection write-ups and Sigma rules are complete; lab testing is in progress.
See [`LAB-PROGRESS.md`](LAB-PROGRESS.md) for the current step.
