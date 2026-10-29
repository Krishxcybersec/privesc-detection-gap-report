# Windows Privilege-Escalation: Detection Gap Report

> A defensive security research project. Five privilege-escalation techniques tested
> against three defences in an isolated lab — see the coverage matrix below.

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
| My own detectors (**1.0** — separate repo) | Purpose-built detection for these techniques |

*(Wazuh SIEM may be added in a later version.)*

> **On authorship:** I performed and documented the five privilege-escalation lab
> exercises, analysed the resulting Windows security events, and compared how different
> defences responded. The Python detection scripts (1.0) were generated with AI assistance
> and used in the research. My own contribution is the hands-on testing, the interpretation
> of the observed results, the evaluation of detection limitations, and the security
> reporting — not independent development of the Python.

## Techniques tested

| # | Technique | MITRE ATT&CK |
|---|-----------|--------------|
| 1 | AlwaysInstallElevated policy | T1548.002 |
| 2 | Unquoted service path | T1574.009 |
| 3 | Backup-operator privilege abuse | T1003.002 |
| 4 | Saved-credential reuse (cmdkey / runas) | T1078 / T1555.004 |
| 5 | Credentials in an unattended-setup file | T1552.001 |

## Coverage matrix

Legend: ✅ detected · ⚠️ telemetry recorded, no alert · ❌ not detected in this test. Full
per-technique evidence in [`results/`](results/).

Note on Sysmon: it is a **logging** tool, not an alerting engine, so ⚠️ is its expected best
result on its own. It records the activity, and turning that into an alert needs rules (such
as Sigma) running in a SIEM. A ⚠️ for Sysmon is therefore a measure of *visibility*, not a
failure.

| Technique | Defender | Sysmon + config | My detectors (1.0) |
|-----------|----------|-----------------|--------------------|
| 1 — AlwaysInstallElevated | ❌ | ❌ | ✅ |
| 2 — Unquoted service path | ❌ | ⚠️ | ✅ |
| 3 — Backup / SAM dump | ✅ | ⚠️ | ❌ |
| 4 — Saved-credential reuse | ❌ | ⚠️ | ✅ |
| 5 — Unattended-setup creds | ❌ | ⚠️ | ✅ |

## Scope — what this study does and does not show

To be precise about the evidence (each technique's page breaks this down):

- **This is a detection and misconfiguration study, not a chain of completed exploits.**
- For every technique I confirmed the **vulnerable configuration** and/or the **suspicious
  activity**, and **validated what each defence detected**.
- I did **not** demonstrate full end-to-end privilege escalation to SYSTEM for every
  technique. In several cases the "attacker" action was performed from an administrative
  shell to generate the telemetry, or the exploit step was blocked (e.g. Defender stopped
  the Metasploit payload in technique 1). Those are noted honestly on each page.
- The value here is the **detection coverage comparison** — which defences notice which
  weaknesses — not a claim of owning the box five times over.

## Conclusion

The three defences have clearly different blind spots:

- **Microsoft Defender** only flagged one technique — the SAM dump (3) — because it matches
  known malicious *behaviour*. In these tests it **flagged none of the misconfigurations**
  (1, 2, 4, 5), which are legitimate-looking actions. A company on Defender alone would not
  have been told these weaknesses exist.
- **Sysmon (community config)** recorded telemetry for four of the five (⚠️). That is what it
  is designed to do: it logs, it doesn't alert, so turning the data into a detection needs
  rules in a SIEM. For technique 1, no matching registry event was found in the sample of
  events checked (see that page for the limits of that check).
- **The purpose-built detectors** caught four of five — every misconfiguration the standard
  tools missed. Their one miss (3) was the **polling design**: a millisecond-long command
  slipped between 3-second polls. Sysmon, being event-driven, caught that same command — the
  clearest evidence for the main 2.0 improvement: **move the detectors from polling to
  event-driven.**

**The gap:** in these tests, misconfigurations that enable privilege escalation went
unnoticed by the defences a typical organisation relies on. The Sigma rules in
[`sigma-rules/`](sigma-rules/) are **proposals** to close that gap by turning the available
telemetry into alerts. They are experimental and have not yet been validated against sample
events or run in a SIEM (see [`sigma-rules/README.md`](sigma-rules/README.md)).

## Repository layout

- [`results/`](results/) — per-technique detection write-ups and the coverage matrix
- [`soc-investigation/`](soc-investigation/) — a worked end-to-end SOC alert investigation (triage → timeline → verdict → incident ticket)
- [`sigma-rules/`](sigma-rules/) — the detection rules, in Sigma format, with MITRE tags
- [`TESTING-PLAN.md`](TESTING-PLAN.md) — how each technique is tested and recorded
- [`EVENT-IDS.md`](EVENT-IDS.md) — cheat sheet of the Windows event IDs these detections use
- [`lab-setup.md`](lab-setup.md) — how the isolated test VM was built
- [`screenshots/`](screenshots/) — evidence captured from the lab

## Status

**Complete.** All five techniques were tested in the lab; the coverage matrix, the
per-technique evidence, the Sigma rules, and the conclusion are all in place.
[`LAB-PROGRESS.md`](LAB-PROGRESS.md) has the full build log.

Possible next steps (noted in the conclusion): move the detectors from polling to
event-driven, and add a Wazuh SIEM as a fourth defence.
