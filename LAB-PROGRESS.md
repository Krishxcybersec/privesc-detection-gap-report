# Lab Progress — Detection Gap Report (2.0)

> **For any new session:** read this file first, then continue from the first unticked step.
> Tick steps off as they are finished, and add a line to the log at the bottom.

## Context (decided 2026-10-27)

- **Goal:** a defensive research project. Test how well common defences detect five
  well-known Windows privilege-escalation techniques, then publish a coverage matrix
  (which defence caught what, which missed, and why), and write detection rules to
  close the gaps.
- **Defences compared (first version):** Microsoft Defender (built in), Sysmon with a
  community config, and my own detectors from the MSc dissertation (1.0).
- **Optional later:** Wazuh (free SIEM), using the Linux VM as the Wazuh server.
- **Lab is built by hand on a brand-new, isolated Windows 11 VM.** No third-party
  lab-setup script is used in 2.0. The 1.0 dissertation keeps its original credit.
- **Host:** 16 GB RAM, Intel Core Ultra 7 155H, VMs on D: (679 GB free).
  VirtualBox and VMware are both installed.
- **Keep the Linux VM powered off** during Windows sessions to save RAM.
- **Work style:** short sessions, one milestone each; snapshot the VM after every milestone.

## The five techniques (all documented by Microsoft and MITRE ATT&CK)

| # | Technique | ATT&CK |
|---|-----------|--------|
| 1 | AlwaysInstallElevated policy | T1548.002 |
| 2 | Unquoted service path | T1574.009 |
| 3 | Backup-operator privilege abuse | T1003 / T1078 |
| 4 | Saved credentials reuse (cmdkey / runas) | T1078 / T1555 |
| 5 | Credentials left in an unattended-setup file | T1552.001 |

## Steps

### Session 1 — Windows 11 VM
- [ ] Decide VirtualBox vs VMware (match the Linux VM)
- [ ] Create the VM (store on D:), install Windows 11
- [ ] Set network to host-only / isolated
- [ ] Windows Update, then take snapshot **"clean"**

### Session 2 — build the test conditions (by hand)
- [ ] Apply condition 1 and note the exact steps
- [ ] Apply condition 2 and note the exact steps
- [ ] Apply condition 3 and note the exact steps
- [ ] Apply condition 4 and note the exact steps
- [ ] Apply condition 5 and note the exact steps
- [ ] Write `lab-setup.md` in my own words
- [ ] Take snapshot **"lab-ready"**

### Session 3 — logging tools
- [ ] Confirm Microsoft Defender is on
- [ ] Install Sysmon with a community config
- [ ] Turn on process-creation command-line auditing
- [ ] Take snapshot **"logging-ready"**

### Per-technique sessions (x5) — one at a time
- [ ] Technique 1: run in lab, record what each defence showed, screenshot, fill matrix row
- [ ] Technique 2: same
- [ ] Technique 3: same
- [ ] Technique 4: same
- [ ] Technique 5: same

### Write-up
- [ ] Fill the coverage matrix in the README
- [ ] Write a detection rule for each gap found
- [ ] Write the per-technique analysis and analyst notes
- [ ] Final README, screenshots, link from the main portfolio
- [ ] Publish (private first, review, then public)

## Log

- 2026-10-27 — project folder created; plan and structure set up. Nothing built in the VM yet.
