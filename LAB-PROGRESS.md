# Lab Progress — Detection Gap Report (2.0)

> **For any new session:** read this file first, then continue from the first unticked step.
> Tick steps off as they are finished, and add a line to the log at the bottom.

## Context (decided 2026-10-27)

- **Goal:** a defensive research project. Test how well common defences detect five
  well-known Windows privilege-escalation techniques, then publish a coverage matrix
  (which defence caught what, which missed, and why), and write detection rules to
  close the gaps.
- **Defences compared (first version):** Microsoft Defender (built in), Sysmon with a
  community config, and my own detectors from the 1.0 project.
- **Optional later:** Wazuh (free SIEM), using the Linux VM as the Wazuh server.
- **Lab is built by hand on a brand-new, isolated Windows 11 VM.** No third-party
  lab-setup script is used in 2.0. The 1.0 project keeps its original credit.
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
- [x] Decide VirtualBox vs VMware (match the Linux VM) → **VMware** (Kali was built in VMware)
- [x] Create the VM shell in VMware on D: → `D:\VMs\Win11-Lab\` (disk + .vmx pre-built: UEFI, Secure Boot, software vTPM, 6 GB RAM, 4 vCPU, 60 GB SATA disk, NAT network)
- [x] Download the Windows 11 ISO from Microsoft → `D:\ISOs\Win11_x64_en-us.iso` (8.43 GB, SHA-256 matches Microsoft's published "English 64-bit" hash)
- [x] Attach the ISO to the VM (set in the .vmx, connects at power on)
- [x] Open `D:\VMs\Win11-Lab\Win11-Lab.vmx` in VMware and start the Windows 11 Pro install
  - Note: the VM has **no TPM** (the auto-add vTPM setting didn't apply); installed with the `LabConfig\BypassTPMCheck` installer flag. None of the five techniques or the compared defences depend on a TPM.
  - Added `bios.bootDelay = "5000"` to the .vmx so there's time to catch "Press any key to boot from CD".
- [ ] Finish Windows setup with a local account
- [x] **Rebuilt the VM on C:** — D: is an external USB HDD (WD My Passport); the overnight install there took 2–9 s per disk operation and was only part-way after ~7 h, so it was powered off and abandoned. New VM: `C:\VMs\Win11-Lab\Win11-Lab.vmx` (display name **Win11-Lab-SSD**), ISO copied to `C:\ISOs\`. Same settings minus the auto-TPM line.
  - The abandoned copy is still at `D:\VMs\Win11-Lab` — safe to delete once the new VM works.
- [x] Install Windows 11 Pro on the new VM (tap Space at boot → Shift+F10 TPM bypass → Pro → Disk 0)
- [x] Local account `labadmin` created with `start ms-cxh:localonly` (OOBE updates skipped)
- [x] Set a password on `labadmin`
- [x] VMware Tools installed (2026-10-27 18:01, status current); Windows ISO disconnected
- [x] Windows Update complete, Defender definitions current
- [x] Snapshot **"clean"** taken (2026-10-27) — roll back here if the VM ever breaks
- [ ] Install VMware Tools (fixes screen size), then disconnect the ISO
- [ ] Set network to host-only / isolated
- [x] Windows Update (running), then take snapshot **"clean"** → done 2026-10-27, snapshot name `clean`

### Session 2 — build the test conditions (by hand)
- [ ] Apply condition 1 and note the exact steps
- [ ] Apply condition 2 and note the exact steps
- [ ] Apply condition 3 and note the exact steps
- [ ] Apply condition 4 and note the exact steps
- [ ] Apply condition 5 and note the exact steps
- [ ] Write `lab-setup.md` in my own words
- [ ] Take snapshot **"lab-ready"**

### Session 3 — logging tools
- [x] Confirm Microsoft Defender is on (real-time protection True, signatures 27/10/2026)
- [x] Install Sysmon with a community config (Sysmon v15.22, SwiftOnSecurity `sysmonconfig-export.xml`, in `C:\Tools` in the VM)
- [x] Turn on process-creation command-line auditing, plus Logon, Special Logon, Sensitive Privilege Use, File System, User Account Management, Security Group Management (auditpol)
- [x] Create the standard test user `labuser` (not in Administrators)
- [x] Logging verified: 4688 records full command lines; Sysmon writing events
- [x] Rename the VM to `WIN-LAB` (was `DESKTOP-9RAM3EQ`) so screenshots match the docs — confirm with `hostname` at the start of testing
- [x] Take snapshot **"lab-ready"** (2026-10-27, VM running; snapshots now: clean, updated, lab-ready). Roll back to this before every technique.

### Per-technique sessions (x5) — one at a time
- [ ] Technique 1: run in lab, record what each defence showed, screenshot, fill matrix row
- [ ] Technique 2: same
- [ ] Technique 3: same
- [ ] Technique 4: same
- [ ] Technique 5: same

### Detection write-ups (done ahead of lab testing)
- [x] All 5 technique detection packs written: `results/01..05`, each with 2 Sigma rules in `sigma-rules/`, MITRE tags, analyst playbooks. Committed.

### Write-up
- [ ] Fill the coverage matrix in the README
- [ ] Write a detection rule for each gap found
- [ ] Write the per-technique analysis and analyst notes
- [ ] Final README, screenshots, link from the main portfolio
- [ ] Publish (private first, review, then public)

## Log

- 2026-10-27 — project folder created; plan and structure set up. Nothing built in the VM yet.
- 2026-10-27 — chose VMware for the Windows 11 VM (same as the Kali VM).
- 2026-10-27 — pre-built the VM shell at D:\VMs\Win11-Lab (60 GB disk + Win11 .vmx). ISO still to download, then install.
- 2026-10-27 — ISO downloaded and hash-verified; attached to the VM. Next: open the VM in VMware and install Windows 11.
- 2026-10-27 — overnight install on the USB HDD was far too slow; rebuilt the VM on C: (internal NVMe SSD). Next: fresh install on the new VM.
- 2026-10-27 — lab base finished: Windows 11 Pro + VMware Tools + updates + password, snapshot "clean" taken. Next: build the 5 test conditions by hand (session 2), while the detection write-ups get drafted in parallel.
- 2026-10-27 — all 5 detection packs written and committed (write-ups + 10 Sigma rules + matrix). Written half of the project is done. Next: lab testing to fill the matrix and capture screenshots.
- 2026-10-27 — logging on (auditpol + Sysmon 15.22 + Defender), standard user `labuser` created, VM renamed, snapshot `lab-ready` taken. Lab is ready. Next: technique 1 test, with the user driving (predict → find evidence → decide → write finding → explain back).
