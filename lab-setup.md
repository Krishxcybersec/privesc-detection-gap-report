# Lab Setup

How the isolated test environment was built, so the results are reproducible. Everything
runs inside one virtual machine with no connection to any real network.

## The virtual machine

- **Windows 11 Pro** in VMware Workstation, named `WIN-LAB`.
- **Isolated**: used only for this testing; no production data, treated as disposable.
- **Accounts:**
  - `labadmin` — administrator (used to introduce the misconfigurations a real admin or
    GPO would set, and to read the logs).
  - `labuser` — standard, non-admin user (the attacker's starting point).
- **Snapshots:** `clean` (fresh install) and `lab-ready` (logging on, test user created),
  so each test can start from an identical state.

## Logging (the three defences, all live before testing)

1. **Microsoft Defender** — built in, real-time protection on, signatures up to date.
2. **Command-line process auditing** — so Event 4688 records full command lines:
   - `auditpol` enabled for Process Creation, Logon, Special Logon, Sensitive Privilege
     Use, File System, User Account Management, Security Group Management.
   - `ProcessCreationIncludeCmdLine_Enabled = 1`.
3. **Sysmon** — Sysmon v15.22 with the community
   [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config).

The user's five **1.0 detectors** (Python) were run from `C:\Detectors` with
`python` + `pywin32` + `psutil`.

## The misconfiguration / action per technique

Each technique is a documented Windows weakness (see its page in `results/` for the MITRE
mapping and references). Summary of what was set up in the lab:

| # | Technique | Set up in the lab as |
|---|-----------|----------------------|
| 1 | AlwaysInstallElevated | the `AlwaysInstallElevated` policy value set to `1` in both HKLM and HKCU |
| 2 | Unquoted service path | a service created with an unquoted `ImagePath` containing spaces, running as LocalSystem |
| 3 | Backup / SAM dump | the SAM and SYSTEM registry hives saved with the built-in `reg save` |
| 4 | Saved-credential reuse | `cmdkey` + `runas /savecred` used to run a command as another account |
| 5 | Unattended-setup creds | an `Unattend.xml` with a **fake** password placed in `C:\Windows\Panther`, with read-auditing (a SACL) enabled so Event 4663 fires |

> Setup/trigger steps follow the standard, publicly documented procedures (MITRE ATT&CK,
> Microsoft Learn, and common training material) and were performed only against this
> private lab VM. No real credentials were used; the only password in any file is a clearly
> labelled fake.

## Method

For each technique: start from `lab-ready`, confirm all three defences are running,
perform the technique, record whether each defence **alerted (✅)**, **only logged (⚠️)**,
or **missed (❌)**, and capture a screenshot into `screenshots/`. Results are in
[`results/`](results/).
