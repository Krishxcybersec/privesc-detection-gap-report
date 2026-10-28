# Windows Event ID Cheat Sheet

The core Windows event IDs a defender recognises on sight. Grouped by the question each
one answers. These are the ones that come up in this project and in SOC work generally —
not a full list (Windows has hundreds), just the essential dozen.

## "Who logged in?"

| ID | Meaning | Why it matters |
|---|---|---|
| 4624 | Successful logon | Who got in, and how (see logon types below) |
| 4625 | Failed logon | Many in a row = password guessing / brute force |
| 4648 | Logon using explicit credentials | Someone ran something **as another user** (technique 4) |
| 4672 | Special privileges assigned at logon | An admin-level account just signed on |

## "What ran?"

| ID | Source | Meaning | Why it matters |
|---|---|---|---|
| 4688 | Security | A process was created | The most-used detection event; needs command-line auditing on |
| 1 | Sysmon | Process created (richer) | Adds parent, hashes, integrity level |

## "What changed?"

| ID | Source | Meaning | Why it matters |
|---|---|---|---|
| 4720 | Security | User account created | Backdoor accounts |
| 4732 | Security | Member added to a local group | Added to **Administrators** = red flag |
| 7045 | System | New service installed | Persistence / SYSTEM execution |
| 7036 | System | Service changed state (running/stopped) | Correlates a service start with a hijack (technique 2) |
| 4698 | Security | Scheduled task created | Persistence |
| 4663 | Security | Attempt to access an object (file/registry) | Needs auditing (a SACL) on the target (technique 5) |
| 4673 / 4674 | Security | Privileged service / object operation | Fires when a privilege like SeBackup is used (technique 3) |
| 13 | Sysmon | Registry value set | Catches a policy being enabled (technique 1) |
| 11 | Sysmon | File created | Catches a hijack binary appearing (technique 2) |

## "Is someone hiding?"

| ID | Source | Meaning | Why it matters |
|---|---|---|---|
| 1102 | Security | Security log was cleared | Attackers wipe logs to cover tracks — always suspicious |

## Logon types (the `LogonType` field on 4624)

| Type | Means |
|---|---|
| 2 | Interactive — someone at the keyboard |
| 3 | Network — accessing a share, etc. |
| 10 | RemoteInteractive — Remote Desktop |

## Which technique uses which

| Technique | Key events |
|---|---|
| 1 — AlwaysInstallElevated | Sysmon 13 (registry), 4688 (msiexec child as SYSTEM) |
| 2 — Unquoted service path | Sysmon 11 (file), 4688 + 7036 (service child), 4720/4732 |
| 3 — Backup-privilege / SAM | 4688 (`reg save`), 4673/4674 |
| 4 — Saved-credential reuse | 4688 (`cmdkey`/`runas`), 4648, 4624, 4672 |
| 5 — Unattended-setup creds | 4663 (file access), 4688 (read by command) |

> Where to look in Event Viewer:
> - **Security log:** Windows Logs → Security
> - **System log:** Windows Logs → System
> - **Sysmon:** Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
