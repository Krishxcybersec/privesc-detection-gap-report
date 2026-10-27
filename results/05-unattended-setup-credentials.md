# Technique 5 — Unattended-Setup Credentials

| | |
|---|---|
| **MITRE ATT&CK** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) — Unsecured Credentials: Credentials In Files |
| **Tactic** | Credential Access (leading to Privilege Escalation) |
| **Starting point** | A standard user who can read a leftover setup file |
| **Result if undetected** | An administrator password read straight from a file |

## What the weakness is

Windows can be installed **automatically** using an "answer file" that fills in all the
setup choices, including the **administrator password**, so no one has to type them. These
files have standard names and live in predictable places:

- `C:\Windows\Panther\Unattend.xml`
- `C:\Windows\Panther\Autounattend.xml`
- `C:\Windows\System32\Sysprep\Unattend.xml`

They are meant to be deleted after setup, but they are often **left behind**. The password
inside is in plain text or lightly encoded (base64), and the files are frequently
**readable by ordinary users**. So a standard user can simply open the file and read the
admin password.

**From your attacker side:** you looked in the known locations, found an `Unattend.xml`,
and read the admin password out of it (decoding the base64 if needed). The weakness is a
**setup file with a password left on disk** where it can be read — no exploit, just a file
that should have been removed.

## How it looks to a defender

### Signal A — the leftover file (the cause)

An `Unattend.xml` / `Autounattend.xml` / `sysprep.inf` present after setup, especially one
readable by standard users. Found by **checking the known locations** — a configuration
audit, not a live event.

### Signal B — the file being read (the abuse)

A non-administrator **reading** one of these files.

- **Security 4663** (an attempt to access an object) on the unattended file. This is the
  signal my 1.0 detector watches. It requires **file auditing (a SACL)** to be enabled on
  those paths, or the event is never generated — an important caveat covered in `../lab-setup.md`.
- **Security 4688 / Sysmon 1** — a process reading the file by command line, e.g.
  `type`, `more`, `findstr`, or `Get-Content` with `unattend.xml` in the arguments.

## Detection logic (plain English)

> **Alert — high:** an unattended-setup file containing credentials exists in a readable location.
>
> **Alert — critical:** a standard user is reading `Unattend.xml` / `Autounattend.xml`.

The file-read alert depends on auditing being switched on for those files. If it is not,
the quieter but still useful signal is a **command that reads the file by name** (Signal B,
second bullet), which process auditing catches without a SACL.

## Sigma rules

- [`../sigma-rules/05a_unattend_file_read_cmd.yml`](../sigma-rules/05a_unattend_file_read_cmd.yml) — a command reading an unattended file (Signal B, process-based)
- [`../sigma-rules/05b_unattend_file_access.yml`](../sigma-rules/05b_unattend_file_access.yml) — a file-access event on an unattended file (Signal B, audit-based)

## What each defence should show (fill from the lab)

| Defence | Detected? | What it showed | Screenshot |
|---|---|---|---|
| Microsoft Defender | _tbd_ | | |
| Sysmon + community config | _tbd_ | | |
| My own detector (1.0) | _tbd_ | | |

## Analyst playbook (if this alert fires)

1. **Confirm the read.** Which account read which unattended file?
2. **Check the contents.** Does the file actually contain a credential? If so, treat that
   account's password as exposed.
3. **Judge the risk.** A standard user reading an admin password from a file is a direct
   path to privilege escalation.
4. **Contain.** Delete the leftover file and reset any password it contained.
5. **Prevent.** Remove answer files as part of the build process; never leave credentials on disk.

## Hardening

- Delete `Unattend.xml` / `Autounattend.xml` / `sysprep.inf` after imaging.
- Never store real passwords in answer files; use a post-install secret instead.
- Enable auditing on the known locations and monitor for reads by non-admin accounts.
