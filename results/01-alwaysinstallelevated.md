# Technique 1 — AlwaysInstallElevated

| | |
|---|---|
| **MITRE ATT&CK** | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) — Abuse Elevation Control Mechanism |
| **Tactic** | Privilege Escalation, Defense Evasion |
| **Starting point** | A standard (non-admin) user account |
| **Result if undetected** | Code running as `NT AUTHORITY\SYSTEM` |

## What the weakness is

`AlwaysInstallElevated` is a Windows Installer **policy**. When it is enabled, Windows
installs any `.msi` package with full SYSTEM privileges, no matter who starts the
install. It exists so that administrators can let standard users install approved
software, but it is dangerous because Windows does not check *which* package is being
installed — only that the policy is on.

It is controlled by one registry value in two places, and it is only exploitable when
**both** are set to `1`:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`

If both are `1`, a standard user can have any installer package run as SYSTEM. That is
the whole technique: a policy that should be off has been left on.

## How it looks to a defender

There are two separate moments a defender can catch, and good detection watches both.

### Signal A — the misconfiguration being set (the cause)

The two registry values changing to `1`. This is the *earliest* possible warning,
before anything is abused.

- **Sysmon Event ID 13** (RegistryValueSet) on either `AlwaysInstallElevated` path.
- Or a scheduled **configuration check** that reads both keys and reports when both are `1`.

### Signal B — the abuse itself (the effect)

A package being installed and spawning a child process that runs as SYSTEM from a
standard user's session.

- **Security Event ID 4688** (process creation) — `msiexec.exe` started in a user
  session, then a child process (`cmd.exe`, `powershell.exe`, etc.) whose **parent is
  `msiexec.exe`** running as `SYSTEM`.
- **Sysmon Event ID 1** (process create) — same parent/child relationship, with the
  integrity level jumping to System.
- Command-line auditing must be on to see the `msiexec` arguments (see `../lab-setup.md`).

## Detection logic (plain English)

> **Alert — critical:** both `AlwaysInstallElevated` values are `1` (the host is exploitable).
>
> **Alert — high:** a process whose parent is `msiexec.exe` is running as `SYSTEM`
> while the installing user is a standard account.

The registry check is the strongest detection because it is specific and has almost no
false positives: on a correctly configured machine these values are absent or `0`, and
they do not turn on by accident.

## Sigma rules

- [`../sigma-rules/01a_alwaysinstallelevated_registry.yml`](../sigma-rules/01a_alwaysinstallelevated_registry.yml) — the policy being enabled (Signal A)
- [`../sigma-rules/01b_alwaysinstallelevated_msiexec_child.yml`](../sigma-rules/01b_alwaysinstallelevated_msiexec_child.yml) — a SYSTEM child of msiexec (Signal B)

## Results from the lab (Signal A — policy enabled)

Tested 2026-10-28 on the `WIN-LAB` VM. Both registry values were set to `1`, confirmed
present (`0x1`). Then each defence was checked.

| Defence | Detected? | What it showed |
|---|---|---|
| Microsoft Defender | ❌ Miss | `Get-MpThreatDetection` count = 0; Defender does not inspect this policy value |
| Sysmon + community config | ❌ Miss | No Event 13 for the `AlwaysInstallElevated` key. Sysmon *is* logging registry (≥5 other Event 13s present), so the gap is in the config's key coverage, not in Sysmon being off |
| My own detector (1.0) | _tbd_ | polls this key directly — to be tested |

**Finding:** a privilege-escalation misconfiguration that gives any installer SYSTEM
rights can be enabled with **no alert from either standard defence**. Defender doesn't
look at this policy, and the SwiftOnSecurity Sysmon config doesn't watch this registry
key. The danger is that everything appears normal. Sigma rule `01a` closes this gap by
alerting specifically on this value being set to `1`.

> Screenshot: `screenshots/01-alwaysinstallelevated-signalA-miss.png` (to add)

## Analyst playbook (if this alert fires)

1. **Confirm the policy.** Read both registry values. If both are `1`, the host is
   exploitable right now.
2. **Find who set it.** Check the 4657/Sysmon 13 registry-change event for the account
   and process that wrote the value.
3. **Look for abuse.** Search for `msiexec.exe` spawning a shell or other process as
   SYSTEM around that time (4688 / Sysmon 1).
4. **Contain.** Set both values to `0` (or remove them). Investigate any SYSTEM process
   that came from `msiexec`.
5. **Prevent.** This policy should never be enabled via Group Policy across the estate.

## Hardening

- Keep `AlwaysInstallElevated` disabled in both `HKLM` and `HKCU` (the default).
- Deploy software through a managed system (Intune, SCCM) instead of this policy.
- Monitor the two registry values as a standing detection — this is a cheap, high-value alert.
