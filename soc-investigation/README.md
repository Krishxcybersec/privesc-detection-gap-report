# SOC Investigation — Credential-Dumping Alert (SAM hive)

A worked, end-to-end investigation of a single alert, in the format a junior SOC analyst
would use: **alert → triage → evidence → timeline → scope → verdict → response → ticket.**

> Provenance: the telemetry comes from the controlled lab in this repository (see
> [`../lab-setup.md`](../lab-setup.md)). The actions were performed deliberately on the
> `WIN-LAB` test VM. This write-up treats that telemetry as if it were a real alert, to
> demonstrate the investigation workflow — it is not a real-world incident.

---

## 1. The alert

| | |
|---|---|
| **Source** | Microsoft Defender |
| **Alert** | Credential theft behaviour — `reg.exe` saving the SAM registry hive |
| **ThreatID** | 2147840094 |
| **Host** | WIN-LAB |
| **Time (first seen)** | 2026-10-28 22:52:15 |
| **Action taken by tool** | Blocked |

Defender resource string:
`CmdLine:_C:\Windows\System32\reg.exe save hklm\sam C:\temp\sam.hiv`

## 2. Triage — what is this?

The SAM hive holds local account **password hashes**; the SYSTEM hive holds the key needed
to decrypt them. Copying them is a classic **credential-dumping** step
(**MITRE ATT&CK [T1003.002](https://attack.mitre.org/techniques/T1003/002/)** — OS Credential
Dumping: SAM). Normal day-to-day activity does **not** save the SAM hive, so this is
high-priority and worth a full look rather than a quick dismissal.

## 3. Evidence gathered

| Source | Event | What it showed |
|---|---|---|
| Defender | ThreatID 2147840094 | Flagged and **blocked** `reg.exe save hklm\sam ...` at 22:52:15 |
| Sysmon | Event ID 1 (process create) | `reg.exe save hklm\sam ...` at 22:52:16, and `reg.exe save hklm\system ...` at 22:52:19 |
| Account | — | `WIN-LAB\labadmin` (local administrator) |

Key query used (Sysmon):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
  Where-Object { $_.Message -match 'reg.exe' -and $_.Message -match 'save' }
```

## 4. Timeline

```
22:52:15  Defender detects and BLOCKS   reg.exe save hklm\sam  (SAM hive — credentials)
22:52:16  Sysmon logs process create    reg.exe save hklm\sam  (the blocked attempt)
22:52:19  Sysmon logs process create    reg.exe save hklm\system  (SYSTEM hive — SUCCEEDED)
```

## 5. Scope and impact

- The **SAM** save (the credential hashes) was **blocked** by Defender — the hashes were
  not written to disk.
- The **SYSTEM** save **succeeded** (Defender does not treat the SYSTEM hive alone as
  credential theft). On its own it is not sensitive, but paired with a SAM copy it would be —
  so the *intent* is clear even though the SAM step failed.
- Single host (`WIN-LAB`), single account (`labadmin`), a ~4-second window. No sign (in this
  data) of the hives being moved off the host.

## 6. Verdict

**True positive — credential-dumping attempt, blocked.** The command, the target (SAM), and
the pairing with a SYSTEM-hive copy are unambiguous. The tool stopped the critical step, but
the behaviour is malicious and the account's activity needs review.

## 7. Response and recommendations

1. **Confirm** no SAM/SYSTEM copies exist on disk or were exfiltrated (check `C:\temp`, recent
   file writes, outbound transfers).
2. **Review the account** (`labadmin`) — was this expected admin activity or a compromise? If
   not expected, treat the account as suspect and reset its credentials.
3. **Assume exposure if in doubt** — had the SAM save succeeded, every local hash would be
   considered compromised; plan a local-password reset accordingly.
4. **Detection gap note:** a purpose-built polling detector *missed* this (the command was too
   fast between polls); Defender and Sysmon (event-driven) caught it. Prefer event-driven
   detection for this technique (see the main report's conclusion).

## 8. Incident ticket (concise)

> **Title:** Credential-dumping attempt blocked on WIN-LAB (SAM hive)
> **Severity:** High · **Status:** Resolved (blocked) · **Account:** WIN-LAB\labadmin
> **Summary:** At 2026-10-28 22:52, Defender blocked `reg.exe` saving the SAM hive (T1003.002);
> a paired SYSTEM-hive save succeeded moments later. Hashes were not written to disk.
> Behaviour is a true-positive credential-dumping attempt.
> **Actions:** Verified no hive files left on disk; flagged `labadmin` for ownership review;
> recommended event-driven detection to close a polling-detector gap.
> **Next:** Confirm the activity was authorised admin work; if not, escalate and reset credentials.

---

*This case uses existing lab telemetry from this repository. A production version would add
SIEM screenshots, the analyst's name and timestamps, and the ticketing-system reference.*
