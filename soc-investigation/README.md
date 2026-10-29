# SOC Investigation — Credential-Dumping Alert (SAM hive)

A worked, end-to-end investigation of a single alert, in the format a junior SOC analyst
would use: **alert → triage → evidence → timeline → what is and isn't established →
verdict → response → ticket.**

> Provenance: the telemetry comes from the controlled lab in this repository (see
> [`../lab-setup.md`](../lab-setup.md)). The actions were performed deliberately on the
> `WIN-LAB` test VM. This write-up treats that telemetry as if it were a real alert, to
> demonstrate the investigation workflow. It is not a real-world incident.

Every statement below is labelled by how well it is supported:

| Label | Meaning |
|---|---|
| **Observed** | Seen directly in the captured evidence (screenshot or query output) |
| **Tool-reported** | Stated by a security tool; the tool's own claim, not independently checked |
| **Inferred** | A reasonable conclusion from the evidence, but not directly shown |
| **Not verified** | Needed for a complete answer, but not checked in this evidence |

---

## 1. The alert

| | |
|---|---|
| **Source** | Microsoft Defender |
| **Alert** | Credential theft behaviour — `reg.exe` saving the SAM registry hive |
| **ThreatID** | 2147840094 |
| **Host** | WIN-LAB |
| **Time (first seen)** | 2026-10-28 22:52:15 |
| **Action reported by tool** | Blocked |

Defender resource string:
`CmdLine:_C:\Windows\System32\reg.exe save hklm\sam C:\temp\sam.hiv`

## 2. Triage — what is this?

The SAM hive holds local account **password hashes**; the SYSTEM hive holds the key needed
to decrypt them. Copying them is a classic **credential-dumping** step
(**MITRE ATT&CK [T1003.002](https://attack.mitre.org/techniques/T1003/002/)** — OS Credential
Dumping: SAM). Normal day-to-day activity does **not** save the SAM hive, so this is
high-priority and worth a full look rather than a quick dismissal.

## 3. Evidence gathered

| # | Source | What it shows | Label |
|---|---|---|---|
| E1 | Defender detection record | ThreatID 2147840094 for the command `reg.exe save hklm\sam C:\temp\sam.hiv` at 22:52:15 | **Observed** |
| E2 | Defender detection record | Action = *blocked* | **Tool-reported** |
| E3 | Analyst's shell | `reg save hklm\sam ...` returned an error; `reg save hklm\system ...` completed | **Observed** |
| E4 | Sysmon Event ID 1 (process create) | Two records matching a search for `reg.exe` + `save`, at 22:52:16 and 22:52:19. The screenshot shows their timestamps, not their full command lines | **Observed** (timestamps only) |
| E5 | Test set-up | Commands were run as `WIN-LAB\labadmin` (local administrator) | Known from the test context |

Key query used (Sysmon):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
  Where-Object { $_.Message -match 'reg.exe' -and $_.Message -match 'save' }
```

## 4. Timeline

```
22:52:15  Defender records the SAM-save command, action "blocked"      (E1, E2)
22:52:16  Sysmon Event 1: reg.exe + save  -> attributed to the SAM save (E4, by order)
22:52:19  Sysmon Event 1: reg.exe + save  -> attributed to the SYSTEM save (E4, by order)
```

The two Sysmon records are matched to the SAM and SYSTEM commands **by timing and the order
the commands were run**, because the evidence captured their timestamps but not their full
command lines (**Inferred**). Timestamps are to the second and come from different tools,
so their exact order within a second is not meaningful.

## 5. What is and isn't established

**Established**
- A `reg.exe save` of the SAM hive was attempted and Defender recorded it (E1). *(Observed)*
- The SAM save returned an error at the time Defender reported blocking it (E2, E3).
- A save of the SYSTEM hive completed (E3). *(Observed)*

**Inferred, not shown**
- That Defender's block **caused** the SAM save to fail. The error and the detection happened
  together, which strongly suggests it, but cause isn't shown directly.
- That no SAM hive copy was written to disk. Likely, because the command failed, but the
  output path was **not** checked.

**Not verified (open checks)**
- Whether `C:\temp\sam.hiv` exists.
- Where the **SYSTEM hive copy** was written, and whether it has been removed. The save completed,
  so a copy exists unless deleted, and its removal is not recorded here.
- Whether any hive file left the host. No network or file-transfer telemetry was reviewed.
- Whether the activity was **authorised** admin work.

## 6. Verdict

**True positive: a credential-dumping attempt.** The command, the target (SAM), and the
paired SYSTEM-hive save make the behaviour unambiguous.

- Confidence in the **behaviour**: high (observed).
- Confidence in the **impact** (that no credential material was exposed): medium. The SAM step
  was reported blocked, but the on-disk checks above are still open, and the SYSTEM hive copy
  is known to exist.

## 7. Response

| # | Action | Status |
|---|---|---|
| 1 | Check `C:\temp` for `sam.hiv`; locate the SYSTEM hive copy | Open |
| 2 | Securely delete any hive copies found, and record that it was done | Open |
| 3 | Review outbound transfers / file activity from the host around 22:52 | Open |
| 4 | Confirm with the owner of `labadmin` whether this was authorised | Open |
| 5 | If not authorised (or the SAM copy is found): treat local account hashes as exposed, reset local passwords, and escalate | Conditional |
| 6 | Detection note: the purpose-built polling detector missed this (the command ended between polls), while Defender and Sysmon recorded it. Prefer event-based detection for this technique | Recorded |

## 8. Incident ticket (concise)

> **Title:** Credential-dumping attempt on WIN-LAB (SAM hive save)
> **Severity:** High · **Status:** Open, pending verification · **Account:** WIN-LAB\labadmin
> **Summary:** At 2026-10-28 22:52, Defender recorded `reg.exe` saving the SAM hive (T1003.002)
> and reported blocking it; the command returned an error. A SYSTEM-hive save completed
> seconds later. Verdict: true-positive credential-dumping attempt.
> **Known:** SAM save attempted and reported blocked; SYSTEM hive copy created.
> **Not yet verified:** absence of a SAM copy on disk; location/removal of the SYSTEM copy;
> no exfiltration; whether the activity was authorised.
> **Next:** complete response actions 1–4. Close only once they are done and recorded;
> escalate if the activity was not authorised.

---

*This case uses existing lab telemetry from this repository. A production version would add
SIEM screenshots, raw (sanitised) event records, the analyst's name and timestamps, and the
ticketing-system reference.*
