# Lab Testing Plan

How to run each technique once and fill in the coverage matrix. The detection packs in
`results/` already say **what to look for**; this file is the **order of operations** and
the **evidence to capture**.

> Everything here happens inside the isolated `Win11-Lab` VM only.

---

## Step 0 — Turn on the logging (once, before any testing)

The three defences we compare all need to be live first.

### 0.1 Microsoft Defender
Already built in. Just confirm it's on: **Windows Security → Virus & threat protection →**
make sure real-time protection is on. No extra setup.

### 0.2 Command-line process auditing
So process-start events (4688) include the command line, which most rules need:
- **gpedit.msc → Computer Configuration → Administrative Templates → System → Audit Process Creation →** *Include command line in process creation events* → **Enabled**.
- **gpedit.msc → … → Windows Settings → Security Settings → Advanced Audit Policy → Detailed Tracking →** *Audit Process Creation* → **Success**.

### 0.3 Sysmon with a community config
Sysmon is the free Microsoft tool that writes a detailed diary.
- Download **Sysmon** (Microsoft Sysinternals): https://learn.microsoft.com/sysinternals/downloads/sysmon
- Download a community config, e.g. **SwiftOnSecurity/sysmon-config** (`sysmonconfig-export.xml`):
  https://github.com/SwiftOnSecurity/sysmon-config
- Install from an **admin** terminal:
  ```
  sysmon64 -accepteula -i sysmonconfig-export.xml
  ```
- Sysmon events then appear in **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**.

### 0.4 Your 1.0 detectors (optional third column)
If you want the "my detector" column, copy your five 1.0 Python scripts into the VM and
run them per their README (`pip install pywin32 psutil`). They print alerts to the console,
which you screenshot.

### 0.5 Snapshot
Once logging is on, power off and take a snapshot named **`lab-ready`**. You will roll
back to this before each technique, so every test starts identical.

---

## The method (same for all five)

1. **Roll back** the VM to the `lab-ready` snapshot.
2. **Set up the weak condition** for the technique (see each technique's "Setup source" below).
3. **Have the three defences running**, and open the right log in Event Viewer.
4. **Trigger the technique once** as the standard user (see "Trigger source").
5. **Observe and record** for each defence: ✅ alerted · ⚠️ only logged · ❌ nothing.
6. **Screenshot** the evidence into `screenshots/` (naming below).
7. **Fill the row** in `results/README.md` and the detail table on the technique's page.

### Where to get the setup/trigger steps
These are standard, documented procedures — use authoritative references rather than
reinventing them:
- **Your own 1.0 dissertation lab** already set up all five conditions once.
- **MITRE ATT&CK** pages (linked in each technique's write-up) describe each one.
- **Microsoft Learn** documents each setting (`AlwaysInstallElevated`, service paths,
  `SeBackupPrivilege`, `cmdkey`, unattended answer files).
- **TryHackMe** "Windows Privilege Escalation" rooms and **HackTricks** give lab-ready steps.

Keep a short note of the exact steps you used in `lab-setup.md` (create it as you go) so
the lab is reproducible.

---

## Per technique — what to watch and capture

### Technique 1 — AlwaysInstallElevated
- **Watch:** Sysmon **13** (registry set) on the `AlwaysInstallElevated` value; Security/Sysmon
  process-create for a child of `msiexec.exe` running as SYSTEM.
- **Open:** Sysmon Operational log, filtered to Event ID 13 and 1.
- **Screenshots:** `01-alwaysinstallelevated-defender.png`, `...-sysmon.png`, `...-detector.png`.

### Technique 2 — Unquoted service path
- **Watch:** Sysmon **11** (file create) for a `.exe` at a root-level path; process-create with
  parent `services.exe` from an unexpected path; System **7036** service start.
- **Open:** Sysmon Operational (11, 1) and System log (7036).
- **Screenshots:** `02-unquoted-path-defender.png`, `...-sysmon.png`, `...-detector.png`.

### Technique 3 — Backup-privilege / SAM hive
- **Watch:** process-create for `reg.exe` with `save` + `hklm\sam`/`system`; Security **4673/4674**.
- **Open:** Sysmon Operational (1) and Security log.
- **Screenshots:** `03-backup-privilege-defender.png`, `...-sysmon.png`, `...-detector.png`.

### Technique 4 — Saved-credential reuse
- **Watch:** process-create for `cmdkey` (`/add`) and `runas` (`/savecred`); Security **4648**
  (explicit-credential logon), then **4624/4672** for the admin account.
- **Open:** Sysmon Operational (1) and Security log (4648/4624/4672).
- **Screenshots:** `04-saved-cred-defender.png`, `...-sysmon.png`, `...-detector.png`.

### Technique 5 — Unattended-setup credentials
- **Watch:** Security **4663** (object access) on `Unattend.xml` — needs file auditing (SACL)
  on `C:\Windows\Panther`; and process-create for `type`/`Get-Content` naming the file.
- **Note:** turn on auditing for that folder first (Properties → Security → Advanced → Auditing),
  or only the process-based signal will appear. Record which one fired — that's a real finding.
- **Screenshots:** `05-unattend-defender.png`, `...-sysmon.png`, `...-detector.png`.

---

## Screenshot rules

- Save into `screenshots/`, named `NN-technique-defence.png` (as above), so they sort.
- **Crop to the evidence** — the alert or the event entry — not the whole desktop.
- **Check each one for personal data** before it enters the repo: no real name, no email,
  no laptop paths, no lab password. The VM host name is `WIN-LAB` by design.
- If unsure about a screenshot, ask before committing it.

---

## Recording a result

In `results/README.md`, change the technique's row from `_tbd_` to ✅ / ⚠️ / ❌ per defence.
On the technique's own page, fill the "What each defence should show" table with one line
of what you saw and the screenshot name. That's the finding — in your own words.

## After all five

- Any ❌ or ⚠️ is a **gap**. The matching Sigma rule in `sigma-rules/` is your answer to it.
- Write a short **conclusion** in the main `README.md`: what the defaults missed, and how
  your rules close it. That paragraph is the point of the whole project.
