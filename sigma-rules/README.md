# Sigma rules — status and caveats

Ten Sigma rules, two per technique, mapping the detections in this report to a portable,
industry-standard format with MITRE ATT&CK tags. All are marked `status: experimental`.

## Validation status

| Level | Rules | What has been shown |
|---|---|---|
| **Validated against sample events** | `01a`, `03a`, `04a` | Converted by pySigma's SQLite backend and run against hand-written positive and benign events; each matches every positive and none of the benign cases |
| **Parses and converts only** | `01b`, `02a`, `02b`, `03b`, `04b`, `05a`, `05b` | Loads in pySigma 2.0.1 without errors and converts to a query; detection behaviour **not** tested |

Run the checks yourself (from this folder):

```bash
pip install -r tests/requirements.txt
pytest tests
```

### How the validation works

1. Each rule is converted by **pySigma's SQLite backend**, so the matching is done by the
   real Sigma toolchain, not by a re-implementation of Sigma.
2. The events in [`tests/sample_events.json`](tests/sample_events.json) are loaded into an
   in-memory SQLite table, and the generated query is run over them.
3. The matched set must equal the expected set: every positive caught, no benign event matched.

| Rule | Positives (must match) | Benign cases (must not match) |
|---|---|---|
| `01a` AlwaysInstallElevated set | HKLM value set to 1; per-user (HKU) value set to 1 | value set back to 0; a different Installer value; a similarly named value elsewhere |
| `03a` credential-hive save | the lab's `reg save hklm\sam`; upper-case `REG SAVE HKLM\SYSTEM`; long `HKEY_LOCAL_MACHINE\SECURITY` spelling; quoted path and hive | `reg query HKLM\SAM /v save /s`; saving a non-credential hive; saving a non-credential hive **to a path containing `hklm\sam`**; `HKLM\SAMPLE`; `reg export`; another program mentioning `hklm\sam` |
| `04a` runas /savecred | the lab's `runas /savecred /user:...`; mixed-case `/SaveCred` | runas without `/savecred`; `runas /?`; another program with `/savecred` in its arguments |

**The validation found and fixed real problems in `03a`.** Run against the same events, the
original rule **missed** the `HKEY_LOCAL_MACHINE` spelling (its "long-form" entries were
duplicates of the short ones) and **falsely matched** `reg query HKLM\SAM /v save /s`
(any `save` word counted). A later independent review found a third case: `reg save
HKLM\SOFTWARE C:\backup\hklm\sam.hiv` matched, because the hive name was searched anywhere in
the line, including the destination path. The rule is now a single pattern: `save` must be
the `reg` subcommand, the credential hive (either spelling) must be the argument straight
after it, and the hive name must end there (`HKLM\SAMPLE` is not `HKLM\SAM`).

### What this validation does NOT show

- The sample events are **synthetic, hand-written** records shaped like Sysmon output, not
  captured telemetry. Real logs may format fields differently (for example the `Details` value).
- It shows the rule logic, not behaviour in a **production SIEM** (field mappings, case
  handling and the backend can differ). Running the rules in a SIEM is the next step.
- Passing a small set of cases is not proof of low false positives in a real environment.

## Known limitations

- **`01a` (AlwaysInstallElevated):** fires on each value being set to 1, one event per hive. A
  single event can't show that **both** hives are enabled, which is what makes the host
  exploitable. Confirm by reading both values, or correlate the HKLM and HKU events. It also
  depends on the Sysmon configuration logging this key; in the lab the community config did not
  appear to (see [technique 1](../results/01-alwaysinstallelevated.md)).
- **`01b` (msiexec child):** flags a shell spawned by `msiexec`, but does not itself confirm the
  child runs as SYSTEM. That would need the integrity level / user from the event.
- **`02a` (unquoted path binary):** detects an executable created at a drive root; it misses
  deeper candidate locations and is not correlated to a specific vulnerable service.
- **`02b` (service execution):** excludes `Program Files`, which also suppresses some plausible
  hijack paths inside it.
- **`03a` (credential-hive save):** saving a subkey of the SYSTEM hive also matches, because hive
  names are matched as substrings.
- **`03b` (backup tools):** a `/b` backup-mode flag on its own can satisfy the selection; it does
  not require a reference to a credential file.
- **`04a` / `04b` (runas / cmdkey):** detect the attempt or the credential being stored, not that
  a stored credential was then successfully reused. Pair with a 4648/4624 logon for the target.
- **`05a` / `05b` (answer files):** a filename in a command line, or a file-access event, does not
  prove the file was read or that it contained credentials.

## Next steps

- Extend the sample-event tests to the remaining seven rules.
- Replace synthetic events with sanitised **captured** events from the lab.
- Run the validated rules in a SIEM and record the results there.
