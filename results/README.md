# Results — Coverage Matrix

This is the heart of the report: for each technique, **which defence noticed, and how.**
Each technique has its own page with the detection logic, the Sigma rules, and the
evidence captured from the lab.

## The matrix

Legend: ✅ detected · ⚠️ partial (logged but no clear alert) · ❌ missed · _tbd_ not yet tested

| # | Technique | ATT&CK | Defender | Sysmon + config | My detector (1.0) |
|---|-----------|--------|----------|-----------------|-------------------|
| 1 | [AlwaysInstallElevated](01-alwaysinstallelevated.md) | T1548.002 | ❌ | ❌ | ✅ |
| 2 | [Unquoted service path](02-unquoted-service-path.md) | T1574.009 | ❌ | ⚠️ | ✅ |
| 3 | [Backup-operator privilege abuse](03-backup-privilege-abuse.md) | T1003.002 | ✅ | ⚠️ | ❌ |
| 4 | [Saved-credential reuse](04-saved-credential-reuse.md) | T1078 / T1555.004 | ❌ | ⚠️ | ✅ |
| 5 | [Unattended-setup credentials](05-unattended-setup-credentials.md) | T1552.001 | ❌ | ⚠️ | ✅ |

## How each technique was tested

Every technique follows the same method, so the comparison is fair:

1. Roll the VM back to the **`lab-ready`** snapshot (identical starting state each time).
2. Confirm all three defences are running and logging.
3. Perform the technique once, in the lab, as the standard user.
4. Record for each defence: did it alert, did it merely log, or did it miss?
5. Capture a screenshot of the evidence into [`../screenshots/`](../screenshots/).
6. Fill in that technique's row above and the detail table on its page.

## How to read the conclusion

The interesting result is **the gaps** — the ❌ and ⚠️ cells. Each gap is where a real
company running that defence would miss the attack. Each one has a proposed Sigma rule in
[`../sigma-rules/`](../sigma-rules/) designed to catch it. The rules are experimental: three
(`01a`, `03a`, `04a`) are validated with pySigma against positive and benign sample events,
the other seven only parse and convert, and none has been run in a SIEM yet (see
[`../sigma-rules/README.md`](../sigma-rules/README.md)). For Sysmon, ⚠️ is the expected result:
it records events but does not alert on its own.

> All five techniques have been run and the matrix is complete. Each technique's page states
> precisely what was demonstrated — vulnerable configuration found, activity observed,
> whether exploitation was carried through, and which defence validated the detection.
