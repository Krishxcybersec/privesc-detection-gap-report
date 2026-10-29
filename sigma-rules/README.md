# Sigma rules — status and caveats

Ten Sigma rules, two per technique, mapping the detections in this report to a portable,
industry-standard format with MITRE ATT&CK tags.

## Honest status

**These are experimental detection *proposals*, not production-validated rules.** They are
marked `status: experimental` for that reason. Specifically:

- They parse as valid YAML, but that does **not** prove Sigma schema compliance or
  detection correctness.
- They have **not** been validated against a representative set of positive (true attack)
  and negative (benign) telemetry. The lab testing in [`../results/`](../results/)
  exercised the *techniques*, not a full true-positive / false-positive evaluation of each rule.
- Each rule includes a `falsepositives:` section, but treat those as starting points, not a
  complete analysis.

## Known limitations worth stating

- **`01b` (msiexec child):** flags a shell spawned by `msiexec`, but does not itself confirm
  the child runs as SYSTEM — that would need the integrity level / token from the event.
- **`02a` (unquoted path binary):** detects an executable created at a drive root broadly;
  it is not correlated to a specific known-vulnerable service.
- **`05b` (unattend access):** flags access to the file, not whether the file actually
  contains credentials.
- Rules relying on command-line or temporal correlation will have false positives from
  legitimate administrative activity.

## Next step (not yet done)

Add rule tests with sample events (true-positive and false-positive cases), and tune each
rule against them before any real-world use.
