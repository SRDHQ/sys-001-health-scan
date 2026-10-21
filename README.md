# SYS-001 — System health scan

Part of **SRD (Systems Research & Development)**. Designation **SYS-001**, site **SRD-01**.

A Tier 0 system health scan for an Arch Linux machine: it runs a fixed table of seven read-only, unprivileged, offline commands (`pacman -Qkk`, `paclog`, `pacman -Qu`, `pacman -Qm`, `pacman -Qdt`, `pacdiff -o`, `systemctl --failed`), writes a scrubbed snapshot outside the repository, and diffs two snapshots. Python standard library only; no network, no model calls, no timers.

## Use

```bash
python -I collect.py --out ~/.local/state/lab/health-scan/runs/ [--previous <snapshot.json>]
python -I diff.py <snapshot-a.json> <snapshot-b.json>
python -I -m unittest discover -s tests        # simulated fixtures only
```

`--out` must be outside this repository; the collector refuses otherwise (AC3).

## Documentation

The specification, decisions, acceptance criteria and experiment results (EXP-001, the Tier 0 two-run experiment) live in the lab's knowledge vault (CEREBRUM), record `SYS-001 — System health scan`. Evidence cites this repository as `SYS-001@<commit>`.

History: this code lived in the vault at `projects/health-scan/` until M05.5 moved it here with `git subtree split`. Messages, authors and dates are preserved, but the commits were rewritten, so their hashes differ from the vault's. Evidence written before the move cites vault commits; this mapping links them:

| Vault commit | This repository |
| --- | --- |
| `7d890e7` | `d5585ae` |
| `4b0c654` | `d311ed0` |
| `9f1d6bd` | `f7c2fa3` |
| `ad9a450` | `9c40909` |
| `15026a9` | `b2b1edc` |
