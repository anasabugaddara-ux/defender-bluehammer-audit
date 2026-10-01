# BlueHammer Defender Compromise-Audit

A **defensive** Metasploit post module that audits a Windows host for
**CVE-2026-33825 "BlueHammer"** — a patched TOCTOU flaw (CWE-1220) in Microsoft
Defender that let a low-privileged user read the SAM database.

> **Scope: detection / hunting / audit only.** This project performs **no
> exploitation**. It does not implement the TOCTOU primitive, touch the SAM
> database, or modify Defender configuration. Every operation is read-only.

## What it does

On an authorized post-exploitation session, `bluehammer_defender_audit` answers three questions:

- **(A) Vulnerable?** Cross-checks the Defender platform build across three sources
  (PowerShell, the on-disk platform folder, and the platform binary version) against the fixed
  version **4.18.26030.3011**, normalising build suffixes and flagging genuine source
  disagreement.
- **(B) Exposed in practice?** Reports posture — Tamper Protection, real-time protection,
  behaviour/on-access monitoring, signature currency, and Volume Shadow Copy presence.
- **(C) Targeted?** Hunts the Windows Defender Operational log (event IDs 1116/1117) for
  `Exploit:Win32/DfndrPEBluHmr.BZ` and matches user-writable directories against Huntress IOCs.

Output: a scored verdict (`VULNERABLE` / `PATCHED-BUT-EXPOSED` / `HARDENED`, optionally overlaid
with `EVIDENCE-OF-TARGETING`), a `report_vuln`/`report_note`, and a JSON loot snapshot.

## Layout

| Path | Purpose |
|---|---|
| `modules/post/windows/gather/bluehammer_defender_audit.rb` | the module |
| `documentation/modules/post/windows/gather/bluehammer_defender_audit.md` | Rapid7-format module documentation |
| `docs/DESIGN.md` | module design + data-collection flow |
| `research/detection-baseline.md` | version baseline, event IDs, detection logic |
| `research/SOURCES.md` | defensive citations |
| `research/iocs.json` | IOC data feed (path regexes, hashes, C2) |
| `scripts/deploy.sh` | symlink the module into `~/.msf4/modules/...` |
| `scripts/lint.sh` | `ruby -c` + patched msftidy |

> **Upstream note:** the repo mirrors the Metasploit framework layout
> (`modules/...` and `documentation/modules/...`), so submission is a direct copy into a
> `metasploit-framework` fork.

## Develop

```bash
./scripts/deploy.sh      # link into the MSF user module tree
./scripts/lint.sh        # syntax + msftidy
msfconsole -q -x "use post/windows/gather/bluehammer_defender_audit; show options; exit"
```

## Usage

```
use post/windows/gather/bluehammer_defender_audit
set SESSION <id>
set IOC_FILE /path/to/research/iocs.json   # optional, enables IOC matching
run
```

See `documentation/modules/post/windows/gather/bluehammer_defender_audit.md` for full options and
example output.

## Status

Complete and verified. Read-only detection logic implemented for all three checks (version,
posture, targeting) with scored verdicts and a JSON loot snapshot. The module loads cleanly, is
`msftidy`-clean, and has been validated against a live Windows Meterpreter session — producing
`PATCHED-BUT-EXPOSED` and `EVIDENCE-OF-TARGETING` results and, via a `FIXED_VERSION` override, the
`VULNERABLE` branch. Rapid7-format documentation and a cited IOC feed are in place.

Remaining: vulnerability/detection writeup, and upstream PR submission.

## Ethics

Detection and hunting only. No offensive PoC is included, rebuilt, or referenced as a build
input. IOCs are sourced from defensive analyses (see `research/SOURCES.md`) and stored as data.
Where a public indicator does not exist — e.g. no file hash was published for the BlueHammer
binary — none is fabricated.
