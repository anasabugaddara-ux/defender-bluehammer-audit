# Sources — defensive only

> Citation list for the writeup. Every source here is advisory/detection-oriented.
> The leaked PoC and the closed offensive PR are **not** used as build inputs.

| # | Source | Use |
|---|---|---|
| 1 | MSRC advisory for CVE-2026-33825 | Vuln class (CWE-1220 TOCTOU), fixed platform version 4.18.26030.3011, affected components |
| 2 | CISA KEV entry (CVE-2026-33825) | Confirms known-exploited status; remediation due-date framing |
| 3 | Huntress — "nightmare-eclipse-intrusion" analysis | IOCs: user-writable drop paths (\Pictures, \Downloads subfolders), C2/hash, failed+quarantined outcome |
| 4 | Microsoft Defender Antimalware Platform release notes | Platform build → date mapping (4.18.26030.3011 = 14 Apr 2026) |
| 5 | Microsoft Docs — Get-MpComputerStatus | Field names: AMProductVersion, IsTamperProtected, RealTimeProtectionEnabled, signature fields |
| 6 | Microsoft Docs — Windows Defender Operational log | Event IDs 1116 (detection) / 1117 (action taken) schema |

## Origin note (writeup only — do NOT rebuild)
- rapid7/metasploit-framework **PR #21521** — original *offensive* exploit module,
  closed as non-functional/unverified. Cited only to narrate the offensive→defensive
  pivot. The leftover local artifact `~/.msf4/modules/exploits/windows/local/blue_hammer.rb`
  (+ `bridge.exe`) is out of scope and untouched by this project.

## TODO (Phase 1 capture)
- [ ] Populate `research/iocs.json` with concrete Huntress IOCs (hashes, C2, path regexes)
      transcribed from source #3, each with a citation field.
- [ ] Confirm exact MSRC/KEV URLs and Huntress article URL for the bibliography.
