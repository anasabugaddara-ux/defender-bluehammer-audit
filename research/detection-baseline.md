# Detection Baseline — CVE-2026-33825 "BlueHammer"

> Defensive reference for the audit module. All values below drive the module's
> version comparison, posture checks, and log-hunting logic. Exploit mechanics are
> intentionally **out of scope** — this file records only what a defender needs to
> detect the vulnerable state and hunt the attack.

## 1. Vulnerability summary (background)

| Field | Value |
|---|---|
| CVE | CVE-2026-33825 |
| Alias | "BlueHammer" |
| Class | TOCTOU race (CWE-1220 — insufficient granularity of access control) |
| Component | Microsoft Defender (Antimalware Platform) |
| Impact | Low-priv local user reads SAM DB → credential theft → indirect priv-esc |
| Status | **Patched**, Microsoft-confirmed, CISA-KEV listed |
| Disclosure | Researcher "Nightmare-Eclipse", 2 Apr 2026 |
| Exploited ITW | ~mid-Apr 2026 (one documented intrusion; attempt FAILED + quarantined) |

## 2. (A) Version baseline — "Vulnerable?"

**Fixed platform version:** `4.18.26030.3011` (Defender Antimalware Platform, released 14 Apr 2026).

- **Vulnerable** iff `AMEngineVersion`/platform `< 4.18.26030.3011`.
- **Patched** iff `>= 4.18.26030.3011`.

Three independent sources to read and cross-check (flag disagreement — tamper indicator):

1. **PowerShell:** `Get-MpComputerStatus | Select AMProductVersion, AMEngineVersion, AMServiceVersion, NISEngineVersion`
   - Platform version maps to `AMProductVersion` (a.k.a. Antimalware Client / platform).
2. **Registry:** `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates` and
   `HKLM\SOFTWARE\Microsoft\Windows Defender` → product/engine version values;
   platform under `...\Windows Defender\` install info.
3. **File version:** `MpCmdRun.exe` / `MsMpEng.exe` under
   `C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\` — the highest
   `<version>` folder name is the active platform build.

> Comparison uses `Rex::Version` (dotted, 4-part). If the three sources disagree,
> report a NOTE — divergence can indicate a stale/rolled-back or tampered platform.

## 3. (B) Posture — "Exploitable in practice?"

Read-only posture signals (all from `Get-MpComputerStatus` unless noted):

| Signal | Field / source | Weakens defense when |
|---|---|---|
| Tamper Protection | `IsTamperProtected` | `False` |
| Real-time protection | `RealTimeProtectionEnabled` | `False` |
| On-access / behavior | `BehaviorMonitorEnabled`, `OnAccessProtectionEnabled` | `False` |
| Signature currency | `AntivirusSignatureVersion` + `AntivirusSignatureLastUpdated` | stale (> 7 days) |
| VSS / shadow copies | `vssadmin list shadows` (read-only) | present → SAM copy exposure surface |

## 4. (C) Targeting — "Attacked?"

**Defender detection name for the exploit:** `Exploit:Win32/DfndrPEBluHmr.BZ`

**Log source:** *Microsoft-Windows-Windows Defender/Operational*
- **Event ID 1116** — malware/threat detected.
- **Event ID 1117** — action taken (quarantine/remove/block).

Hunt query (read-only, via `Get-WinEvent`):
```
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in 1116,1117 -and $_.Message -match "DfndrPEBluHmr" }
```

**Huntress "nightmare-eclipse-intrusion" IOC pattern (behavioral):**
- Suspicious executables dropped in **user-writable** dirs, notably subfolders of
  `%USERPROFILE%\Pictures\` and `%USERPROFILE%\Downloads\` (e.g. nested/oddly-named
  subfolders holding a lone `.exe`).
- Known-bad C2 host / file hash → recorded in `research/iocs.json` (populated in Phase 1
  capture from the Huntress writeup; module reads that list so IOCs stay data, not code).

> NOTE: the one documented ITW attempt **failed and was quarantined**, so on real
> hosts a 1116/1117 hit for this signature most likely means *attempted, blocked* —
> the module reports EVIDENCE-OF-TARGETING, not confirmed compromise, and says so.

## 5. Verdict scoring (drives module output)

| Verdict | Condition |
|---|---|
| `VULNERABLE` | platform `< 4.18.26030.3011` |
| `PATCHED-BUT-EXPOSED` | patched, but posture weak (Tamper off / RTP off / VSS present) |
| `HARDENED` | patched + Tamper Protection on + RTP on + signatures current |
| `EVIDENCE-OF-TARGETING` | any 1116/1117 DfndrPEBluHmr hit OR Huntress IOC match (overlays the above) |

## 6. Sources
See `research/SOURCES.md`. All defensive: MSRC advisory, CISA KEV, Huntress analysis,
Microsoft Defender platform release notes, Microsoft `Get-MpComputerStatus` docs.
