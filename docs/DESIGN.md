# Module Design — `bluehammer_defender_audit`

`module/post/windows/gather/bluehammer_defender_audit.rb` — a **defensive** MSF post module.
Read-only detection / hunting / audit for CVE-2026-33825 "BlueHammer". No exploitation.

## Collection approach

The module performs a **single, memoized PowerShell collection pass** and derives all three
checks from its output:

- `collection_script` builds the script (injecting `HUNT_DAYS` and the Defender log name).
- `run_ps` base64-encodes it and runs it via `cmd_exec` with
  `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ...`.
- `collected` parses the returned JSON once and caches it, so the host is touched only once.

Cmdlets used (all read-only): `Get-MpComputerStatus`, `Get-Service WinDefend`,
`Get-CimInstance Win32_ShadowCopy`, `Get-WinEvent`, `Get-ChildItem`, `Get-FileHash`.

## Mixins

- `Msf::Post::Common` — `cmd_exec`, used to execute the encoded PowerShell.

IOC files are read locally with Ruby's `::File`; all target-side data (version, posture, log,
staged files) comes from the single PowerShell pass, so no registry or file mixin is required on
the target.

## Datastore options

| Option | Type | Default | Purpose |
|---|---|---|---|
| `FIXED_VERSION` | string | `4.18.26030.3011` | patched-platform baseline (overridable) |
| `HUNT_LOG` | bool | `true` | run (C) event-log hunt |
| `HUNT_DAYS` | int | `90` | lookback window for the log hunt |
| `IOC_FILE` | path | (blank) | optional local `iocs.json`; if set, path-regex/hash IOCs loaded |
| `STORE_LOOT` | bool | `true` | write JSON snapshot via `store_loot` |

## Flow (`run`)

1. Guard: confirm Windows session and Defender present (`defender_present?`); else `print_error` + return.
2. **(A) `check_version`** → `{ vulnerable:, versions:, primary:, disagree: }`
3. **(B) `check_posture`** → `{ tamper:, rtp:, behavior:, onaccess:, sig_age_days:, vss_present: }`
4. **(C) `hunt_targeting`** (if `HUNT_LOG`) → `{ sig_hits:, ioc_hits:, detection_total: }`
5. **`score`** → verdict (see below)
6. **`report`** → `print_*` sections; `report_vuln` when VULNERABLE; `report_note`
   (type `bluehammer.audit`) always; `store_loot` JSON when `STORE_LOOT`.

## Version sources (A) and normalisation

Three independent sources are read and compared:

1. **PowerShell** — `(Get-MpComputerStatus).AMProductVersion`
2. **Platform folder** — highest `<version>` directory under
   `%ProgramData%\Microsoft\Windows Defender\Platform`
3. **Platform binary** — `MpCmdRun.exe` file version

Each value is reduced to its dotted-numeric core by `normalize_version`
(e.g. `4.18.26050.15-0` → `4.18.26050.15`) **before** comparison, so a folder-revision suffix is
not mistaken for a genuine version disagreement. Comparison uses `Gem::Version`. A real
disagreement across normalised sources is reported as a possible tampering / partial-update
indicator.

## Posture (B)

From `Get-MpComputerStatus`: `IsTamperProtected`, `RealTimeProtectionEnabled`,
`BehaviorMonitorEnabled`, `OnAccessProtectionEnabled`, signature age in days
(computed on-host from `AntivirusSignatureLastUpdated`), and shadow-copy presence
(`Get-CimInstance Win32_ShadowCopy` count). Signatures older than `SIG_STALE_DAYS` (7 days)
count as stale.

## Targeting (C)

- **Log hunt:** `Get-WinEvent` on `Microsoft-Windows-Windows Defender/Operational`, event IDs
  1116/1117 within `HUNT_DAYS`, filtered to messages containing the `DfndrPEBluHmr` signature.
- **IOC match:** executables enumerated under each user's `Downloads`/`Pictures` are matched
  against the path-regex and SHA-256 indicators loaded from `IOC_FILE`
  (see `research/iocs.json`). Path regexes are the primary, name-independent indicator; observed
  filenames are supplementary; the one available hash is BeigeBurrow (associated tooling), never a
  fabricated BlueHammer hash.

## Verdict scoring

```
base = VULNERABLE            if version below FIXED_VERSION
     = PATCHED-BUT-EXPOSED   if patched and weak posture
     = HARDENED              if patched and strong posture
     = UNKNOWN               if version could not be determined
overlay EVIDENCE-OF-TARGETING if any signature hit or IOC match
```

`weak_posture?` = Tamper Protection off, real-time protection off, signatures stale
(> `SIG_STALE_DAYS`), or shadow copies present.

## Safety / boundary invariants

- Every action is **read-only**: status, version, log, and file reads only.
- No write to Defender config, no Tamper-Protection toggle, no SAM access, no exploit primitive.
- IOCs are external data (`research/iocs.json`), never exploit artifacts.
- Failures degrade gracefully (missing data → empty/`UNKNOWN`, not a crash); module is
  `CRASH_SAFE` with no side effects.
