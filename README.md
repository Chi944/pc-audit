# pc-audit

A read-only speed & storage auditor for **Windows and macOS**. One script scans your machine, shows where every gigabyte went, and generates a tiered cleanup plan **plus a ready-to-paste prompt for any AI agent** (Cursor, Claude Code, Codex CLI, ...) to execute the cleanup with guardrails.

**pc-audit itself never deletes anything.** It only reads, measures, and reports.

## Quick start

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\audit.ps1
```

Or double-click `run-audit.bat`.

### macOS

```bash
bash audit-macos.sh
```

Or double-click `run-audit-macos.sh` (may need `chmod +x run-audit-macos.sh audit-macos.sh` first).

A full scan takes roughly 5–15 minutes depending on disk size. When it finishes, `report.html` opens in your browser.

## Options

| Flag | Windows | macOS | Effect |
| --- | --- | --- | --- |
| Quick scan | `-Quick` | `--quick` | Scan only your user profile instead of the whole drive (much faster) |
| Skip duplicates | `-SkipDuplicates` | `--skip-duplicates` | Skip the duplicate-file hashing pass |
| No browser | `-NoBrowser` | `--no-browser` | Don't auto-open the report |
| Custom output dir | `-OutputDir <path>` | `--output-dir <path>` | Write reports somewhere other than `./reports` |

## What it checks

Both platforms cover the same audit workflow:

1. **System** — OS version, RAM, disk size/free %, storage health.
2. **Where the space goes** — largest folders in your home profile, caches, and (full scan) system-wide locations.
3. **Caches & known bloat** — safe-to-clear verdicts for temp, package-manager caches, and platform-specific bloat.
4. **Largest files** — top 40 files over 300 MB with last-modified dates.
5. **Old installers** — `.exe`/`.msi`/`.iso` (Windows) or `.dmg`/`.pkg`/`.iso` (macOS) sitting in Downloads/Desktop/Documents.
6. **Duplicates** — files over 10 MB in user folders, grouped by size then verified with MD5 hashes.
7. **Dev bloat** — `node_modules` and virtualenvs per project, Docker/Ollama/model caches, and platform-specific dev stores.
8. **Installed apps** — categorized as Essential / Occasional / Unnecessary / Review with reasons.
9. **Startup / background items** — with disable/keep verdicts for boot speed.

### Platform-specific extras

| | Windows | macOS |
| --- | --- | --- |
| **Caches** | Windows Update, WinSxS, hibernation file, NVIDIA driver downloads, Recycle Bin | Homebrew cache, Xcode DerivedData/Archives, iOS DeviceSupport, CoreSimulator, Mail downloads, iOS backups |
| **Dev stores** | WSL virtual disks, Claude Desktop VM bundles | OrbStack, Android SDK, Gradle, CocoaPods |
| **Apps source** | Registry uninstall keys | `/Applications` folder sizes |
| **Startup** | Task Manager startup entries | Login items + LaunchAgents/Daemons |
| **Disk health** | Physical disk type (SSD/HDD) + health | Time Machine local snapshot count |

## Output

Each run creates `reports/<timestamp>/` containing:

| File | Purpose |
| --- | --- |
| `report.html` | The full visual audit report |
| `cleanup-prompt.md` | Paste into any AI agent with shell access to execute the cleanup |
| `data.json` | Raw findings for scripting |

The generated prompt organizes deletions into three tiers — **Tier 1** (safe: caches, temp, installers, duplicates), **Tier 2** (rebuildable: dependency folders, model caches), **Tier 3** (big items needing a human decision: games, large media, personal backups) — and instructs the agent to confirm before each tier, skip locked files, never touch code/documents/profiles, and report freed space as it goes.

## Safety notes

- The scan is 100% read-only; deletion only ever happens if *you* hand the generated prompt to an agent and approve its steps.
- `reports/` is gitignored because reports contain machine-specific paths and app inventories.
- Some cleanup steps in the generated prompt require elevated privileges (Windows admin shell, macOS `sudo` for system caches); the prompt says which.
- On macOS, iOS device backups and Xcode archives are flagged as Tier 3 personal data — never auto-deleted.

## Repository layout

```
pc-audit/
  audit.ps1           # Windows scanner
  audit-macos.sh      # macOS scanner (bash 3.2+)
  run-audit.bat       # Windows double-click launcher
  run-audit-macos.sh  # macOS launcher
  README.md
  reports/            # generated (gitignored)
```
