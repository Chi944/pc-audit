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
git clone https://github.com/Chi944/pc-audit.git
cd pc-audit
chmod +x audit-macos.sh run-audit-macos.sh
bash audit-macos.sh --quick
```

**Recommended first run on Mac: use `--quick`** (2–5 minutes). A full scan takes 5–12 minutes depending on disk size and Xcode/Docker data.

Or double-click `run-audit-macos.sh` in Terminal (may need `chmod +x` first).

When the scan finishes, `report.html` opens in your browser and `cleanup-prompt.md` is saved alongside it.

## Options

| Flag | Windows | macOS | Effect |
| --- | --- | --- | --- |
| Quick scan | `-Quick` | `--quick` | Faster scan: skips system-wide paths and duplicate hashing (macOS) |
| Skip duplicates | `-SkipDuplicates` | `--skip-duplicates` | Skip the duplicate-file hashing pass |
| No browser | `-NoBrowser` | `--no-browser` | Don't auto-open the report |
| Custom output dir | `-OutputDir <path>` | `--output-dir <path>` | Write reports somewhere other than `./reports` |
| Help | — | `--help` | Show macOS usage |

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

## macOS troubleshooting

### Script seems to hang / runs forever

Older versions walked your entire home folder including Photos libraries and iCloud — that can take hours. The current script avoids those paths. If it still feels slow:

1. **Use `--quick` first** — finishes in a few minutes.
2. **Watch the progress lines** — each step prints `[ Ns] Step name...`. If it stops on one step for >3 minutes, that folder is very large (often Xcode DerivedData or Docker).
3. **Grant Terminal Full Disk Access** (optional, speeds up some reads): System Settings → Privacy & Security → Full Disk Access → add Terminal or iTerm.

### osascript / login items permission popup

On macOS Ventura+, the script uses `sfltool` instead of `osascript` to avoid a blocking permission dialog. If you see a prompt anyway, click **OK** or skip it — the script times out after 5 seconds and continues.

### "Operation not permitted" on some folders

Normal on macOS without Full Disk Access. The script skips unreadable paths and still produces a complete report for everything it can read.

### Spotlight / mdfind returns nothing

Large-file search falls back to a targeted `find` in Downloads/Desktop/Documents only. Rebuild the Spotlight index if needed: System Settings → Siri & Spotlight → Spotlight Privacy (remove and re-add your home folder).

### Expected run times (macOS)

| Mode | Typical duration |
| --- | --- |
| `--quick` | 2–5 min |
| Full scan (no Xcode) | 5–8 min |
| Full scan (Xcode + Docker) | 8–15 min |

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

## Requirements

| Platform | Needs |
| --- | --- |
| Windows | PowerShell 5.1+ (built into Windows) |
| macOS | bash 3.2+ (built in), python3 optional (for `data.json`) |
