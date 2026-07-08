#!/bin/bash
# pc-audit (macOS): read-only speed & storage audit.
#
# Scans the machine (never deletes anything) and produces:
#   - report.html         rich audit report (opens in browser)
#   - cleanup-prompt.md   ready-to-paste prompt for any AI agent with shell access
#   - data.json           raw findings (requires python3, skipped otherwise)
#
# Usage:  bash audit-macos.sh [--quick] [--skip-duplicates] [--no-browser] [--output-dir DIR]
#
# Compatible with the stock macOS bash 3.2. Read-only: nothing is deleted.

set -u
START_TS=$(date +%s)
QUICK=0; SKIP_DUPES=0; NO_BROWSER=0; OUTPUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --skip-duplicates) SKIP_DUPES=1 ;;
    --no-browser) NO_BROWSER=1 ;;
    --output-dir) shift; OUTPUT_DIR="$1" ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="$SCRIPT_DIR/reports"
STAMP=$(date +%Y-%m-%d_%H-%M)
REPORT_DIR="$OUTPUT_DIR/$STAMP"
mkdir -p "$REPORT_DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

REPORT="$REPORT_DIR/report.html"
PROMPT="$REPORT_DIR/cleanup-prompt.md"

step() { printf '[%4ss] %s\n' "$(( $(date +%s) - START_TS ))" "$1"; }
# du in KB (one filesystem, silent on permission errors)
kb() { du -skx "$1" 2>/dev/null | cut -f1; }
gb_of_kb() { awk -v k="${1:-0}" 'BEGIN{printf "%.2f", k/1048576}'; }
mb_of_kb() { awk -v k="${1:-0}" 'BEGIN{printf "%.1f", k/1024}'; }
gb_of_bytes() { awk -v b="${1:-0}" 'BEGIN{printf "%.2f", b/1073741824}'; }
mb_of_bytes() { awk -v b="${1:-0}" 'BEGIN{printf "%.1f", b/1048576}'; }
esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# ------------------------------------------------------------- 1. System
step "Detecting macOS version, RAM, disk..."
OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
RAM_GB=$(awk -v b="$(sysctl -n hw.memsize 2>/dev/null)" 'BEGIN{printf "%.1f", b/1073741824}')
CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
# APFS: the Data volume holds user data; / is the sealed system volume.
DATA_VOL="/System/Volumes/Data"; [ -d "$DATA_VOL" ] || DATA_VOL="/"
DISK_TOTAL_KB=$(df -k "$DATA_VOL" | awk 'NR==2{print $2}')
DISK_FREE_KB=$(df -k "$DATA_VOL" | awk 'NR==2{print $4}')
DISK_TOTAL_GB=$(gb_of_kb "$DISK_TOTAL_KB"); DISK_FREE_GB=$(gb_of_kb "$DISK_FREE_KB")
PCT_FREE=$(awk -v f="$DISK_FREE_KB" -v t="$DISK_TOTAL_KB" 'BEGIN{printf "%.1f", 100*f/t}')
TM_SNAPSHOTS=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c snapshot || echo 0)

# -------------------------------------------------------- 2. Folder sizes
# folders.tsv: group <TAB> path <TAB> kb
scan_children() { # $1=parent $2=group $3=min_kb
  local d sz
  for d in "$1"/* "$1"/.[!.]*; do
    [ -d "$d" ] || continue
    case "$d" in */.Trash|*/Library) [ "$2" = "Home" ] && continue ;; esac
    sz=$(kb "$d"); [ -z "$sz" ] && sz=0
    [ "$sz" -ge "$3" ] && printf '%s\t%s\t%s\n' "$2" "$d" "$sz" >> "$TMP/folders.tsv"
  done
}
: > "$TMP/folders.tsv"
step "Measuring home folder..."
scan_children "$HOME" "Home" 51200                       # >= 50 MB
scan_children "$HOME/Library" "Library" 51200
[ -d "$HOME/Library/Application Support" ] && scan_children "$HOME/Library/Application Support" "App Support" 102400
[ -d "$HOME/Library/Containers" ] && scan_children "$HOME/Library/Containers" "Containers" 512000
[ -d "$HOME/Library/Developer" ] && scan_children "$HOME/Library/Developer" "Developer" 102400
if [ "$QUICK" -eq 0 ]; then
  step "Measuring system-wide locations (slow; permission-restricted dirs are skipped)..."
  for p in /Applications /Library /usr/local /opt/homebrew /private/var/log /private/var/vm; do
    if [ -d "$p" ]; then
      sz=$(kb "$p"); [ -n "$sz" ] && [ "$sz" -ge 102400 ] && printf '%s\t%s\t%s\n' "System" "$p" "$sz" >> "$TMP/folders.tsv"
    fi
  done
fi
sort -t"$(printf '\t')" -k3 -rn "$TMP/folders.tsv" > "$TMP/folders_sorted.tsv"

# ------------------------------------------------------------- 3. Caches
step "Measuring caches / known bloat locations..."
BREW_CACHE=$(command -v brew >/dev/null 2>&1 && brew --cache 2>/dev/null || echo "$HOME/Library/Caches/Homebrew")
# caches.tsv: name TAB path TAB kb TAB verdict
: > "$TMP/caches.tsv"
add_cache() { # name path verdict
  local sz; [ -e "$2" ] || return 0
  sz=$(kb "$2"); [ -z "$sz" ] && sz=0
  [ "$sz" -ge 10240 ] && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$sz" "$3" >> "$TMP/caches.tsv"
}
add_cache "User caches"            "$HOME/Library/Caches"                                   "Mostly safe to clear; apps rebuild them"
add_cache "User logs"              "$HOME/Library/Logs"                                     "Safe to clear"
add_cache "Trash"                  "$HOME/.Trash"                                           "Safe: empty the Trash"
add_cache "Homebrew cache"         "$BREW_CACHE"                                            "Safe: brew cleanup --prune=all"
add_cache "npm cache"              "$HOME/.npm"                                             "Safe: npm cache clean --force"
add_cache "pip cache"              "$HOME/Library/Caches/pip"                               "Safe: pip cache purge"
add_cache "uv cache"               "$HOME/.cache/uv"                                        "Safe: uv cache clean"
add_cache "Xcode DerivedData"      "$HOME/Library/Developer/Xcode/DerivedData"              "Safe: Xcode rebuilds on next build"
add_cache "Xcode Archives"         "$HOME/Library/Developer/Xcode/Archives"                 "Keep only archives you still need to distribute"
add_cache "iOS DeviceSupport"      "$HOME/Library/Developer/Xcode/iOS DeviceSupport"        "Safe: re-created next time a device connects"
add_cache "CoreSimulator caches"   "$HOME/Library/Developer/CoreSimulator/Caches"           "Safe to clear"
add_cache "CoreSimulator devices"  "$HOME/Library/Developer/CoreSimulator/Devices"          "xcrun simctl delete unavailable removes stale simulators"
add_cache "Mail downloads"         "$HOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads" "Safe to clear"
add_cache "iOS device backups"     "$HOME/Library/Application Support/MobileSync/Backup"    "PERSONAL DATA - review before deleting old backups"
sort -t"$(printf '\t')" -k3 -rn "$TMP/caches.tsv" > "$TMP/caches_sorted.tsv"

# --------------------------------------------------------- 4. Large files
step "Finding largest files (>300 MB) in home..."
# largefiles.tsv: bytes TAB date TAB path
find "$HOME" -xdev -type f -size +300M \
  \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/.Trash/*" \) -prune -o \
  -type f -size +300M -print0 2>/dev/null |
  while IFS= read -r -d '' f; do
    printf '%s\t%s\t%s\n' "$(stat -f%z "$f" 2>/dev/null)" "$(stat -f%Sm -t %Y-%m-%d "$f" 2>/dev/null)" "$f"
  done | sort -rn | head -40 > "$TMP/largefiles.tsv"

# ---------------------------------------------------------- 5. Installers
step "Finding old installers (.dmg/.pkg/.iso)..."
: > "$TMP/installers.tsv"
for r in "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents"; do
  [ -d "$r" ] || continue
  find "$r" -type f \( -name "*.dmg" -o -name "*.pkg" -o -name "*.iso" \) -size +5M -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
      printf '%s\t%s\t%s\n' "$(stat -f%z "$f")" "$(stat -f%Sm -t %Y-%m-%d "$f")" "$f"
    done >> "$TMP/installers.tsv"
done
sort -rn "$TMP/installers.tsv" -o "$TMP/installers.tsv"

# ---------------------------------------------------------- 6. Duplicates
: > "$TMP/dupes.txt"
if [ "$SKIP_DUPES" -eq 0 ]; then
  step "Hashing candidate duplicates (>10 MB in user folders)..."
  : > "$TMP/sizes.tsv"
  for r in "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents" "$HOME/Pictures" "$HOME/Movies"; do
    [ -d "$r" ] || continue
    find "$r" -type f -size +10M \
      \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/.venv/*" \) -prune -o \
      -type f -size +10M -print0 2>/dev/null |
      while IFS= read -r -d '' f; do printf '%s\t%s\n' "$(stat -f%z "$f")" "$f"; done >> "$TMP/sizes.tsv"
  done
  # sizes that occur more than once -> hash those files, group by hash
  cut -f1 "$TMP/sizes.tsv" | sort | uniq -d > "$TMP/dupsizes.txt"
  : > "$TMP/hashes.tsv"
  while IFS= read -r sz; do
    grep "^$sz	" "$TMP/sizes.tsv" | cut -f2 | while IFS= read -r f; do
      printf '%s\t%s\t%s\n' "$(md5 -q "$f" 2>/dev/null)" "$sz" "$f"
    done >> "$TMP/hashes.tsv"
  done < "$TMP/dupsizes.txt"
  # dupes.txt blocks: "SET <bytes>" then member paths
  cut -f1 "$TMP/hashes.tsv" | sort | uniq -d | while IFS= read -r h; do
    [ -z "$h" ] && continue
    sz=$(grep "^$h	" "$TMP/hashes.tsv" | head -1 | cut -f2)
    echo "SET	$sz" >> "$TMP/dupes.txt"
    grep "^$h	" "$TMP/hashes.tsv" | cut -f3 | sed 's/^/FILE	/' >> "$TMP/dupes.txt"
  done
fi

# ----------------------------------------------------------- 7. Dev bloat
step "Measuring dev bloat (node_modules, venvs, model caches)..."
: > "$TMP/devbloat.tsv"
for r in "$HOME/Documents" "$HOME/Desktop" "$HOME/Projects" "$HOME/dev" "$HOME/code"; do
  [ -d "$r" ] || continue
  find "$r" -maxdepth 6 -type d \( -name node_modules -o -name .venv -o -name venv \) -prune -print 2>/dev/null |
    grep -v "node_modules/.*node_modules" | while IFS= read -r d; do
      sz=$(kb "$d"); [ -n "$sz" ] && [ "$sz" -ge 20480 ] && printf '%s\t%s\n' "$sz" "$d"
    done >> "$TMP/devbloat.tsv"
done
sort -rn "$TMP/devbloat.tsv" -o "$TMP/devbloat.tsv"

: > "$TMP/devstores.tsv"
add_store() { # name path note
  local sz; [ -e "$2" ] || return 0
  sz=$(kb "$2"); [ -z "$sz" ] && sz=0
  [ "$sz" -ge 102400 ] && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$sz" "$3" >> "$TMP/devstores.tsv"
}
add_store "Docker Desktop data"  "$HOME/Library/Containers/com.docker.docker"  "docker system prune -a reclaims unused images; Docker.raw shrinks after"
add_store "OrbStack data"        "$HOME/.orbstack"                             "Prune unused containers/images"
add_store "Ollama models"        "$HOME/.ollama"                               "ollama rm <model>; re-pullable anytime"
add_store "HuggingFace cache"    "$HOME/.cache/huggingface"                    "Re-downloaded on demand"
add_store "Playwright browsers"  "$HOME/Library/Caches/ms-playwright"          "npx playwright install re-fetches"
add_store "Android SDK/AVD"      "$HOME/.android"                              "Delete unused emulator images via Android Studio"
add_store "Gradle cache"         "$HOME/.gradle"                               "Safe: gradle rebuilds"
add_store "CocoaPods cache"      "$HOME/Library/Caches/CocoaPods"              "Safe: pod install re-fetches"

# --------------------------------------------------------------- 8. Apps
step "Enumerating /Applications and categorizing..."
# apps.tsv: category TAB name TAB kb TAB reason
: > "$TMP/apps.tsv"
categorize_app() { # $1 = app name (no .app)
  case "$1" in
    MacKeeper*|CleanMyMac*|*McAfee*|Norton*|Avast*|AVG*|"Advanced Mac Cleaner"*|MacBooster*)
      echo "Unnecessary	Cleaner/AV bundleware - macOS + XProtect cover this; these add background load" ;;
    GarageBand|iMovie)
      echo "Review	Apple creative app - several GB each; remove if unused (reinstallable from App Store)" ;;
    Xcode) echo "Essential	Dev toolchain (also check DerivedData/DeviceSupport caches above)" ;;
    "Visual Studio Code"|Cursor|Docker|iTerm|Warp|Ghostty|IntelliJ*|PyCharm*|WebStorm*|Sublime*|Postman|TablePlus|Fork|GitHub*)
      echo "Essential	Development tool" ;;
    Safari|Mail|Messages|FaceTime|Photos|Notes|Calendar|Reminders|Music|TV|Podcasts|Maps|News|Stocks|Freeform|Pages|Numbers|Keynote)
      echo "Essential	Apple system/productivity app" ;;
    "Google Chrome"|Firefox|"Opera GX"|Opera|Brave*|"Microsoft Edge"|Arc|Vivaldi)
      echo "Occasional	Browser - consider keeping only one third-party browser" ;;
    Steam|"Epic Games Launcher"|"Riot Client"|VALORANT|"League of Legends"|Battle.net|GOG*)
      echo "Occasional	Game/launcher - uninstall finished titles (saves usually sync to cloud)" ;;
    Zoom*|Slack|Discord|Telegram|WhatsApp|Notion|Obsidian|Spotify|1Password*|Bitwarden)
      echo "Essential	Daily comms/productivity app" ;;
    "Microsoft Word"|"Microsoft Excel"|"Microsoft PowerPoint"|"Microsoft Outlook"|"Microsoft OneNote"|OneDrive)
      echo "Occasional	Microsoft 365 - keep the ones you actually open" ;;
    *) echo "Review	Unclassified - check if you still use it" ;;
  esac
}
if [ -d /Applications ]; then
  for app in /Applications/*.app; do
    [ -d "$app" ] || continue
    name=$(basename "$app" .app)
    sz=$(kb "$app"); [ -z "$sz" ] && sz=0
    result=$(categorize_app "$name")
    cat_part=${result%%	*}; why_part=${result#*	}
    printf '%s\t%s\t%s\t%s\n' "$cat_part" "$name" "$sz" "$why_part" >> "$TMP/apps.tsv"
  done
fi

# ------------------------------------------------------------- 9. Startup
step "Listing login items and launch agents..."
: > "$TMP/startup.tsv"
LOGIN_ITEMS=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
if [ -n "$LOGIN_ITEMS" ]; then
  echo "$LOGIN_ITEMS" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | while IFS= read -r li; do
    [ -n "$li" ] && printf 'Login item\t%s\tReview - disable in System Settings > General > Login Items if not needed at boot\n' "$li" >> "$TMP/startup.tsv"
  done
else
  printf 'Login items\t(list unavailable - grant Terminal automation permission or check System Settings > General > Login Items)\tReview manually\n' >> "$TMP/startup.tsv"
fi
for d in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  [ -d "$d" ] || continue
  for pl in "$d"/*.plist; do
    [ -e "$pl" ] || continue
    base=$(basename "$pl" .plist)
    verdict="Review - third-party background service"
    case "$base" in
      com.apple.*) continue ;;
      *mcafee*|*wondershare*|*mackeeper*|*norton*|*avast*) verdict="Disable/remove - junkware helper" ;;
      *adobe*|*creativecloud*) verdict="Disable if you rarely use Adobe apps" ;;
      *google*keystone*|*microsoft*update*) verdict="Keep - app auto-updater (small)" ;;
    esac
    printf 'LaunchAgent/Daemon\t%s\t%s\n' "$pl" "$verdict" >> "$TMP/startup.tsv"
  done
done

# ------------------------------------------------------ 10. Recommendations
step "Building tiered recommendations..."
# tier files: item TAB kb TAB path
: > "$TMP/t1.tsv"; : > "$TMP/t2.tsv"; : > "$TMP/t3.tsv"
while IFS=$(printf '\t') read -r name path skb verdict; do
  case "$name" in
    "User caches") echo "Clear user caches (keep apps closed)	$skb	$path" >> "$TMP/t1.tsv" ;;
    "User logs") echo "Clear user logs	$skb	$path" >> "$TMP/t1.tsv" ;;
    "Trash") echo "Empty Trash	$skb	$path" >> "$TMP/t1.tsv" ;;
    "Homebrew cache") echo "brew cleanup --prune=all	$skb	$path" >> "$TMP/t1.tsv" ;;
    "npm cache") echo "npm cache clean --force	$skb	$path" >> "$TMP/t1.tsv" ;;
    "pip cache") echo "pip cache purge	$skb	$path" >> "$TMP/t1.tsv" ;;
    "uv cache") echo "uv cache clean	$skb	$path" >> "$TMP/t1.tsv" ;;
    "Xcode DerivedData") echo "Delete Xcode DerivedData	$skb	$path" >> "$TMP/t1.tsv" ;;
    "iOS DeviceSupport") echo "Delete old iOS DeviceSupport folders	$skb	$path" >> "$TMP/t1.tsv" ;;
    "CoreSimulator caches") echo "Clear simulator caches	$skb	$path" >> "$TMP/t1.tsv" ;;
    "Mail downloads") echo "Clear Mail downloads	$skb	$path" >> "$TMP/t1.tsv" ;;
    "CoreSimulator devices") echo "xcrun simctl delete unavailable	$skb	$path" >> "$TMP/t2.tsv" ;;
    "Xcode Archives") echo "Review old Xcode archives	$skb	$path" >> "$TMP/t3.tsv" ;;
    "iOS device backups") echo "PERSONAL DATA: review old device backups	$skb	$path" >> "$TMP/t3.tsv" ;;
  esac
done < "$TMP/caches_sorted.tsv"
while IFS=$(printf '\t') read -r bytes d path; do
  skb=$(( bytes / 1024 ))
  echo "Delete old installer (app already installed?)	$skb	$path" >> "$TMP/t1.tsv"
done < "$TMP/installers.tsv"
# duplicate sets -> tier 1 (wasted = (count-1)*size)
awk -F'\t' '
  $1=="SET" { if (n>1) print items"\t"int(sz*(n-1)/1024); sz=$2; n=0; items=""; next }
  $1=="FILE" { n++; items = items ($2) " | " }
  END { if (n>1) print items"\t"int(sz*(n-1)/1024) }
' "$TMP/dupes.txt" 2>/dev/null | while IFS=$(printf '\t') read -r items wkb; do
  echo "Duplicate set - keep the first, delete the rest	$wkb	$items" >> "$TMP/t1.tsv"
done
while IFS=$(printf '\t') read -r skb path; do
  echo "Rebuildable dependency dir (npm/pip install restores)	$skb	$path" >> "$TMP/t2.tsv"
done < "$TMP/devbloat.tsv"
while IFS=$(printf '\t') read -r name path skb note; do
  echo "$name - $note	$skb	$path" >> "$TMP/t2.tsv"
done < "$TMP/devstores.tsv"
head -15 "$TMP/largefiles.tsv" | while IFS=$(printf '\t') read -r bytes d path; do
  case "$path" in *Docker.raw|*.vhdx) continue ;; esac
  echo "Large file (modified $d) - your call	$(( bytes / 1024 ))	$path" >> "$TMP/t3.tsv"
done
if [ "$TM_SNAPSHOTS" -gt 2 ]; then
  echo "Thin Time Machine local snapshots ($TM_SNAPSHOTS found): tmutil thinlocalsnapshots / 999999999999 4	0	/" >> "$TMP/t2.tsv"
fi
tier_total_gb() { awk -F'\t' '{s+=$2} END{printf "%.2f", s/1048576}' "$1"; }
T1_GB=$(tier_total_gb "$TMP/t1.tsv"); T2_GB=$(tier_total_gb "$TMP/t2.tsv"); T3_GB=$(tier_total_gb "$TMP/t3.tsv")

# ----------------------------------------------------- 11. AI cleanup prompt
step "Generating AI cleanup prompt..."
{
  echo "# Mac Cleanup Request (generated by pc-audit, $(date '+%Y-%m-%d %H:%M'))"
  echo
  echo "You are an AI agent with shell access to my Mac. Execute the cleanup plan below."
  echo
  echo "## Rules - read before acting"
  echo "1. Work tier by tier, in order. Before each tier, list exactly what you will delete and WAIT for my confirmation."
  echo "2. Never delete anything not listed here without asking me first."
  echo "3. Quote all paths; many contain spaces. Never run rm -rf on a variable that could be empty."
  echo "4. Prefer app-native cleanup commands (brew cleanup, npm cache clean, xcrun simctl, tmutil, docker system prune) over raw rm."
  echo "5. Never touch: source code, documents, photos, ~/Library/Keychains, browser profiles, or anything under /System."
  echo "6. For duplicate sets, keep the first file listed and delete the rest."
  echo "7. iOS device backups are personal data - list their dates first and let me choose."
  echo "8. Report free disk space (df -h /System/Volumes/Data) before starting, after each tier, and at the end."
  echo
  echo "## System snapshot"
  echo "- $OS_NAME, $RAM_GB GB RAM, $CPU"
  echo "- Data volume: $DISK_TOTAL_GB GB total, $DISK_FREE_GB GB free ($PCT_FREE%)"
  echo "- Time Machine local snapshots: $TM_SNAPSHOTS"
  echo
  echo "## Tier 1 - safe deletions (~$T1_GB GB)"
  while IFS=$(printf '\t') read -r item skb path; do
    echo "- [ ] $item | $(gb_of_kb "$skb") GB | $path"
  done < "$TMP/t1.tsv"
  echo
  echo "## Tier 2 - rebuildable, confirm I am not mid-project (~$T2_GB GB)"
  while IFS=$(printf '\t') read -r item skb path; do
    echo "- [ ] $item | $(gb_of_kb "$skb") GB | $path"
  done < "$TMP/t2.tsv"
  echo
  echo "## Tier 3 - big items, ask me one by one (~$T3_GB GB)"
  while IFS=$(printf '\t') read -r item skb path; do
    echo "- [ ] $item | $(gb_of_kb "$skb") GB | $path"
  done < "$TMP/t3.tsv"
  echo
  echo "## Apps flagged as unnecessary (drag to Trash or use the app's uninstaller)"
  grep "^Unnecessary" "$TMP/apps.tsv" | while IFS=$(printf '\t') read -r c name skb why; do
    echo "- [ ] $name ($(gb_of_kb "$skb") GB) - $why"
  done
  echo
  echo "## Background items to review (System Settings > General > Login Items)"
  while IFS=$(printf '\t') read -r kind name verdict; do
    case "$verdict" in Keep*) ;; *) echo "- [ ] $kind: $name - $verdict" ;; esac
  done < "$TMP/startup.tsv"
} > "$PROMPT"

# ------------------------------------------------------------- 12. Report
step "Writing HTML report..."
FREE_CLASS="ok"
LOW_SPACE=$(awk -v f="$DISK_FREE_KB" -v t="$DISK_TOTAL_KB" 'BEGIN{print (f/t < 0.15) ? 1 : 0}')
[ "$LOW_SPACE" -eq 1 ] && FREE_CLASS="danger"

cat > "$REPORT" <<'HTMLHEAD'
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mac Speed &amp; Storage Audit</title>
<style>
  :root { color-scheme: dark; }
  body { background:#101418; color:#d7dde3; font:14px/1.5 -apple-system,system-ui,sans-serif; max-width:1100px; margin:0 auto; padding:32px 24px; }
  h1 { font-size:24px; margin:0 0 4px; } h2 { font-size:18px; margin:36px 0 10px; border-bottom:1px solid #2a3138; padding-bottom:6px; }
  .muted { color:#8b96a1; } .danger { color:#ff7b72; } .ok { color:#7ee787; } .warn { color:#e3b341; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:20px 0; }
  .stat { border:1px solid #2a3138; border-radius:8px; padding:14px; }
  .stat .v { font-size:22px; font-weight:600; } .stat .l { color:#8b96a1; font-size:12px; margin-top:2px; }
  table { border-collapse:collapse; width:100%; margin:8px 0 16px; font-size:13px; }
  th,td { text-align:left; padding:6px 10px; border-bottom:1px solid #232a31; vertical-align:top; word-break:break-word; }
  th { color:#8b96a1; font-weight:600; font-size:12px; }
  pre#prompt { background:#161b21; border:1px solid #2a3138; border-radius:8px; padding:16px; white-space:pre-wrap; font-size:12.5px; max-height:480px; overflow:auto; }
  button { background:#2f81f7; color:#fff; border:0; border-radius:6px; padding:8px 14px; font-size:13px; cursor:pointer; }
  button:hover { background:#4593f8; }
  details { margin:8px 0; } summary { cursor:pointer; color:#8b96a1; }
  .callout { border:1px solid #2a3138; border-left:3px solid #e3b341; border-radius:6px; padding:10px 14px; margin:12px 0; }
</style></head><body>
HTMLHEAD

{
  echo "<h1>Mac Speed &amp; Storage Audit</h1>"
  echo "<p class='muted'>$(echo "$OS_NAME · $RAM_GB GB RAM · $CPU" | esc) · generated $(date '+%Y-%m-%d %H:%M') · read-only scan, nothing was changed</p>"
  echo "<div class='stats'>"
  echo "<div class='stat'><div class='v $FREE_CLASS'>$DISK_FREE_GB GB</div><div class='l'>free of $DISK_TOTAL_GB GB ($PCT_FREE%)</div></div>"
  echo "<div class='stat'><div class='v ok'>~$T1_GB GB</div><div class='l'>Tier 1: safe reclaim</div></div>"
  echo "<div class='stat'><div class='v'>~$T2_GB GB</div><div class='l'>Tier 2: rebuildable</div></div>"
  echo "<div class='stat'><div class='v warn'>~$T3_GB GB</div><div class='l'>Tier 3: your call</div></div>"
  echo "</div>"
  [ "$LOW_SPACE" -eq 1 ] && echo "<div class='callout'><b>Disk pressure:</b> below ~15% free space macOS slows down (swap, snapshots, APFS). Prioritize Tier 1.</div>"
  [ "$TM_SNAPSHOTS" -gt 2 ] && echo "<div class='callout'><b>$TM_SNAPSHOTS Time Machine local snapshots</b> exist - they silently hold deleted space. tmutil thinlocalsnapshots reclaims it.</div>"

  echo "<h2>Where the space goes</h2><table><thead><tr><th>Folder</th><th>Size (GB)</th><th>Area</th></tr></thead><tbody>"
  head -40 "$TMP/folders_sorted.tsv" | while IFS=$(printf '\t') read -r grp path skb; do
    echo "<tr><td>$(echo "$path" | esc)</td><td>$(gb_of_kb "$skb")</td><td>$(echo "$grp" | esc)</td></tr>"
  done
  echo "</tbody></table>"

  echo "<h2>Caches &amp; known bloat</h2><table><thead><tr><th>Location</th><th>Size (GB)</th><th>Verdict</th><th>Path</th></tr></thead><tbody>"
  while IFS=$(printf '\t') read -r name path skb verdict; do
    echo "<tr><td>$(echo "$name" | esc)</td><td>$(gb_of_kb "$skb")</td><td>$(echo "$verdict" | esc)</td><td>$(echo "$path" | esc)</td></tr>"
  done < "$TMP/caches_sorted.tsv"
  echo "</tbody></table>"

  if [ -s "$TMP/largefiles.tsv" ]; then
    echo "<h2>Largest files</h2><table><thead><tr><th>File</th><th>Size (GB)</th><th>Modified</th></tr></thead><tbody>"
    while IFS=$(printf '\t') read -r bytes d path; do
      echo "<tr><td>$(echo "$path" | esc)</td><td>$(gb_of_bytes "$bytes")</td><td>$d</td></tr>"
    done < "$TMP/largefiles.tsv"
    echo "</tbody></table>"
  fi

  if [ -s "$TMP/installers.tsv" ]; then
    echo "<h2>Old installers</h2><table><thead><tr><th>Installer</th><th>Size (MB)</th><th>Modified</th></tr></thead><tbody>"
    while IFS=$(printf '\t') read -r bytes d path; do
      echo "<tr><td>$(echo "$path" | esc)</td><td>$(mb_of_bytes "$bytes")</td><td>$d</td></tr>"
    done < "$TMP/installers.tsv"
    echo "</tbody></table>"
  fi

  if [ -s "$TMP/dupes.txt" ]; then
    echo "<h2>Duplicate files (hash-verified)</h2><table><thead><tr><th>Each (MB)</th><th>Files</th></tr></thead><tbody>"
    awk -F'\t' '
      $1=="SET" { if (files!="") printf "<tr><td>%.1f</td><td>%s</td></tr>\n", sz/1048576, files; sz=$2; files=""; next }
      $1=="FILE" { gsub(/&/,"\\&amp;",$2); gsub(/</,"\\&lt;",$2); files = files $2 "<br>" }
      END { if (files!="") printf "<tr><td>%.1f</td><td>%s</td></tr>\n", sz/1048576, files }
    ' "$TMP/dupes.txt"
    echo "</tbody></table>"
  fi

  if [ -s "$TMP/devbloat.tsv" ] || [ -s "$TMP/devstores.tsv" ]; then
    echo "<h2>Dev bloat (rebuildable)</h2>"
    if [ -s "$TMP/devbloat.tsv" ]; then
      echo "<table><thead><tr><th>Dependency folder</th><th>Size (MB)</th></tr></thead><tbody>"
      while IFS=$(printf '\t') read -r skb path; do
        echo "<tr><td>$(echo "$path" | esc)</td><td>$(mb_of_kb "$skb")</td></tr>"
      done < "$TMP/devbloat.tsv"
      echo "</tbody></table>"
    fi
    if [ -s "$TMP/devstores.tsv" ]; then
      echo "<table><thead><tr><th>Store</th><th>Size (GB)</th><th>Note</th></tr></thead><tbody>"
      while IFS=$(printf '\t') read -r name path skb note; do
        echo "<tr><td>$(echo "$name - $path" | esc)</td><td>$(gb_of_kb "$skb")</td><td>$(echo "$note" | esc)</td></tr>"
      done < "$TMP/devstores.tsv"
      echo "</tbody></table>"
    fi
  fi

  echo "<h2>Applications (/Applications)</h2>"
  for cat_name in Unnecessary Occasional Essential Review; do
    n=$(grep -c "^$cat_name	" "$TMP/apps.tsv" 2>/dev/null || echo 0)
    [ "$n" -eq 0 ] && continue
    open_attr=""; [ "$cat_name" = "Unnecessary" ] && open_attr=" open"
    echo "<details$open_attr><summary>$cat_name ($n)</summary><table><thead><tr><th>App</th><th>Size (GB)</th><th>Why</th></tr></thead><tbody>"
    grep "^$cat_name	" "$TMP/apps.tsv" | sort -t"$(printf '\t')" -k3 -rn | while IFS=$(printf '\t') read -r c name skb why; do
      echo "<tr><td>$(echo "$name" | esc)</td><td>$(gb_of_kb "$skb")</td><td>$(echo "$why" | esc)</td></tr>"
    done
    echo "</tbody></table></details>"
  done

  echo "<h2>Login items &amp; background services</h2><table><thead><tr><th>Type</th><th>Item</th><th>Verdict</th></tr></thead><tbody>"
  while IFS=$(printf '\t') read -r kind name verdict; do
    echo "<tr><td>$(echo "$kind" | esc)</td><td>$(echo "$name" | esc)</td><td>$(echo "$verdict" | esc)</td></tr>"
  done < "$TMP/startup.tsv"
  echo "</tbody></table>"

  echo "<h2>AI cleanup prompt</h2>"
  echo "<p class='muted'>Paste this into any AI agent with shell access (Cursor, Claude Code, Codex CLI...). Also saved as cleanup-prompt.md next to this report.</p>"
  echo "<button onclick=\"navigator.clipboard.writeText(document.getElementById('prompt').textContent).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy prompt',1500)})\">Copy prompt</button>"
  echo "<pre id='prompt'>$(esc < "$PROMPT")</pre>"
  ELAPSED_MIN=$(awk -v s=$(( $(date +%s) - START_TS )) 'BEGIN{printf "%.1f", s/60}')
  echo "<p class='muted'>pc-audit · scan took $ELAPSED_MIN min · read-only: this tool never deletes anything.</p>"
  echo "</body></html>"
} >> "$REPORT"

# data.json (best effort, requires python3)
if command -v python3 >/dev/null 2>&1; then
  python3 - "$TMP" "$REPORT_DIR/data.json" <<'PYEOF'
import csv, json, os, sys
tmp, out = sys.argv[1], sys.argv[2]
def tsv(name, cols):
    path = os.path.join(tmp, name)
    rows = []
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for r in csv.reader(f, delimiter="\t"):
                if r:
                    rows.append(dict(zip(cols, r)))
    return rows
data = {
    "folders": tsv("folders_sorted.tsv", ["group", "path", "kb"]),
    "caches": tsv("caches_sorted.tsv", ["name", "path", "kb", "verdict"]),
    "largeFiles": tsv("largefiles.tsv", ["bytes", "modified", "path"]),
    "installers": tsv("installers.tsv", ["bytes", "modified", "path"]),
    "devBloat": tsv("devbloat.tsv", ["kb", "path"]),
    "devStores": tsv("devstores.tsv", ["name", "path", "kb", "note"]),
    "apps": tsv("apps.tsv", ["category", "name", "kb", "reason"]),
    "startup": tsv("startup.tsv", ["kind", "name", "verdict"]),
    "tier1": tsv("t1.tsv", ["item", "kb", "path"]),
    "tier2": tsv("t2.tsv", ["item", "kb", "path"]),
    "tier3": tsv("t3.tsv", ["item", "kb", "path"]),
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=1)
PYEOF
fi

ELAPSED_MIN=$(awk -v s=$(( $(date +%s) - START_TS )) 'BEGIN{printf "%.1f", s/60}')
echo
echo "============================================="
echo " Audit complete in $ELAPSED_MIN min (read-only, nothing deleted)"
echo "   Tier 1 safe reclaim : ~$T1_GB GB"
echo "   Tier 2 rebuildable  : ~$T2_GB GB"
echo "   Tier 3 your call    : ~$T3_GB GB"
echo "   Report : $REPORT"
echo "   Prompt : $PROMPT"
echo "============================================="
[ "$NO_BROWSER" -eq 0 ] && open "$REPORT" 2>/dev/null
exit 0
