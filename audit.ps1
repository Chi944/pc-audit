<#
.SYNOPSIS
    pc-audit: read-only speed & storage audit for Windows.

.DESCRIPTION
    Scans the machine (never deletes anything) and produces:
      - report.html         rich audit report (opens in browser)
      - cleanup-prompt.md   a ready-to-paste prompt for any AI agent with shell access
      - data.json           raw findings for programmatic use

    Mirrors a manual audit workflow:
      1. Detect OS + disk health/free space
      2. Inventory largest directories and files
      3. Measure known cache/temp/bloat locations
      4. Find old installers and hash-verified duplicate files
      5. Find dev bloat (node_modules, venvs, WSL disks, model caches)
      6. Categorize installed apps (essential / occasional / unnecessary)
      7. List startup programs with disable/keep verdicts
      8. Build tiered deletion recommendations + AI cleanup prompt

.PARAMETER Quick
    Skip whole-drive scans; only scan the user profile (much faster).

.PARAMETER SkipDuplicates
    Skip the duplicate-file hashing pass.

.PARAMETER NoBrowser
    Do not auto-open the HTML report.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\audit.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [switch]$Quick,
    [switch]$SkipDuplicates,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'SilentlyContinue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$UserHome = $env:USERPROFILE
$SysDrive = $env:SystemDrive
if (-not $OutputDir) {
    if ($PSScriptRoot) { $OutputDir = Join-Path $PSScriptRoot 'reports' }
    else { $OutputDir = Join-Path $UserHome 'pc-audit-reports' }
}
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$ReportDir = Join-Path $OutputDir $stamp
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

function Write-Step([string]$msg) {
    Write-Host ("[{0,4}s] {1}" -f [math]::Round($sw.Elapsed.TotalSeconds), $msg) -ForegroundColor Cyan
}
function GB([long]$b) { [math]::Round($b / 1GB, 2) }
function MB([long]$b) { [math]::Round($b / 1MB, 1) }

$DefaultSkipDirs = @('node_modules', '.git', '.venv', 'venv', '__pycache__', '$RECYCLE.BIN', 'System Volume Information')

# Iterative walker: sums sizes and optionally collects files above a threshold.
# Skips reparse points (junctions/OneDrive placeholders) to avoid loops and double counting.
function Invoke-Walk {
    param(
        [string]$Root,
        [long]$CollectMinBytes = [long]::MaxValue,
        [string[]]$SkipDirNames = @('$RECYCLE.BIN', 'System Volume Information'),
        [string[]]$Extensions
    )
    $files = [System.Collections.Generic.List[object]]::new()
    [long]$total = 0
    if (-not (Test-Path -LiteralPath $Root)) {
        return [PSCustomObject]@{ Bytes = 0; Files = $files }
    }
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                try {
                    $fi = [System.IO.FileInfo]::new($f)
                    $total += $fi.Length
                    if ($fi.Length -ge $CollectMinBytes) {
                        if (-not $Extensions -or $Extensions -contains $fi.Extension.ToLower()) {
                            $files.Add($fi)
                        }
                    }
                } catch { }
            }
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                try {
                    $di = [System.IO.DirectoryInfo]::new($d)
                    if ($di.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { continue }
                    if ($SkipDirNames -contains $di.Name) { continue }
                    $stack.Push($d)
                } catch { }
            }
        } catch { }
    }
    return [PSCustomObject]@{ Bytes = $total; Files = $files }
}

function Get-DirSize([string]$Path, [string[]]$SkipDirNames = @('$RECYCLE.BIN', 'System Volume Information')) {
    (Invoke-Walk -Root $Path -SkipDirNames $SkipDirNames).Bytes
}

# ---------------------------------------------------------------- 1. System
Write-Step 'Detecting OS, RAM, disks...'
$os = Get-CimInstance Win32_OperatingSystem
$disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'
$physical = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, Size
$sysDisk = $disks | Where-Object DeviceID -eq $SysDrive
$system = [PSCustomObject]@{
    OS          = $os.Caption
    Version     = $os.Version
    Arch        = $os.OSArchitecture
    RAM_GB      = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    LastBoot    = $os.LastBootUpTime
    Disks       = @($disks | ForEach-Object {
        [PSCustomObject]@{
            Drive   = $_.DeviceID
            Size_GB = GB $_.Size
            Free_GB = GB $_.FreeSpace
            PctFree = [math]::Round(100 * $_.FreeSpace / $_.Size, 1)
        }
    })
    Physical    = @($physical | ForEach-Object {
        [PSCustomObject]@{ Name = $_.FriendlyName; Media = "$($_.MediaType)"; Health = "$($_.HealthStatus)"; Size_GB = GB $_.Size }
    })
}

# ---------------------------------------------------------- 2. Folder sizes
$folderScan = [System.Collections.Generic.List[object]]::new()
function Add-FolderSizes([string]$Parent, [string]$Label, [double]$MinGB = 0.1) {
    foreach ($d in (Get-ChildItem -LiteralPath $Parent -Directory -Force)) {
        $bytes = Get-DirSize $d.FullName
        if ($bytes / 1GB -ge $MinGB) {
            $folderScan.Add([PSCustomObject]@{ Group = $Label; Path = $d.FullName; Size_GB = GB $bytes; Bytes = $bytes })
        }
    }
}
if (-not $Quick) {
    Write-Step "Measuring top-level folders on $SysDrive\ (slowest step, can take several minutes)..."
    Add-FolderSizes "$SysDrive\" 'Drive root'
}
Write-Step 'Measuring user profile folders...'
Add-FolderSizes $UserHome 'User profile' 0.05
foreach ($sub in @('AppData\Local', 'AppData\Roaming', 'AppData\LocalLow', 'Desktop', 'Documents', 'Downloads')) {
    $p = Join-Path $UserHome $sub
    if (Test-Path $p) { Add-FolderSizes $p $sub 0.05 }
}
$folderScan = $folderScan | Sort-Object Bytes -Descending

# Loose files at drive root (pagefile, hiberfil, stray logs)
$rootFiles = @(Get-ChildItem "$SysDrive\" -File -Force | Where-Object Length -gt 50MB |
    Sort-Object Length -Descending |
    ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; Size_GB = GB $_.Length; Bytes = $_.Length } })

# ------------------------------------------------------------- 3. Caches
Write-Step 'Measuring cache / temp / known bloat locations...'
$cacheDefs = @(
    @{ Name = 'User temp';                Path = $env:TEMP;                                              Verdict = 'Safe to clear (skip locked files)' }
    @{ Name = 'Windows temp';             Path = "$env:WINDIR\Temp";                                     Verdict = 'Safe to clear (needs admin)' }
    @{ Name = 'Windows Update cache';     Path = "$env:WINDIR\SoftwareDistribution\Download";            Verdict = 'Safe to clear (needs admin)' }
    @{ Name = 'Windows Installer cache';  Path = "$env:WINDIR\Installer";                                Verdict = 'Do NOT delete manually - use Disk Cleanup' }
    @{ Name = 'WinSxS component store';   Path = "$env:WINDIR\WinSxS";                                   Verdict = 'Do NOT delete manually - use DISM StartComponentCleanup' }
    @{ Name = 'npm cache';                Path = "$env:LOCALAPPDATA\npm-cache";                          Verdict = 'Safe: npm cache clean --force' }
    @{ Name = 'pip cache';                Path = "$env:LOCALAPPDATA\pip";                                Verdict = 'Safe: pip cache purge' }
    @{ Name = 'uv cache';                 Path = "$env:LOCALAPPDATA\uv";                                 Verdict = 'Safe: uv cache clean (close IDEs first)' }
    @{ Name = 'NVIDIA driver downloads';  Path = "$env:ProgramData\NVIDIA Corporation\Downloader";       Verdict = 'Safe to clear' }
    @{ Name = 'Recycle Bin';              Path = "$SysDrive\`$Recycle.Bin";                              Verdict = 'Safe: Clear-RecycleBin -Force' }
    @{ Name = 'Hibernation file';         Path = "$SysDrive\hiberfil.sys";                               Verdict = 'Safe on desktops: powercfg /h off (admin)' }
    @{ Name = 'Page file';                Path = "$SysDrive\pagefile.sys";                               Verdict = 'Leave alone - system managed' }
)
$caches = foreach ($c in $cacheDefs) {
    $bytes = 0
    if (Test-Path -LiteralPath $c.Path -PathType Leaf) { $bytes = (Get-Item -LiteralPath $c.Path -Force).Length }
    elseif (Test-Path -LiteralPath $c.Path) { $bytes = Get-DirSize $c.Path }
    if ($bytes -gt 10MB) {
        [PSCustomObject]@{ Name = $c.Name; Path = $c.Path; Size_GB = GB $bytes; Bytes = $bytes; Verdict = $c.Verdict }
    }
}
$caches = @($caches | Sort-Object Bytes -Descending)

# --------------------------------------------------------- 4. Large files
Write-Step 'Finding largest files...'
$largeRoot = if ($Quick) { $UserHome } else { "$SysDrive\" }
$largeSkip = $DefaultSkipDirs + @('WinSxS', 'Installer', 'wsl')
$largeFiles = @((Invoke-Walk -Root $largeRoot -CollectMinBytes 300MB -SkipDirNames $largeSkip).Files |
    Sort-Object Length -Descending | Select-Object -First 40 |
    ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; Size_GB = GB $_.Length; Bytes = $_.Length; Modified = $_.LastWriteTime.ToString('yyyy-MM-dd') } })

# ---------------------------------------------------------- 5. Installers
Write-Step 'Finding old installers...'
$installerRoots = @("$UserHome\Downloads", "$UserHome\Desktop", "$UserHome\Documents") | Where-Object { Test-Path $_ }
$installers = @($(foreach ($r in $installerRoots) {
    (Invoke-Walk -Root $r -CollectMinBytes 5MB -SkipDirNames $DefaultSkipDirs -Extensions @('.exe', '.msi', '.iso', '.dmg')).Files
}) | Sort-Object Length -Descending |
    ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; Size_MB = MB $_.Length; Bytes = $_.Length; Modified = $_.LastWriteTime.ToString('yyyy-MM-dd') } })

# ---------------------------------------------------------- 6. Duplicates
$duplicates = @()
if (-not $SkipDuplicates) {
    Write-Step 'Hashing candidate duplicate files (>10 MB in user folders)...'
    $dupRoots = @("$UserHome\Downloads", "$UserHome\Desktop", "$UserHome\Documents", "$UserHome\Pictures", "$UserHome\Videos") | Where-Object { Test-Path $_ }
    $candidates = foreach ($r in $dupRoots) {
        (Invoke-Walk -Root $r -CollectMinBytes 10MB -SkipDirNames $DefaultSkipDirs).Files
    }
    $sizeGroups = $candidates | Group-Object Length | Where-Object Count -gt 1
    $duplicates = @(foreach ($g in $sizeGroups) {
        $hashed = foreach ($fi in $g.Group) {
            $h = Get-FileHash -LiteralPath $fi.FullName -Algorithm MD5
            if ($h) { [PSCustomObject]@{ File = $fi; Hash = $h.Hash } }
        }
        foreach ($hg in ($hashed | Group-Object Hash | Where-Object Count -gt 1)) {
            $wasted = ($hg.Count - 1) * $hg.Group[0].File.Length
            [PSCustomObject]@{
                Size_MB   = MB $hg.Group[0].File.Length
                Wasted    = $wasted
                Wasted_MB = MB $wasted
                Files     = @($hg.Group | ForEach-Object { $_.File.FullName })
            }
        }
    })
}

# ----------------------------------------------------------- 7. Dev bloat
Write-Step 'Measuring dev bloat (node_modules, venvs, WSL, model caches)...'
function Find-NamedDirs([string]$Root, [string[]]$Names, [int]$MaxDepth = 6) {
    $found = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path $Root)) { return $found }
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $dir = $item[0]; $depth = [int]$item[1]
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                $di = [System.IO.DirectoryInfo]::new($d)
                if ($di.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { continue }
                if ($Names -contains $di.Name) { $found.Add($d); continue }  # don't descend into matches
                if ($di.Name -in @('.git', 'AppData', 'Windows')) { continue }
                if ($depth -lt $MaxDepth) { $stack.Push(@($d, $depth + 1)) }
            }
        } catch { }
    }
    return $found
}
$nmDirs = @()
$nmDirs += Find-NamedDirs "$UserHome\Documents" @('node_modules', '.venv', 'venv')
$nmDirs += Find-NamedDirs "$UserHome\Desktop" @('node_modules', '.venv', 'venv')
$devBloat = @($nmDirs | ForEach-Object {
    $bytes = Get-DirSize $_
    if ($bytes -gt 20MB) { [PSCustomObject]@{ Path = $_; Size_MB = MB $bytes; Bytes = $bytes } }
} | Sort-Object Bytes -Descending)

$extraDefs = @(
    @{ Name = 'WSL virtual disks';        Path = "$env:LOCALAPPDATA\wsl";                    Note = 'Check usage inside distro before compacting; only free space compacts' }
    @{ Name = 'Docker Desktop data';      Path = "$env:LOCALAPPDATA\Docker";                 Note = 'docker system prune -a reclaims unused images' }
    @{ Name = 'Ollama models';            Path = "$UserHome\.ollama";                        Note = 'ollama rm <model>; re-pullable anytime' }
    @{ Name = 'Claude Desktop VM bundles'; Path = "$env:APPDATA\Claude\vm_bundles";          Note = 'Re-downloaded on demand' }
    @{ Name = 'HuggingFace cache';        Path = "$UserHome\.cache\huggingface";             Note = 'Re-downloaded on demand' }
    @{ Name = 'Playwright browsers';      Path = "$env:LOCALAPPDATA\ms-playwright";          Note = 'npx playwright install re-fetches' }
)
$devExtra = @($(foreach ($e in $extraDefs) {
    if (Test-Path $e.Path) {
        $bytes = Get-DirSize $e.Path
        if ($bytes -gt 100MB) { [PSCustomObject]@{ Name = $e.Name; Path = $e.Path; Size_GB = GB $bytes; Bytes = $bytes; Note = $e.Note } }
    }
}) | Sort-Object Bytes -Descending)

# --------------------------------------------------------------- 8. Apps
Write-Step 'Enumerating and categorizing installed applications...'
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$rawApps = Get-ItemProperty $regPaths | Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
    Sort-Object DisplayName -Unique

$junkPatterns      = 'McAfee Security Scan|Wondershare|Razer Cortex|WildTangent|Driver Booster|Web Companion|Toolbar|WeatherBug|Search App by Ask'
$overlayPatterns   = 'Overwolf|Outplayed|^BUFF$|Tracker$|Palworld Map|Buff Achievement'
$oldRuntimePattern = 'Java [5-8] Update|Java\(TM\) [5-8]'
$driverPatterns    = 'NVIDIA|Realtek|Intel\(R\)|AMD |Visual C\+\+.*Redistributable|WebView2|Microsoft Edge$|\.NET|Windows Subsystem|ASUS|AURA|ROG |Synaptics|Dolby|THX|Killer|Chipset|Microsoft Update Health|Microsoft GameInput'
$osPatterns        = 'Microsoft 365|Microsoft OneDrive|Office 16|Microsoft Teams|Copilot'
$devPatterns       = '^Git$|Node\.js|^GitHub CLI$|Docker Desktop|Visual Studio Code|Cursor|^uv$|^Bun$|FFmpeg|Pandoc|Typst|RipGrep|Windows Terminal|PowerShell 7|Obsidian|Notion|MySQL|PostgreSQL|MongoDB'
$gamePatterns      = '^Steam$|VALORANT|Riot|Epic Games|GOG|Battle\.net|Xbox|Palworld$|It Takes Two|Ubisoft'
$browserPatterns   = 'Google Chrome|Firefox|Opera|Brave|Vivaldi'
$sdkPatterns       = 'Windows SDK|Windows Software Development Kit|Visual Studio Build Tools|Windows App Certification|WinRT Intellisense|Universal CRT|vs_|vcpp_|Windows Team Extension|Windows Desktop Extension|Windows IoT Extension|Windows Mobile Extension|Kits Configuration'

$pythonApps = @($rawApps | Where-Object { $_.DisplayName -match '^Python \d|Anaconda' })
$newestPython = ($pythonApps | ForEach-Object {
    if ($_.DisplayName -match 'Python (\d+)\.(\d+)') { [version]"$($Matches[1]).$($Matches[2])" }
} | Sort-Object -Descending | Select-Object -First 1)

$apps = @($(foreach ($a in $rawApps) {
    $n = $a.DisplayName
    $sizeMB = 0; if ($a.EstimatedSize) { $sizeMB = [math]::Round($a.EstimatedSize / 1024, 0) }
    $cat = 'Review'; $why = 'Unclassified - check if you still use it'
    if     ($n -match $junkPatterns)      { $cat = 'Unnecessary'; $why = 'Bundleware / background junk with no real benefit' }
    elseif ($n -match $overlayPatterns)   { $cat = 'Unnecessary'; $why = 'Game overlay/tracker app - heavy background load, auto-records clips' }
    elseif ($n -match $oldRuntimePattern) { $cat = 'Unnecessary'; $why = 'Outdated runtime and a security liability; modern apps bundle their own' }
    elseif ($n -match $sdkPatterns)       { $cat = 'Review';      $why = 'Dev SDK/build tooling - remove if you do not compile native code' }
    elseif ($n -match $driverPatterns)    { $cat = 'Essential';   $why = 'Driver / OS runtime' }
    elseif ($n -match $osPatterns)        { $cat = 'Essential';   $why = 'OS-integrated Microsoft component' }
    elseif ($n -match $devPatterns)       { $cat = 'Essential';   $why = 'Development / productivity tool' }
    elseif ($n -match $gamePatterns)      { $cat = 'Occasional';  $why = 'Game/launcher - uninstall largest titles you finished (saves stay in cloud)' }
    elseif ($n -match $browserPatterns)   { $cat = 'Occasional';  $why = 'Browser - consider keeping only one third-party browser' }
    elseif ($n -match '^Python \d|Anaconda') {
        if ($n -match 'Anaconda') { $cat = 'Unnecessary'; $why = 'Superseded if you use a newer Python + package manager' }
        elseif ($n -match 'Python (\d+)\.(\d+)' -and $newestPython -and ([version]"$($Matches[1]).$($Matches[2])" -lt $newestPython)) {
            $cat = 'Unnecessary'; $why = "Older Python (newest installed: $newestPython)"
        } else { $cat = 'Essential'; $why = 'Current Python runtime' }
    }
    [PSCustomObject]@{ Name = $n; Version = "$($a.DisplayVersion)"; Publisher = "$($a.Publisher)"; Size_MB = $sizeMB; Category = $cat; Reason = $why }
}) | Sort-Object @{e = 'Category' }, @{e = 'Size_MB'; Descending = $true })

# -------------------------------------------------------------- 9. Startup
Write-Step 'Listing startup programs...'
$startupDisable = 'Steam|Riot|Overwolf|Cortex|Opera|EdgeAutoLaunch|MicrosoftEdgeAutoLaunch|McAfee|Wondershare|UniConverter|Adobe.*Sync|CollabSync|Notion|Discord|Docker|Spotify|Epic'
$startupKeep    = 'SecurityHealth|Rtk|Realtek|OneDrive|Vanguard|Audio|Synaptics|IntelliType|IntelliPoint'
$startup = @(Get-CimInstance Win32_StartupCommand | ForEach-Object {
    $v = 'Review'
    if ($_.Name -match $startupDisable -or $_.Command -match $startupDisable) { $v = 'Disable - launch manually when needed' }
    elseif ($_.Name -match $startupKeep -or $_.Command -match $startupKeep) { $v = 'Keep (security/driver/sync)' }
    [PSCustomObject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; Verdict = $v }
})

# ------------------------------------------------------ 10. Recommendations
Write-Step 'Building tiered recommendations...'
$tier1 = [System.Collections.Generic.List[object]]::new()
$tier2 = [System.Collections.Generic.List[object]]::new()
$tier3 = [System.Collections.Generic.List[object]]::new()

foreach ($c in $caches) {
    switch -Regex ($c.Name) {
        'Hibernation'          { $tier1.Add([PSCustomObject]@{ Item = 'Disable hibernation (powercfg /h off, admin)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'npm cache'            { $tier1.Add([PSCustomObject]@{ Item = 'Clear npm cache (npm cache clean --force)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'pip cache'            { $tier1.Add([PSCustomObject]@{ Item = 'Clear pip cache (pip cache purge)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'uv cache'             { $tier1.Add([PSCustomObject]@{ Item = 'Clear uv cache (uv cache clean)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'User temp'            { $tier1.Add([PSCustomObject]@{ Item = 'Clear user temp (locked files remain)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'Windows temp'         { $tier1.Add([PSCustomObject]@{ Item = 'Clear Windows temp (admin)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'Update cache'         { $tier1.Add([PSCustomObject]@{ Item = 'Clear Windows Update cache (admin)'; Path = $c.Path; Bytes = $c.Bytes }) }
        'NVIDIA'               { $tier1.Add([PSCustomObject]@{ Item = 'Clear NVIDIA driver download cache'; Path = $c.Path; Bytes = $c.Bytes }) }
        'Recycle'              { $tier1.Add([PSCustomObject]@{ Item = 'Empty Recycle Bin'; Path = $c.Path; Bytes = $c.Bytes }) }
    }
}
foreach ($i in ($installers | Where-Object { $_.Path -match '\\Downloads\\' })) {
    $tier1.Add([PSCustomObject]@{ Item = 'Delete old installer'; Path = $i.Path; Bytes = $i.Bytes })
}
foreach ($d in $duplicates) {
    $tier1.Add([PSCustomObject]@{ Item = "Duplicate set - keep 1 of $($d.Files.Count)"; Path = ($d.Files -join ' | '); Bytes = $d.Wasted })
}
foreach ($n in $devBloat) { $tier2.Add([PSCustomObject]@{ Item = 'Rebuildable dependency dir (npm install / pip install restores)'; Path = $n.Path; Bytes = $n.Bytes }) }
foreach ($e in $devExtra) { $tier2.Add([PSCustomObject]@{ Item = "$($e.Name) - $($e.Note)"; Path = $e.Path; Bytes = $e.Bytes }) }
foreach ($f in ($largeFiles | Where-Object { $_.Path -notmatch 'pagefile|hiberfil|swapfile|ext4\.vhdx|docker_data' } | Select-Object -First 15)) {
    $tier3.Add([PSCustomObject]@{ Item = "Large file (modified $($f.Modified)) - your call"; Path = $f.Path; Bytes = $f.Bytes })
}
foreach ($g in ($folderScan | Where-Object { $_.Path -match 'steamapps\\common|Riot Games|Epic Games' -and $_.Bytes -gt 5GB })) {
    $tier3.Add([PSCustomObject]@{ Item = 'Installed game - uninstall via launcher if finished'; Path = $g.Path; Bytes = $g.Bytes })
}
function TierTotal($t) { GB (($t | Measure-Object Bytes -Sum).Sum) }
$t1GB = TierTotal $tier1; $t2GB = TierTotal $tier2; $t3GB = TierTotal $tier3

$uninstallApps = @($apps | Where-Object Category -eq 'Unnecessary')
$disableStartup = @($startup | Where-Object Verdict -match '^Disable')

# ----------------------------------------------------- 11. AI cleanup prompt
Write-Step 'Generating AI cleanup prompt...'
$sysD = $system.Disks | Where-Object Drive -eq $SysDrive
$p = [System.Text.StringBuilder]::new()
[void]$p.AppendLine("# PC Cleanup Request (generated by pc-audit, $(Get-Date -Format 'yyyy-MM-dd HH:mm'))")
[void]$p.AppendLine()
[void]$p.AppendLine('You are an AI agent with shell access to my Windows machine. Execute the cleanup plan below.')
[void]$p.AppendLine()
[void]$p.AppendLine('## Rules - read before acting')
[void]$p.AppendLine('1. Work tier by tier, in order. Before each tier, list exactly what you will delete and WAIT for my confirmation.')
[void]$p.AppendLine('2. Never delete anything not listed here without asking me first.')
[void]$p.AppendLine('3. Skip locked/in-use files gracefully (-ErrorAction SilentlyContinue); report skips, do not force or reboot.')
[void]$p.AppendLine('4. Some steps need an elevated shell: powercfg /h off, Windows temp, Windows Update cache.')
[void]$p.AppendLine('5. Never touch: source code, documents, .ssh, browser profiles, or anything under C:\Windows other than the named caches.')
[void]$p.AppendLine('6. For duplicate sets, keep the first file listed and delete the rest.')
[void]$p.AppendLine('7. For games, uninstall through the launcher (Steam/Riot) so saves and manifests stay consistent.')
[void]$p.AppendLine('8. Report drive free space before starting, after each tier, and at the end.')
[void]$p.AppendLine()
[void]$p.AppendLine('## System snapshot')
[void]$p.AppendLine("- $($system.OS) $($system.Version), $($system.RAM_GB) GB RAM")
[void]$p.AppendLine("- $SysDrive $($sysD.Size_GB) GB total, $($sysD.Free_GB) GB free ($($sysD.PctFree)%)")
[void]$p.AppendLine()
[void]$p.AppendLine("## Tier 1 - safe deletions (~$t1GB GB)")
foreach ($i in $tier1) { [void]$p.AppendLine("- [ ] $($i.Item) | $(GB $i.Bytes) GB | $($i.Path)") }
[void]$p.AppendLine()
[void]$p.AppendLine("## Tier 2 - rebuildable, confirm I am not mid-project (~$t2GB GB)")
foreach ($i in $tier2) { [void]$p.AppendLine("- [ ] $($i.Item) | $(GB $i.Bytes) GB | $($i.Path)") }
[void]$p.AppendLine()
[void]$p.AppendLine("## Tier 3 - big items, ask me one by one (~$t3GB GB)")
foreach ($i in $tier3) { [void]$p.AppendLine("- [ ] $($i.Item) | $(GB $i.Bytes) GB | $($i.Path)") }
[void]$p.AppendLine()
[void]$p.AppendLine('## Apps recommended for uninstall (via Settings > Apps or winget uninstall)')
foreach ($a in $uninstallApps) { [void]$p.AppendLine("- [ ] $($a.Name) ($($a.Size_MB) MB) - $($a.Reason)") }
[void]$p.AppendLine()
[void]$p.AppendLine('## Startup programs to disable (Task Manager > Startup apps)')
foreach ($s in $disableStartup) { [void]$p.AppendLine("- [ ] $($s.Name)") }
$promptText = $p.ToString()

# ------------------------------------------------------------- 12. Report
Write-Step 'Writing HTML report...'
function Esc($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
function HtmlTable([string[]]$Headers, [object[][]]$Rows) {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append("<th>$(Esc $h)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($cell in $r) { [void]$sb.Append("<td>$(Esc $cell)</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

$css = @'
<style>
  :root { color-scheme: dark; }
  body { background:#101418; color:#d7dde3; font:14px/1.5 "Segoe UI",system-ui,sans-serif; max-width:1100px; margin:0 auto; padding:32px 24px; }
  h1 { font-size:24px; margin:0 0 4px; } h2 { font-size:18px; margin:36px 0 10px; border-bottom:1px solid #2a3138; padding-bottom:6px; }
  h3 { font-size:15px; margin:20px 0 8px; }
  .muted { color:#8b96a1; } .danger { color:#ff7b72; } .ok { color:#7ee787; } .warn { color:#e3b341; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:20px 0; }
  .stat { border:1px solid #2a3138; border-radius:8px; padding:14px; }
  .stat .v { font-size:22px; font-weight:600; } .stat .l { color:#8b96a1; font-size:12px; margin-top:2px; }
  table { border-collapse:collapse; width:100%; margin:8px 0 16px; font-size:13px; }
  th,td { text-align:left; padding:6px 10px; border-bottom:1px solid #232a31; vertical-align:top; word-break:break-word; }
  th { color:#8b96a1; font-weight:600; font-size:12px; }
  .bar { display:flex; height:14px; border-radius:7px; overflow:hidden; margin:10px 0 4px; background:#232a31; }
  .legend { display:flex; flex-wrap:wrap; gap:14px; font-size:12px; color:#8b96a1; margin-bottom:10px; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; }
  pre#prompt { background:#161b21; border:1px solid #2a3138; border-radius:8px; padding:16px; white-space:pre-wrap; font-size:12.5px; max-height:480px; overflow:auto; }
  button { background:#2f81f7; color:#fff; border:0; border-radius:6px; padding:8px 14px; font-size:13px; cursor:pointer; }
  button:hover { background:#4593f8; }
  details { margin:8px 0; } summary { cursor:pointer; color:#8b96a1; }
  .callout { border:1px solid #2a3138; border-left:3px solid #e3b341; border-radius:6px; padding:10px 14px; margin:12px 0; }
</style>
'@

$colors = @('#a371f7', '#f0883e', '#2f81f7', '#3fb950', '#e3b341', '#8b96a1', '#db61a2', '#39c5cf')
$topForBar = @($folderScan | Where-Object Group -in @('Drive root', 'User profile') | Select-Object -First 8)
$barTotalBytes = [long](($sysDisk.Size - $sysDisk.FreeSpace))
$barHtml = '<div class="bar">'
$legendHtml = '<div class="legend">'
$ci = 0
foreach ($f in $topForBar) {
    $pct = [math]::Max(0.5, [math]::Round(100 * $f.Bytes / [math]::Max(1, $barTotalBytes), 1))
    $barHtml += "<div style='width:$pct%;background:$($colors[$ci % 8])' title='$(Esc $f.Path)'></div>"
    $legendHtml += "<span><span class='dot' style='background:$($colors[$ci % 8])'></span>$(Esc (Split-Path $f.Path -Leaf)) $($f.Size_GB) GB</span>"
    $ci++
}
$barHtml += '</div>'; $legendHtml += '</div>'

$freeClass = 'ok'; if ($sysDisk -and $sysDisk.FreeSpace / $sysDisk.Size -lt 0.15) { $freeClass = 'danger' }
$html = [System.Text.StringBuilder]::new()
[void]$html.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>PC Speed &amp; Storage Audit</title>' + $css + '</head><body>')
[void]$html.AppendLine("<h1>PC Speed &amp; Storage Audit</h1>")
[void]$html.AppendLine("<p class='muted'>$(Esc $system.OS) $($system.Version) &middot; $($system.RAM_GB) GB RAM &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; read-only scan, nothing was changed</p>")
[void]$html.AppendLine("<div class='stats'>")
foreach ($d in $system.Disks) {
    [void]$html.AppendLine("<div class='stat'><div class='v $freeClass'>$($d.Free_GB) GB</div><div class='l'>free on $($d.Drive) of $($d.Size_GB) GB ($($d.PctFree)%)</div></div>")
}
[void]$html.AppendLine("<div class='stat'><div class='v ok'>~$t1GB GB</div><div class='l'>Tier 1: safe reclaim</div></div>")
[void]$html.AppendLine("<div class='stat'><div class='v'>~$t2GB GB</div><div class='l'>Tier 2: rebuildable</div></div>")
[void]$html.AppendLine("<div class='stat'><div class='v warn'>~$t3GB GB</div><div class='l'>Tier 3: your call</div></div>")
[void]$html.AppendLine('</div>')
if ($sysDisk -and $sysDisk.FreeSpace / $sysDisk.Size -lt 0.15) {
    [void]$html.AppendLine("<div class='callout'><b>Disk pressure:</b> below ~15% free space Windows and SSDs slow down noticeably. Prioritize Tier 1.</div>")
}

[void]$html.AppendLine('<h2>Disk health</h2>')
[void]$html.AppendLine((HtmlTable @('Disk', 'Type', 'Health', 'Size (GB)') @($system.Physical | ForEach-Object { , @($_.Name, $_.Media, $_.Health, $_.Size_GB) })))

[void]$html.AppendLine('<h2>Where the space goes</h2>')
[void]$html.AppendLine($barHtml + $legendHtml)
[void]$html.AppendLine((HtmlTable @('Folder', 'Size (GB)', 'Area') @($folderScan | Select-Object -First 40 | ForEach-Object { , @($_.Path, $_.Size_GB, $_.Group) })))
if ($rootFiles.Count) {
    [void]$html.AppendLine('<h3>Loose files at drive root</h3>')
    [void]$html.AppendLine((HtmlTable @('File', 'Size (GB)') @($rootFiles | ForEach-Object { , @($_.Path, $_.Size_GB) })))
}

[void]$html.AppendLine('<h2>Caches, temp &amp; known bloat</h2>')
[void]$html.AppendLine((HtmlTable @('Location', 'Size (GB)', 'Verdict', 'Path') @($caches | ForEach-Object { , @($_.Name, $_.Size_GB, $_.Verdict, $_.Path) })))

if ($largeFiles.Count) {
    [void]$html.AppendLine('<h2>Largest files</h2>')
    [void]$html.AppendLine((HtmlTable @('File', 'Size (GB)', 'Modified') @($largeFiles | ForEach-Object { , @($_.Path, $_.Size_GB, $_.Modified) })))
}
if ($installers.Count) {
    [void]$html.AppendLine('<h2>Old installers</h2>')
    [void]$html.AppendLine((HtmlTable @('Installer', 'Size (MB)', 'Modified') @($installers | ForEach-Object { , @($_.Path, $_.Size_MB, $_.Modified) })))
}
if ($duplicates.Count) {
    [void]$html.AppendLine('<h2>Duplicate files (hash-verified)</h2>')
    [void]$html.AppendLine((HtmlTable @('Copies', 'Each (MB)', 'Wasted (MB)', 'Files') @($duplicates | ForEach-Object { , @($_.Files.Count, $_.Size_MB, $_.Wasted_MB, ($_.Files -join "`n")) })))
}
if ($devBloat.Count -or $devExtra.Count) {
    [void]$html.AppendLine('<h2>Dev bloat (rebuildable)</h2>')
    if ($devBloat.Count) { [void]$html.AppendLine((HtmlTable @('Dependency folder', 'Size (MB)') @($devBloat | ForEach-Object { , @($_.Path, $_.Size_MB) }))) }
    if ($devExtra.Count) { [void]$html.AppendLine((HtmlTable @('Store', 'Size (GB)', 'Note') @($devExtra | ForEach-Object { , @("$($_.Name) - $($_.Path)", $_.Size_GB, $_.Note) }))) }
}

[void]$html.AppendLine('<h2>Installed applications</h2>')
foreach ($cat in @('Unnecessary', 'Occasional', 'Essential', 'Review')) {
    $group = @($apps | Where-Object Category -eq $cat)
    if (-not $group.Count) { continue }
    $open = ''; if ($cat -eq 'Unnecessary') { $open = ' open' }
    [void]$html.AppendLine("<details$open><summary>$cat ($($group.Count))</summary>")
    [void]$html.AppendLine((HtmlTable @('Application', 'Version', 'Size (MB)', 'Why') @($group | ForEach-Object { , @($_.Name, $_.Version, $_.Size_MB, $_.Reason) })))
    [void]$html.AppendLine('</details>')
}

[void]$html.AppendLine('<h2>Startup programs</h2>')
[void]$html.AppendLine((HtmlTable @('Name', 'Verdict', 'Command') @($startup | Sort-Object Verdict | ForEach-Object { , @($_.Name, $_.Verdict, $_.Command) })))

[void]$html.AppendLine('<h2>AI cleanup prompt</h2>')
[void]$html.AppendLine('<p class="muted">Paste this into any AI agent with shell access (Cursor, Claude Code, Codex CLI...). It contains the full tiered plan with guardrails. Also saved as cleanup-prompt.md next to this report.</p>')
[void]$html.AppendLine('<button onclick="navigator.clipboard.writeText(document.getElementById(''prompt'').textContent).then(()=>{this.textContent=''Copied!'';setTimeout(()=>this.textContent=''Copy prompt'',1500)})">Copy prompt</button>')
[void]$html.AppendLine("<pre id='prompt'>$(Esc $promptText)</pre>")
[void]$html.AppendLine("<p class='muted'>pc-audit &middot; scan took $([math]::Round($sw.Elapsed.TotalMinutes,1)) min &middot; read-only: this tool never deletes anything.</p>")
[void]$html.AppendLine('</body></html>')

# ------------------------------------------------------------ 13. Outputs
$reportPath = Join-Path $ReportDir 'report.html'
$promptPath = Join-Path $ReportDir 'cleanup-prompt.md'
$dataPath = Join-Path $ReportDir 'data.json'
$html.ToString() | Set-Content -Path $reportPath -Encoding UTF8
$promptText | Set-Content -Path $promptPath -Encoding UTF8
[PSCustomObject]@{
    GeneratedAt = (Get-Date).ToString('o'); System = $system; Folders = $folderScan; RootFiles = $rootFiles
    Caches = $caches; LargeFiles = $largeFiles; Installers = $installers; Duplicates = $duplicates
    DevBloat = $devBloat; DevStores = $devExtra; Apps = $apps; Startup = $startup
    Tier1 = $tier1; Tier2 = $tier2; Tier3 = $tier3
} | ConvertTo-Json -Depth 6 | Set-Content -Path $dataPath -Encoding UTF8

Write-Host ''
Write-Host '=============================================' -ForegroundColor Green
Write-Host " Audit complete in $([math]::Round($sw.Elapsed.TotalMinutes,1)) min (read-only, nothing deleted)" -ForegroundColor Green
Write-Host "   Tier 1 safe reclaim : ~$t1GB GB"
Write-Host "   Tier 2 rebuildable  : ~$t2GB GB"
Write-Host "   Tier 3 your call    : ~$t3GB GB"
Write-Host "   Report : $reportPath"
Write-Host "   Prompt : $promptPath"
Write-Host '=============================================' -ForegroundColor Green
if (-not $NoBrowser) { Start-Process $reportPath }
