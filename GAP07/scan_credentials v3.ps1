<#
.SYNOPSIS
    Credential exposure auditing script for Windows file servers.
.DESCRIPTION
    Pure PowerShell - no external dependencies. Works standalone or via Ansible.

    Phase 1 - Open Share Discovery (SMB shares with ACL analysis, DFS namespaces)
    Phase 2 - Credential Content Scan (regex-based, multilingual: EN/FR/ES/PT/DE/IT/NL/TR)
    Phase 3 - Vault File Detection (KeePass, 1Password, PEM, PFX, etc.)

    Nested Write-Progress bars: an overall bar across all scan targets (Id 1) plus a
    per-target file-level bar (Id 2) showing percent, elapsed time, throughput (files/sec),
    and ETA. Program Files, Windows, $Recycle.Bin, System Volume Information and other
    OS-noise directories are skipped entirely (never traversed), and EFS-encrypted or
    OS "system"-attribute files are skipped per-file. Disable via config: ExcludeSystemPaths
    / ExcludeEncryptedFiles (both default true). The scan also runs at BelowNormal process
    priority and throttles between files (ThrottleMs) to avoid impacting the host.

    A comprehensive startup banner reports run context (host, user, elevation, PowerShell/
    OS version, script path) and the full effective configuration before scanning begins.

    Pattern matches whose value is a known placeholder/template token or a reference to
    where the real secret is actually stored (env var, vault, key-management lookup) are
    classified as detection_type 'credential_placeholder' / severity INFO instead of
    HIGH/MEDIUM - still logged for full auditability, but kept out of the risk counts so
    sample configs, .env.example files, and schema definitions don't drown out real findings.

    Two modes:
      interactive - discovers shares, lets you pick targets, then scans
      automated   - scans everything non-interactively (for Ansible Tower)

    Output: 3 CSV files per scan target:
      1_open_shares.csv - share permission findings
      2_credentials.csv - cleartext credential matches
      3_vaultfiles.csv  - password vault / key files
.EXAMPLE
    .\scan_credentials.ps1 -Mode interactive
	.\scan_credentials.ps1 -ConfigPath .\config.json -Mode automated
    .\scan_credentials.ps1 -Mode automated -ConfigPath .\config.json -OutputPath .\results
    .\scan_credentials.ps1 -ScanPath C:\Data,D:\Shares
.NOTES
    Dab17 Security Audit Framework v2.2.0
#>
Param(
    [string]$Mode = 'automated',
    [string]$ConfigPath,
    [string]$OutputPath,
    [string]$Hostname = $env:COMPUTERNAME,
    [string[]]$ScanPath = @()
)

###############################################################################
# Init
###############################################################################

$Script:ZipAvailable = $false
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Script:ZipAvailable = $true
} catch {
    Write-Warning "ZipFile assembly not available - Office doc scanning disabled"
}

try {
    # BelowNormal keeps the scan from starving other processes on a live file server -
    # the OS scheduler favors interactive/normal-priority work over this script.
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'BelowNormal'
} catch {}

$Script:ScanUser = "$($env:USERDOMAIN)\$($env:USERNAME)"

# Per-target CSV writers (keyed by sanitized target name)
$Script:CsvWriters = @{}

$DefaultConfig = @{
    MaxFileSizeMB         = 50
    MaxDepth              = 10
    ThrottleMs            = 5
    AdditionalScanPaths   = @()
    ExcludeSystemShares   = $true
    ExcludeSystemPaths    = $true   # Skip Windows, Program Files, Recycle Bin, System Volume Information, etc.
    ExcludeEncryptedFiles = $true   # Skip EFS-encrypted files (unreadable content, low audit value)
}

$CsvHeader = 'hostname,share_name,share_type,file_path,detection_type,matched_pattern,severity,context_snippet,language,timestamp,scan_user'

###############################################################################
# Config
###############################################################################

function Load-Config {
    param([string]$Path)
    $cfg = $DefaultConfig.Clone()
    if ($Path -and (Test-Path $Path)) {
        try {
            $raw = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json
            $maxSize = if ($null -ne $raw.MaxFileSizeMB) { $raw.MaxFileSizeMB } elseif ($null -ne $raw.max_file_size_mb) { $raw.max_file_size_mb } else { $null }
            $maxDep  = if ($null -ne $raw.MaxDepth) { $raw.MaxDepth } elseif ($null -ne $raw.max_depth) { $raw.max_depth } else { $null }
            $thrMs   = if ($null -ne $raw.ThrottleMs) { $raw.ThrottleMs } elseif ($null -ne $raw.throttle_ms) { $raw.throttle_ms } else { $null }
            if ($null -ne $maxSize) { $cfg.MaxFileSizeMB = [int]$maxSize }
            if ($null -ne $maxDep)  { $cfg.MaxDepth      = [int]$maxDep }
            if ($null -ne $thrMs)   { $cfg.ThrottleMs    = [int]$thrMs }
            if ($null -ne $raw.AdditionalScanPaths) { $cfg.AdditionalScanPaths = @($raw.AdditionalScanPaths) }
            if ($null -ne $raw.ExcludeSystemShares) { $cfg.ExcludeSystemShares = [bool]$raw.ExcludeSystemShares }

            $exclSysPaths = if ($null -ne $raw.ExcludeSystemPaths) { $raw.ExcludeSystemPaths } elseif ($null -ne $raw.exclude_system_paths) { $raw.exclude_system_paths } else { $null }
            $exclEnc      = if ($null -ne $raw.ExcludeEncryptedFiles) { $raw.ExcludeEncryptedFiles } elseif ($null -ne $raw.exclude_encrypted_files) { $raw.exclude_encrypted_files } else { $null }
            if ($null -ne $exclSysPaths) { $cfg.ExcludeSystemPaths    = [bool]$exclSysPaths }
            if ($null -ne $exclEnc)      { $cfg.ExcludeEncryptedFiles = [bool]$exclEnc }
        } catch {
            Write-Warning "Config load failed: $($_.Exception.Message)"
        }
    }
    return $cfg
}

###############################################################################
# CSV output - per-target writers
###############################################################################

function Escape-CsvField {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value -match '^[=+\-@]' -or $Value -match '[,"\r\n]') {
        return '"' + $Value.Replace('"', '""') + '"'
    }
    return $Value
}

function Sanitize-TargetName {
    param([string]$Path)
    $name = $Path.TrimStart('\', '/')
    $name = $name -replace '[\\/]', '_'
    $name = $name -replace '[^a-zA-Z0-9._\-]', '_'
    $name = $name.TrimEnd('_')
    if ([string]::IsNullOrEmpty($name)) { $name = 'root' }
    return $name
}

function Initialize-TargetOutputDir {
    param([string]$OutputDir, [string]$TargetPath)
    $safeName = Sanitize-TargetName -Path $TargetPath
    $targetDir = Join-Path $OutputDir $safeName
    if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

    $writers = @{}
    foreach ($file in @('1_open_shares.csv', '2_credentials.csv', '3_vaultfiles.csv')) {
        $filePath = Join-Path $targetDir $file
        $stream = [System.IO.StreamWriter]::new($filePath, $false, [System.Text.UTF8Encoding]::new($true))
        $stream.AutoFlush = $false
        $stream.WriteLine($CsvHeader)
        $writers[$file] = $stream
    }
    $Script:CsvWriters[$safeName] = $writers
    return $safeName
}

function Write-CsvRow {
    param([System.IO.StreamWriter]$Writer, [hashtable]$Row)
    $Row['timestamp']  = [datetime]::UtcNow.ToString('o')
    $Row['scan_user']  = $Script:ScanUser
    $fields = @(
        (Escape-CsvField $Row.hostname), (Escape-CsvField $Row.share_name),
        (Escape-CsvField $Row.share_type), (Escape-CsvField $Row.file_path),
        (Escape-CsvField $Row.detection_type), (Escape-CsvField $Row.matched_pattern),
        (Escape-CsvField $Row.severity), (Escape-CsvField $Row.context_snippet),
        (Escape-CsvField $Row.language), (Escape-CsvField $Row.timestamp),
        (Escape-CsvField $Row.scan_user)
    )
    $Writer.WriteLine($fields -join ',')
}

function Close-AllWriters {
    foreach ($targetWriters in $Script:CsvWriters.Values) {
        foreach ($writer in $targetWriters.Values) {
            try {
                $writer.Flush()
                $writer.Close()
                $writer.Dispose()
            } catch {}
        }
    }
}

$Script:Phase1Writer = $null

function Initialize-Phase1Buffer {
    param([string]$OutputDir)
    $tempPath = Join-Path $OutputDir '.phase1_temp.csv'
    $stream = [System.IO.StreamWriter]::new($tempPath, $false, [System.Text.UTF8Encoding]::new($true))
    $stream.AutoFlush = $false
    $stream.WriteLine($CsvHeader)
    $Script:Phase1Writer = $stream
    return $tempPath
}

function Write-Phase1Row {
    param([hashtable]$Row)
    Write-CsvRow -Writer $Script:Phase1Writer -Row $Row
}

###############################################################################
# Pattern engine
###############################################################################

function Get-RedactedSnippet {
    param([string]$Line, [int]$MatchIndex, [int]$MatchLength, [int]$WindowSize = 80)
    $half  = [math]::Floor($WindowSize / 2)
    $start = [math]::Max(0, $MatchIndex - $half)
    $end   = [math]::Min($Line.Length, $MatchIndex + $MatchLength + $half)
    $snippet = $Line.Substring($start, $end - $start)
    $snippet = [regex]::Replace($snippet, '([:=]\s*[''"]?)([^\s''"]{3,})', '$1[REDACTED]')
    return ($snippet -replace '[\r\n\t]', ' ')
}

$HighPatternStr = '(api[_\-]?key|apikey|private[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?secret|secret[_\-]?key|jwt[_\-]?secret)'
try {
    $Script:HighPatternCompiled = [regex]::new($HighPatternStr,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Compiled)
} catch {
    $Script:HighPatternCompiled = [regex]::new($HighPatternStr,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-PatternSeverity {
    param([string]$MatchedText)
    if ($Script:HighPatternCompiled.IsMatch($MatchedText)) { return 'HIGH' }
    return 'MEDIUM'
}

# Values that look like a credential match syntactically but are NOT a real exposed
# secret: template/placeholder tokens, masked values, and references to where the
# real secret is actually stored (env vars, vaults, config-management lookups).
# Matches classified here are still logged (severity INFO, detection_type
# 'credential_placeholder') for full auditability, but excluded from the HIGH/MEDIUM
# risk counts so they don't drown out genuine findings.
$PlaceholderValuePattern = '^(' + (@(
    'null', 'none', 'nil', 'undefined', 'n\/a', 'na', 'todo', 'fixme', 'tbd',
    'x{3,}', '\*{3,}', '-{3,}', '_{3,}',
    'change[_\-]?me', 'placeholder', 'your[_\-]?\S*', 'insert[_\-]\S*',
    'example\S*', 'sample\S*', 'demo\S*', 'dummy\S*', 'test\S*',
    'redacted\S*', 'removed', 'hidden', 'masked',
    'secret', 'password', 'passwd', 'pwd', 'credential', 'token', 'key', 'string',
    'true', 'false',
    '<[^>]+>', '\{\{[^}]+\}\}', '\$\{[^}]+\}', '%[a-zA-Z_][a-zA-Z0-9_]*%',
    '\$env:\S+', '\$\(.+\)', '\{.*',
    'getenv\(.*', 'process\.env\.\S*', 'os\.environ\S*',
    'vault:\S*', 'secretsmanager\S*', 'keyvault\S*', 'ssm:\S*'
) -join '|') + ')$'

try {
    $Script:PlaceholderValueRegex = [regex]::new($PlaceholderValuePattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Compiled)
} catch {
    $Script:PlaceholderValueRegex = [regex]::new($PlaceholderValuePattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Test-IsPlaceholderValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    return $Script:PlaceholderValueRegex.IsMatch($Value)
}

$PatternBank = @{
    en = '(password|passwd|pwd|credential|secret|api[_\-]?key|apikey|token|auth[_\-]?(token|key|secret)|private[_\-]?key|access[_\-]?key|client[_\-]?secret|jwt[_\-]?secret|db[_\-]?pass(word)?|connection[_\-]?string)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    fr = '(mot[_ ]de[_ ]passe|mdp|identifiant|cl[e\u00e9]|jeton|authentification|acc[\u00e8e]s)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    es = '(contrase[\u00f1n]a|clave|secreto|credencial|llave|acceso|autenticaci[o\u00f3]n)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    pt = '(senha|chave|segredo|autentica[c\u00e7][a\u00e3]o)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    de = '(passwort|kennwort|geheimnis|schl[u\u00fc]ssel|zugang|berechtigung|zugangsdaten)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    it = '(chiave|segreto|credenziale)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    nl = '(wachtwoord|sleutel|geheim|toegang|inloggegevens)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
    tr = '([s\u015f]ifre|anahtar|gizli|kimlik)\s*[:=]\s*[''"]?(?<val>[^\s''"]{3,})'
}

$CompiledPatterns = @{}
foreach ($lang in $PatternBank.Keys) {
    try {
        $CompiledPatterns[$lang] = [regex]::new($PatternBank[$lang],
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::Compiled)
    } catch {
        $CompiledPatterns[$lang] = [regex]::new($PatternBank[$lang],
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
}

# Extension lookup sets
$TextExtSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '.txt','.log','.cfg','.cnf','.conf','.ini','.xml','.json','.yaml','.yml','.env',
        '.properties','.csv','.sql','.sh','.ps1','.bat','.cmd','.py','.rb','.js',
        '.ts','.php','.java','.cs','.config','.htpasswd','.pgpass','.netrc','.toml',
        '.tf','.tfvars'
    ), [System.StringComparer]::OrdinalIgnoreCase)
$OfficeExtSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('.docx', '.xlsx', '.pptx'), [System.StringComparer]::OrdinalIgnoreCase)
$VaultExtSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '.kdbx','.kdb','.1pif','.opvault','.agilekeychain','.1pux',
        '.psafe3','.key','.pem','.ppk','.pfx','.p12','.jks','.keystore'
    ), [System.StringComparer]::OrdinalIgnoreCase)

# Directories that are skipped outright (never enumerated into) - exact name match,
# checked against the final path component only.
$Script:ExcludedDirNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '$Recycle.Bin', 'RECYCLER', 'RECYCLED', 'System Volume Information',
        'Config.Msi', 'PerfLogs', 'MSOCache', '$WinREAgent'
    ), [System.StringComparer]::OrdinalIgnoreCase)

# Path fragments that are skipped outright regardless of nesting depth - covers OS install
# locations (Windows, Program Files) wherever they appear under a scan root, e.g. when a
# whole drive letter (C:\) is scanned.
$Script:ExcludedPathRegex = [regex]::new(
    '\\(Windows|WindowsApps|Program Files|Program Files \(x86\)|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|MSOCache)\\',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Test-PathExcluded {
    param([string]$FullPath, [string]$LeafName)
    if ($LeafName -and $Script:ExcludedDirNames.Contains($LeafName)) { return $true }
    if ($Script:ExcludedPathRegex.IsMatch("$FullPath\")) { return $true }
    return $false
}

$Script:Stats = @{
    SharesFound = 0; FilesScanned = 0; FilesSkipped = 0; AccessErrors = 0
    DetectionHigh = 0; DetectionMedium = 0; DetectionInfo = 0
    VaultFiles = 0; OfficeScanned = 0; PdfScanned = 0
    DirsExcluded = 0; FilesExcludedSystem = 0; FilesExcludedEncrypted = 0
}

###############################################################################
# Helpers
###############################################################################

function Get-ShareNameFromPath {
    param([string]$Path, [string]$ScanRoot)
    if ([string]::IsNullOrEmpty($ScanRoot)) { return '' }
    $relative = $Path
    if ($Path.StartsWith($ScanRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $Path.Substring($ScanRoot.Length).TrimStart('\', '/')
    }
    $parts = $relative -split '[\\/]'
    if ($parts.Count -gt 0) { return $parts[0] }
    return ''
}

function Invoke-PatternMatch {
    param([System.IO.StreamWriter]$Writer, [string]$Line, [string]$LogicalPath, [string]$DetectionType, [string]$ScanRoot)
    foreach ($lang in $CompiledPatterns.Keys) {
        $matches = $CompiledPatterns[$lang].Matches($Line)
        foreach ($m in $matches) {
            $value = if ($m.Groups['val'].Success) { $m.Groups['val'].Value } else { '' }
            $isPlaceholder = Test-IsPlaceholderValue -Value $value
            $snippet = Get-RedactedSnippet -Line $Line -MatchIndex $m.Index -MatchLength $m.Length

            if ($isPlaceholder) {
                $severity = 'INFO'
                $thisType = 'credential_placeholder'
            } else {
                $severity = Get-PatternSeverity -MatchedText $m.Value
                $thisType = $DetectionType
            }

            Write-CsvRow -Writer $Writer -Row @{
                hostname=$Hostname; share_name=(Get-ShareNameFromPath -Path $LogicalPath -ScanRoot $ScanRoot)
                share_type=''; file_path=$LogicalPath
                detection_type=$thisType; matched_pattern=$m.Groups[1].Value
                severity=$severity; context_snippet=$snippet; language=$lang
            }

            if ($isPlaceholder) {
                $Script:Stats.DetectionInfo++
            } elseif ($severity -eq 'HIGH') {
                $Script:Stats.DetectionHigh++
            } else {
                $Script:Stats.DetectionMedium++
            }
        }
    }
}

###############################################################################
# Phase 1: Open Share Discovery with ACL analysis
###############################################################################

function Invoke-ShareDiscovery {
    param([string]$Hostname, [bool]$ExcludeSystem)

    Write-Host "`n[Phase 1] Discovering SMB shares and analyzing permissions..."
    $systemShares = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('IPC$','ADMIN$','C$','D$','E$','F$','G$','print$'),
        [System.StringComparer]::OrdinalIgnoreCase)

    $broadGroupPatterns = @('Everyone', 'BUILTIN\Users', 'Authenticated Users', 'ANONYMOUS LOGON', 'Domain Users')
    $sharePaths = @()

    try {
        $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop
    } catch {
        Write-Warning "Share enumeration failed: $($_.Exception.Message)"
        Write-Phase1Row -Row @{
            hostname=$Hostname; share_name=''; share_type=''; file_path=''
            detection_type='access_error'; matched_pattern='Win32_Share'; severity='INFO'
            context_snippet="Failed to enumerate shares: $($_.Exception.Message)"
            language=''
        }
        $Script:Stats.AccessErrors++
        return $sharePaths
    }

    $shareList = @($shares)
    $shareTotal = $shareList.Count
    $shareIdx = 0

    foreach ($share in $shareList) {
        $shareIdx++
        $sharePct = if ($shareTotal -gt 0) { [int](($shareIdx / $shareTotal) * 100) } else { 0 }
        Write-Progress -Activity "Phase 1: Share discovery on $Hostname" `
            -Status "$sharePct% - $shareIdx / $shareTotal shares | $($share.Name)" `
            -PercentComplete $sharePct

        $isSystem = $systemShares.Contains($share.Name)
        if ($ExcludeSystem -and $isSystem) { continue }
        $Script:Stats.SharesFound++

        $permInfo = ''
        $shareSeverity = 'INFO'

        if ($share.Path -and (Test-Path $share.Path -ErrorAction SilentlyContinue)) {
            try {
                $fsAcl = Get-Acl -Path $share.Path -ErrorAction Stop
                $permEntries = [System.Collections.Generic.List[string]]::new()
                foreach ($ace in $fsAcl.Access) {
                    [void]$permEntries.Add("$($ace.IdentityReference):$($ace.FileSystemRights)/$($ace.AccessControlType)")

                    $isBroad = $false
                    foreach ($bg in $broadGroupPatterns) {
                        if ("$($ace.IdentityReference)" -like "*$bg*") { $isBroad = $true; break }
                    }

                    if ($isBroad -and $ace.AccessControlType -eq 'Allow') {
                        $rights = $ace.FileSystemRights
                        if ($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) {
                            $shareSeverity = 'HIGH'
                        } elseif ($rights -band ([System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::Write)) {
                            if ($shareSeverity -ne 'HIGH') { $shareSeverity = 'HIGH' }
                        } elseif ($rights -band [System.Security.AccessControl.FileSystemRights]::Read) {
                            if ($shareSeverity -ne 'HIGH') { $shareSeverity = 'MEDIUM' }
                        }
                    }
                }
                $permInfo = ($permEntries -join '; ')
            } catch {
                $permInfo = "Unable to read permissions: $($_.Exception.Message)"
            }
        }

        $shareType = if ($isSystem) { 'system' } else { 'user' }
        if ($permInfo.Length -gt 500) { $permInfo = $permInfo.Substring(0, 497) + '...' }

        Write-Phase1Row -Row @{
            hostname=$Hostname; share_name=$share.Name; share_type=$shareType
            file_path=$share.Path; detection_type='open_share'; matched_pattern=''
            severity=$shareSeverity; context_snippet=$permInfo; language=''
        }

        if (-not $isSystem -and $share.Path -and (Test-Path $share.Path -ErrorAction SilentlyContinue)) {
            $sharePaths += $share.Path
        }
    }
    Write-Progress -Activity "Phase 1: Share discovery on $Hostname" -Completed

    Write-Host "  Shares found: $($Script:Stats.SharesFound)"

    try {
        $roots = @(Get-DfsnRoot -ErrorAction Stop 2>$null)
        if ($roots.Count -gt 0) {
            Write-Host "  DFS namespaces: $($roots.Count) roots found"
            foreach ($root in $roots) {
                Write-Phase1Row -Row @{
                    hostname=$Hostname; share_name=$root.Path; share_type='dfs_root'
                    file_path=$root.Path; detection_type='open_share'
                    matched_pattern='DFS Namespace Root'; severity='MEDIUM'
                    context_snippet="State: $($root.State); Type: $($root.Type)"
                    language=''
                }
                try {
                    $folders = Get-DfsnFolder -Path "$($root.Path)\*" -ErrorAction Stop
                    foreach ($folder in $folders) {
                        Write-Phase1Row -Row @{
                            hostname=$Hostname; share_name=$folder.Path; share_type='dfs_folder'
                            file_path=$folder.Path; detection_type='open_share'
                            matched_pattern='DFS Folder'; severity='INFO'
                            context_snippet="State: $($folder.State)"
                            language=''
                        }
                    }
                } catch { }
            }
        }
    } catch { }

    return $sharePaths
}

function Invoke-RemoteShareDiscovery {
    param([string[]]$Paths, [bool]$ExcludeSystem)

    $remoteHosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $Paths) {
        if ($p -match '^\\\\([^\\]+)') { [void]$remoteHosts.Add($Matches[1]) }
    }
    if ($remoteHosts.Count -eq 0) { return @() }

    Write-Host "`n[Phase 1] Enumerating remote shares..."
    $systemShares = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('IPC$','ADMIN$','C$','D$','E$','F$','G$','print$'),
        [System.StringComparer]::OrdinalIgnoreCase)
    $broadGroupPatterns = @('Everyone', 'BUILTIN\Users', 'Authenticated Users', 'ANONYMOUS LOGON', 'Domain Users')
    $discoveredPaths = @()

    foreach ($rHost in $remoteHosts) {
        Write-Host "  \\$rHost - enumerating via net view..."
        try {
            $rawOutput = net view "\\$rHost" 2>&1
            $lines = @($rawOutput | ForEach-Object { "$_" })
            $inShares = $false

            foreach ($line in $lines) {
                if ($line -match '^-{3,}') { $inShares = $true; continue }
                if (-not $inShares) { continue }
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                if ($line -match 'command completed') { break }

                if ($line -match '^(.+?)\s{2,}(Disk|Print|IPC)\b') {
                    $shareName = $Matches[1].TrimEnd()
                    $shareType = $Matches[2]
                    if ($shareType -ne 'Disk') { continue }

                    $isSystem = $systemShares.Contains($shareName)
                    if ($ExcludeSystem -and $isSystem) { continue }
                    $Script:Stats.SharesFound++

                    $uncPath = "\\$rHost\$shareName"
                    $permInfo = ''
                    $shareSeverity = 'INFO'

                    try {
                        if (Test-Path $uncPath -ErrorAction Stop) {
                            $fsAcl = Get-Acl -Path $uncPath -ErrorAction Stop
                            $permEntries = [System.Collections.Generic.List[string]]::new()
                            foreach ($ace in $fsAcl.Access) {
                                [void]$permEntries.Add("$($ace.IdentityReference):$($ace.FileSystemRights)/$($ace.AccessControlType)")
                                $isBroad = $false
                                foreach ($bg in $broadGroupPatterns) {
                                    if ("$($ace.IdentityReference)" -like "*$bg*") { $isBroad = $true; break }
                                }
                                if ($isBroad -and $ace.AccessControlType -eq 'Allow') {
                                    $rights = $ace.FileSystemRights
                                    if ($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) {
                                        $shareSeverity = 'HIGH'
                                    } elseif ($rights -band ([System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::Write)) {
                                        if ($shareSeverity -ne 'HIGH') { $shareSeverity = 'HIGH' }
                                    } elseif ($rights -band [System.Security.AccessControl.FileSystemRights]::Read) {
                                        if ($shareSeverity -ne 'HIGH') { $shareSeverity = 'MEDIUM' }
                                    }
                                }
                            }
                            $permInfo = ($permEntries -join '; ')
                        }
                    } catch {
                        $permInfo = "Unable to read permissions: $($_.Exception.Message)"
                    }

                    $shareTypeStr = if ($isSystem) { 'system' } else { 'user' }
                    if ($permInfo.Length -gt 500) { $permInfo = $permInfo.Substring(0, 497) + '...' }

                    Write-Phase1Row -Row @{
                        hostname=$rHost; share_name=$shareName; share_type=$shareTypeStr
                        file_path=$uncPath; detection_type='open_share'; matched_pattern='remote_smb'
                        severity=$shareSeverity; context_snippet=$permInfo; language=''
                    }

                    if (-not $isSystem) { $discoveredPaths += $uncPath }
                }
            }
        } catch {
            Write-Warning "Could not enumerate shares on \\${rHost}: $($_.Exception.Message)"
            Write-Phase1Row -Row @{
                hostname=$rHost; share_name=''; share_type=''; file_path="\\$rHost"
                detection_type='access_error'; matched_pattern='net_view'; severity='INFO'
                context_snippet="Failed to enumerate remote shares: $($_.Exception.Message)"
                language=''
            }
        }
    }

    Write-Host "  Remote shares found: $($discoveredPaths.Count)"
    return $discoveredPaths
}

###############################################################################
# Interactive target selection
###############################################################################

function Select-ScanTargets {
    param([System.Collections.Generic.List[string]]$Paths)

    Write-Host ""
    Write-Host "=== Discovered Scan Targets ===" -ForegroundColor Cyan
    if ($Paths.Count -eq 0) {
        Write-Host "  (no directories found)"
    } else {
        for ($i = 0; $i -lt $Paths.Count; $i++) {
            $exists = if (Test-Path $Paths[$i] -ErrorAction SilentlyContinue) { '[OK]' } else { '[NOT FOUND]' }
            Write-Host "  [$($i+1)] $exists $($Paths[$i])"
        }
    }

    Write-Host ""
    Write-Host "Enter additional paths to scan (comma-separated, or press Enter to skip):"
    $addInput = Read-Host
    if ($addInput) {
        foreach ($p in ($addInput -split ',')) {
            $p = $p.Trim()
            if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
                [void]$Paths.Add($p)
                Write-Host "  Added: $p" -ForegroundColor Green
            } elseif ($p) {
                Write-Host "  WARNING: $p does not exist or not accessible" -ForegroundColor Yellow
            }
        }
    }

    if ($Paths.Count -eq 0) {
        Write-Host "No targets available. Exiting."
        exit 0
    }

    Write-Host ""
    Write-Host "Current targets:"
    for ($i = 0; $i -lt $Paths.Count; $i++) {
        Write-Host "  [$($i+1)] $($Paths[$i])"
    }

    Write-Host ""
    Write-Host "Enter numbers to remove (comma-separated, or press Enter to skip):"
    $removeInput = Read-Host
    if ($removeInput) {
        $removeNums = @()
        foreach ($n in ($removeInput -split ',')) {
            $n = $n.Trim()
            if ($n -match '^\d+$') { $removeNums += [int]$n }
        }
        $removeNums = $removeNums | Sort-Object -Descending
        foreach ($n in $removeNums) {
            if ($n -ge 1 -and $n -le $Paths.Count) {
                Write-Host "  Removed: $($Paths[$n-1])" -ForegroundColor Yellow
                $Paths.RemoveAt($n - 1)
            }
        }
    }

    Write-Host ""
    Write-Host "Final scan targets:" -ForegroundColor Cyan
    foreach ($p in $Paths) { Write-Host "  - $p" }

    Write-Host ""
    $confirm = Read-Host "Proceed with scan? [Y/n]"
    if ($confirm -eq 'n') {
        Write-Host "Scan cancelled."
        exit 0
    }

    return $Paths
}

###############################################################################
# Phase 1 distribution - match buffered rows to targets
###############################################################################

function Distribute-Phase1Results {
    param([string]$TempPath, [string]$OutputDir, [string[]]$Targets)

    # Always close writer first - even if temp file is missing
    if ($Script:Phase1Writer) {
        try { $Script:Phase1Writer.Flush(); $Script:Phase1Writer.Close(); $Script:Phase1Writer.Dispose() } catch {}
        $Script:Phase1Writer = $null
    }

    if (-not (Test-Path $TempPath)) { return }

    # Sort targets longest-first so C:\DataArchive matches before C:\Data
    $sortedTargets = $Targets | Sort-Object { $_.Length } -Descending

    $lines = Get-Content -Path $TempPath -Encoding UTF8 -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($line -eq $CsvHeader) { continue }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $matched = $false
        foreach ($target in $sortedTargets) {
            if ($line.IndexOf($target, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $safeName = Sanitize-TargetName -Path $target
                if ($Script:CsvWriters.ContainsKey($safeName)) {
                    $Script:CsvWriters[$safeName]['1_open_shares.csv'].WriteLine($line)
                }
                $matched = $true
                break
            }
        }

        if (-not $matched) {
            # Server-level findings go to _server directory
            $serverDir = Join-Path $OutputDir '_server'
            if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory -Path $serverDir -Force | Out-Null }
            $serverFile = Join-Path $serverDir '1_open_shares.csv'
            if (-not (Test-Path $serverFile)) {
                $CsvHeader | Out-File -FilePath $serverFile -Encoding utf8
            }
            $line | Out-File -FilePath $serverFile -Encoding utf8 -Append
        }
    }

    Remove-Item -Path $TempPath -Force -ErrorAction SilentlyContinue
}

###############################################################################
# Phase 2+3: Content Scan & Vault Detection (single traversal, per-target)
###############################################################################

function Scan-TextFile {
    param([System.IO.StreamWriter]$Writer, [string]$FilePath, [string]$ScanRoot)
    $Script:Stats.FilesScanned++
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($FilePath, [System.Text.Encoding]::Default, $true)
        $lineNum = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNum++
            if ($line.Length -gt 10000) { continue }
            Invoke-PatternMatch -Writer $Writer -Line $line -LogicalPath "${FilePath}:${lineNum}" -DetectionType 'credential_in_file' -ScanRoot $ScanRoot
        }
    } catch { throw } finally {
        if ($reader) { $reader.Close(); $reader.Dispose() }
    }
}

function Scan-OfficeFile {
    param([System.IO.StreamWriter]$Writer, [string]$FilePath, [string]$ScanRoot)
    if (-not $Script:ZipAvailable) { return }
    $Script:Stats.FilesScanned++
    $Script:Stats.OfficeScanned++
    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notmatch '\.(xml|rels)$') { continue }
            if ($entry.FullName -match '^\[Content_Types\]|_rels/\.rels$|docProps/') { continue }
            if ($entry.Length -gt (10 * 1MB)) { continue }
            $stream = $null; $reader = $null
            try {
                $stream = $entry.Open()
                $reader = New-Object System.IO.StreamReader($stream)
                $xmlContent = $reader.ReadToEnd()
                $plainText = [regex]::Replace($xmlContent, '<[^>]+>', ' ')
                $plainText = $plainText -replace '&amp;','&' -replace '&lt;','<' -replace '&gt;','>' -replace '&quot;','"' -replace '&apos;',"'" -replace '&#39;',"'"
                foreach ($line in ($plainText -split '\r?\n')) {
                    if ($line.Length -lt 5 -or $line.Length -gt 10000) { continue }
                    Invoke-PatternMatch -Writer $Writer -Line $line -LogicalPath "${FilePath}#$($entry.FullName)" -DetectionType 'credential_in_office' -ScanRoot $ScanRoot
                }
            } catch { } finally {
                if ($reader) { $reader.Close(); $reader.Dispose() }
            }
        }
    } catch { throw } finally {
        if ($archive) { $archive.Dispose() }
    }
}

function Scan-PdfFile {
    param([System.IO.StreamWriter]$Writer, [string]$FilePath, [string]$ScanRoot, [long]$FileSize)
    $Script:Stats.FilesScanned++
    $Script:Stats.PdfScanned++
    $reader = $null
    $content = $null
    try {
        $reader = New-Object System.IO.StreamReader($FilePath, [System.Text.Encoding]::GetEncoding('iso-8859-1'), $false)
        $bufSize = [Math]::Min($FileSize, 10 * 1MB)
        $buffer = New-Object char[] ($bufSize)
        $read = $reader.Read($buffer, 0, $buffer.Length)
        $content = New-Object string($buffer, 0, $read)
    } catch { throw } finally {
        if ($reader) { $reader.Close(); $reader.Dispose() }
    }
    if ([string]::IsNullOrEmpty($content)) { return }

    $pdfTextRegex = [regex]::new('\(([^)]{3,500})\)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $extractedLines = [System.Collections.Generic.List[string]]::new()

    foreach ($pm in $pdfTextRegex.Matches($content)) {
        $text = $pm.Groups[1].Value
        $printable = 0
        foreach ($ch in $text.ToCharArray()) { if ([int]$ch -ge 32 -and [int]$ch -le 126) { $printable++ } }
        if ($printable -gt ($text.Length * 0.6)) { $extractedLines.Add($text) }
    }

    foreach ($line in $extractedLines) {
        if ($line.Length -gt 10000) { continue }
        Invoke-PatternMatch -Writer $Writer -Line $line -LogicalPath $FilePath -DetectionType 'credential_in_pdf' -ScanRoot $ScanRoot
    }
}

function Get-EligibleFiles {
    <#
        Single-pass, depth-bounded directory walk built on raw .NET enumeration
        (DirectoryInfo.EnumerateFiles/EnumerateDirectories) instead of the
        Get-ChildItem cmdlet pipeline - this avoids the provider/pipeline overhead
        of Get-ChildItem and, critically, skips excluded directories *before*
        ever enumerating their contents, so Program Files / Windows / Recycle Bin
        / System Volume Information are never touched at all rather than being
        walked and filtered out afterwards. Reparse points (junctions/symlinks)
        are skipped to avoid loops. Returns a single List so the caller can know
        the total file count up front for an accurate progress bar without a
        second traversal pass.
    #>
    param(
        [string]$RootPath,
        [int]$MaxDepth,
        [bool]$ExcludeSystemPaths,
        [bool]$ExcludeEncryptedFiles
    )

    $results = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $Script:TraversalErrors = [System.Collections.Generic.List[hashtable]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@{ Path = $RootPath; Depth = 0 })

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()

        $dirInfo = $null
        try { $dirInfo = [System.IO.DirectoryInfo]::new($current.Path) } catch { continue }
        if (-not $dirInfo.Exists) { continue }

        try {
            foreach ($f in $dirInfo.EnumerateFiles()) {
                try {
                    $attrs = $f.Attributes
                    if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                    if ($ExcludeSystemPaths -and ($attrs -band [System.IO.FileAttributes]::System)) {
                        $Script:Stats.FilesExcludedSystem++; continue
                    }
                    if ($ExcludeEncryptedFiles -and ($attrs -band [System.IO.FileAttributes]::Encrypted)) {
                        $Script:Stats.FilesExcludedEncrypted++; continue
                    }
                    $results.Add($f)
                } catch {
                    $Script:Stats.AccessErrors++
                    $Script:TraversalErrors.Add(@{ Path = $current.Path; Message = $_.Exception.Message })
                }
            }
        } catch {
            $Script:Stats.AccessErrors++
            $Script:TraversalErrors.Add(@{ Path = $current.Path; Message = $_.Exception.Message })
        }

        if ($current.Depth -lt $MaxDepth) {
            try {
                foreach ($d in $dirInfo.EnumerateDirectories()) {
                    try {
                        if ($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                        if ($ExcludeSystemPaths) {
                            if (Test-PathExcluded -FullPath $d.FullName -LeafName $d.Name) {
                                $Script:Stats.DirsExcluded++; continue
                            }
                            if ($d.Attributes -band [System.IO.FileAttributes]::System) {
                                $Script:Stats.DirsExcluded++; continue
                            }
                        }
                        $stack.Push(@{ Path = $d.FullName; Depth = $current.Depth + 1 })
                    } catch {
                        $Script:Stats.AccessErrors++
                        $Script:TraversalErrors.Add(@{ Path = $d.FullName; Message = $_.Exception.Message })
                    }
                }
            } catch {
                $Script:Stats.AccessErrors++
                $Script:TraversalErrors.Add(@{ Path = $current.Path; Message = $_.Exception.Message })
            }
        }
    }

    return $results
}

function Invoke-FullScan {
    param([string]$Hostname, [string[]]$ScanPaths, [hashtable]$Config)
    Write-Host "`n[Phase 2+3] Content scan & vault detection..."
    $maxBytes = $Config.MaxFileSizeMB * 1MB

    $targetTotal = $ScanPaths.Count
    $targetIdx = 0
    $overallActivity = 'Credential Exposure Audit - Overall Progress'

    foreach ($scanRoot in $ScanPaths) {
        $targetIdx++
        if (-not (Test-Path $scanRoot -ErrorAction SilentlyContinue)) { continue }

        $targetPct = [int]((($targetIdx - 1) / [Math]::Max(1, $targetTotal)) * 100)
        Write-Progress -Id 1 -Activity $overallActivity `
            -Status "$targetPct% - Target $targetIdx / $targetTotal : $scanRoot" `
            -PercentComplete $targetPct

        $safeName = Sanitize-TargetName -Path $scanRoot
        $targetWriters = $Script:CsvWriters[$safeName]
        if (-not $targetWriters) {
            Write-Warning "No output writers for target: $scanRoot (sanitized: $safeName) - skipping"
            continue
        }
        $credWriter = $targetWriters['2_credentials.csv']
        $vaultWriter = $targetWriters['3_vaultfiles.csv']

        $activity = "Credential scan: $scanRoot"
        Write-Host "  Enumerating: $scanRoot (skipping system/program/recycle paths)..."
        Write-Progress -Id 2 -ParentId 1 -Activity $activity -Status 'Enumerating eligible files...' -PercentComplete 0

        $files = Get-EligibleFiles -RootPath $scanRoot -MaxDepth $Config.MaxDepth `
            -ExcludeSystemPaths $Config.ExcludeSystemPaths -ExcludeEncryptedFiles $Config.ExcludeEncryptedFiles
        $total = $files.Count
        Write-Host "  Scanning: $scanRoot  ($total file(s) eligible, $($Script:Stats.DirsExcluded) dir(s) excluded so far)"

        if ($credWriter -and $Script:TraversalErrors -and $Script:TraversalErrors.Count -gt 0) {
            foreach ($err in $Script:TraversalErrors) {
                Write-CsvRow -Writer $credWriter -Row @{
                    hostname=$Hostname; share_name=''; share_type=''
                    file_path=$err.Path; detection_type='access_error'
                    matched_pattern=''; severity='INFO'
                    context_snippet=$err.Message; language=''
                }
            }
        }

        if ($total -eq 0) {
            Write-Progress -Id 2 -ParentId 1 -Activity $activity -Completed
            continue
        }

        $processed = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $lastUpdateMs = 0

        foreach ($file in $files) {
            $processed++

            # Throttle progress UI updates themselves (every ~200ms or every 50 files,
            # whichever comes first) so Write-Progress doesn't add its own overhead.
            if (($sw.ElapsedMilliseconds - $lastUpdateMs) -ge 200 -or ($processed % 50) -eq 0 -or $processed -eq $total) {
                $pct = [int](($processed / $total) * 100)
                $elapsedTs = $sw.Elapsed
                $rate = if ($elapsedTs.TotalSeconds -gt 0) { $processed / $elapsedTs.TotalSeconds } else { 0 }

                if ($rate -gt 0) {
                    $etaSeconds = [Math]::Max(0, ($total - $processed) / $rate)
                    $etaStr = ([timespan]::FromSeconds($etaSeconds)).ToString('hh\:mm\:ss')
                } else {
                    $etaSeconds = -1
                    $etaStr = '--:--:--'
                }
                $rateStr = [math]::Round($rate, 1)
                $elapsedStr = $elapsedTs.ToString('hh\:mm\:ss')

                $status = "$pct% - $processed / $total files | $rateStr files/s | " +
                    "Elapsed $elapsedStr | ETA $etaStr | " +
                    "HIGH:$($Script:Stats.DetectionHigh) MED:$($Script:Stats.DetectionMedium) Vault:$($Script:Stats.VaultFiles)"

                $progressParams = @{
                    Id = 2; ParentId = 1; Activity = $activity
                    Status = $status; PercentComplete = $pct; CurrentOperation = $file.FullName
                }
                if ($etaSeconds -ge 0) { $progressParams['SecondsRemaining'] = [int]$etaSeconds }
                Write-Progress @progressParams

                # Mirror the overall bar's status too, so it reflects live throughput
                # even while sitting on a single (possibly very large) target.
                Write-Progress -Id 1 -Activity $overallActivity `
                    -Status "$targetPct% - Target $targetIdx / $targetTotal : $scanRoot ($pct% of this target)" `
                    -PercentComplete $targetPct

                $lastUpdateMs = $sw.ElapsedMilliseconds
            }

            try {
                if ($Config.ThrottleMs -gt 0) { Start-Sleep -Milliseconds $Config.ThrottleMs }

                if ($file.Length -gt $maxBytes) { $Script:Stats.FilesSkipped++; continue }
                $ext = $file.Extension.ToLower()

                # Vault file - emit to vault writer
                if ($VaultExtSet.Contains($ext)) {
                    $Script:Stats.VaultFiles++
                    if ($vaultWriter) {
                        Write-CsvRow -Writer $vaultWriter -Row @{
                            hostname=$Hostname; share_name=(Get-ShareNameFromPath -Path $file.FullName -ScanRoot $scanRoot)
                            share_type=''; file_path=$file.FullName
                            detection_type='vault_file'; matched_pattern=$ext.TrimStart('.'); severity='HIGH'
                            context_snippet="Vault/key file ($($file.Length) bytes): $($file.Name)"
                            language='en'
                        }
                    }
                    $Script:Stats.DetectionHigh++
                    continue
                }

                # Content scan - emit to credentials writer
                if ($TextExtSet.Contains($ext)) {
                    Scan-TextFile -Writer $credWriter -FilePath $file.FullName -ScanRoot $scanRoot
                } elseif ($OfficeExtSet.Contains($ext)) {
                    Scan-OfficeFile -Writer $credWriter -FilePath $file.FullName -ScanRoot $scanRoot
                } elseif ($ext -eq '.pdf') {
                    Scan-PdfFile -Writer $credWriter -FilePath $file.FullName -ScanRoot $scanRoot -FileSize $file.Length
                }
            } catch {
                if ($credWriter) {
                    Write-CsvRow -Writer $credWriter -Row @{
                        hostname=$Hostname; share_name=(Get-ShareNameFromPath -Path $file.FullName -ScanRoot $scanRoot)
                        share_type=''; file_path=$file.FullName
                        detection_type='access_error'; matched_pattern=''; severity='INFO'
                        context_snippet=$_.Exception.Message; language=''
                    }
                }
                $Script:Stats.AccessErrors++
            }
        }

        Write-Progress -Id 2 -ParentId 1 -Activity $activity -Completed
    }

    Write-Progress -Id 1 -Activity $overallActivity -Completed
}

###############################################################################
# Banner / Summary
###############################################################################

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Show-Banner {
    param([string]$Hostname, [string]$OutputDir, [hashtable]$Config)

    $border = '=' * 78
    $rule   = '-' * 78
    $isAdmin = Test-IsAdmin
    $psVer   = $PSVersionTable.PSVersion.ToString()
    $osVer   = [System.Environment]::OSVersion.VersionString
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { '(dot-sourced / interactive - no script path)' }
    $officeStatus = if ($Script:ZipAvailable) { 'Enabled' } else { 'Disabled (ZipFile assembly unavailable)' }
    $extraPaths = if ($Config.AdditionalScanPaths -and $Config.AdditionalScanPaths.Count -gt 0) {
        $Config.AdditionalScanPaths -join ', '
    } else { '(none)' }

    Write-Host ""
    Write-Host $border
    Write-Host "  CREDENTIAL EXPOSURE AUDIT PLATFORM - v2.2.0"
    Write-Host $border
    Write-Host "  Mode               : $Mode"
    Write-Host "  Hostname           : $Hostname"
    Write-Host "  Scan User          : $Script:ScanUser"
    Write-Host "  Elevated (Admin)   : $(if ($isAdmin) { 'Yes' } else { 'No - some shares/ACLs may be inaccessible' })"
    Write-Host "  PowerShell Version : $psVer"
    Write-Host "  OS Version         : $osVer"
    Write-Host "  Script Path        : $scriptPath"
    Write-Host "  Output Dir         : $OutputDir"
    Write-Host $rule
    Write-Host "  CONFIGURATION"
    Write-Host $rule
    Write-Host "  MaxFileSizeMB      : $($Config.MaxFileSizeMB)"
    Write-Host "  MaxDepth           : $($Config.MaxDepth)"
    Write-Host "  ThrottleMs         : $($Config.ThrottleMs)"
    Write-Host "  ExclSysShares      : $($Config.ExcludeSystemShares)"
    Write-Host "  ExclSysPaths       : $($Config.ExcludeSystemPaths) (Windows/Program Files/Recycle Bin/etc.)"
    Write-Host "  ExclEncrypted      : $($Config.ExcludeEncryptedFiles)"
    Write-Host "  Office Doc Scan    : $officeStatus"
    Write-Host "  Extra Scan Paths   : $extraPaths"
    Write-Host $rule
    Write-Host "  Start Time (UTC)   : $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host $border
    Write-Host ""
}

function Write-SummaryFile {
    param([string]$OutputDir, [string]$Hostname, [string[]]$Targets, [datetime]$StartTime)
    $elapsed = (Get-Date) - $StartTime
    $total = $Script:Stats.DetectionHigh + $Script:Stats.DetectionMedium + $Script:Stats.DetectionInfo

    $summaryPath = Join-Path $OutputDir 'summary.txt'
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Credential Exposure Audit - $Hostname")
    [void]$sb.AppendLine("==========================================")
    [void]$sb.AppendLine("Scan start:       $($StartTime.ToUniversalTime().ToString('o'))")
    [void]$sb.AppendLine("Scan end:         $([datetime]::UtcNow.ToString('o'))")
    [void]$sb.AppendLine("Duration:         $($elapsed.ToString('hh\:mm\:ss'))")
    [void]$sb.AppendLine("Mode:             $Mode")
    [void]$sb.AppendLine("Shares found:     $($Script:Stats.SharesFound)")
    [void]$sb.AppendLine("Files scanned:    $($Script:Stats.FilesScanned)")
    [void]$sb.AppendLine("Files skipped:    $($Script:Stats.FilesSkipped) (size limit)")
    [void]$sb.AppendLine("Dirs excluded:    $($Script:Stats.DirsExcluded) (system/program/recycle paths)")
    [void]$sb.AppendLine("Files excluded:   $($Script:Stats.FilesExcludedSystem) (system attrib), $($Script:Stats.FilesExcludedEncrypted) (encrypted)")
    [void]$sb.AppendLine("Office docs:      $($Script:Stats.OfficeScanned)")
    [void]$sb.AppendLine("PDFs scanned:     $($Script:Stats.PdfScanned)")
    [void]$sb.AppendLine("Vault files:      $($Script:Stats.VaultFiles)")
    [void]$sb.AppendLine("Access errors:    $($Script:Stats.AccessErrors)")
    [void]$sb.AppendLine("------------------------------------------")
    [void]$sb.AppendLine("Total detections: $total")
    [void]$sb.AppendLine("  HIGH:           $($Script:Stats.DetectionHigh)")
    [void]$sb.AppendLine("  MEDIUM:         $($Script:Stats.DetectionMedium)")
    [void]$sb.AppendLine("  INFO:           $($Script:Stats.DetectionInfo) (placeholders/env-var refs - not real exposures)")
    [void]$sb.AppendLine("------------------------------------------")
    [void]$sb.AppendLine("Targets scanned:")

    foreach ($target in $Targets) {
        $safeName = Sanitize-TargetName -Path $target
        $targetDir = Join-Path $OutputDir $safeName
        $shareCount = 0; $credCount = 0; $vaultCount = 0
        $shareFile = Join-Path $targetDir '1_open_shares.csv'
        $credFile  = Join-Path $targetDir '2_credentials.csv'
        $vaultFile = Join-Path $targetDir '3_vaultfiles.csv'
        if (Test-Path $shareFile) { $shareCount = [Math]::Max(0, ([System.IO.File]::ReadAllLines($shareFile)).Length - 1) }
        if (Test-Path $credFile)  { $credCount  = [Math]::Max(0, ([System.IO.File]::ReadAllLines($credFile)).Length - 1) }
        if (Test-Path $vaultFile) { $vaultCount = [Math]::Max(0, ([System.IO.File]::ReadAllLines($vaultFile)).Length - 1) }
        [void]$sb.AppendLine("  $target")
        [void]$sb.AppendLine("    shares: $shareCount | credentials: $credCount | vaults: $vaultCount")
    }

    [System.IO.File]::WriteAllText($summaryPath, $sb.ToString())

    Write-Host ""
    Write-Host $sb.ToString()
    Write-Host "Output directory: $OutputDir"
    Write-Host ""
    Write-Host "[*] Generated files:"
    foreach ($target in $Targets) {
        $safeName = Sanitize-TargetName -Path $target
        Write-Host "  $(Join-Path $OutputDir $safeName)\"
        Write-Host "    1_open_shares.csv"
        Write-Host "    2_credentials.csv"
        Write-Host "    3_vaultfiles.csv"
    }
}

###############################################################################
# Main
###############################################################################

function Main {
    $startTime = Get-Date

    if ([string]::IsNullOrEmpty($OutputPath)) {
        # $PSScriptRoot is blank in some contexts (dot-sourced, ISE older versions,
        # Invoke-Expression) - fall back to the current working directory in that case.
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
        $Script:OutputDir = Join-Path $scriptDir "dab17_scan_${Hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    } else {
        $Script:OutputDir = $OutputPath
    }

    if (-not (Test-Path $Script:OutputDir)) {
        New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null
    }

    $config = Load-Config -Path $ConfigPath
    Show-Banner -Hostname $Hostname -OutputDir $Script:OutputDir -Config $config

    $phase1TempPath = Initialize-Phase1Buffer -OutputDir $Script:OutputDir
    $targetArray = @()

    try {
        $sharePaths = @()
        try { $sharePaths = Invoke-ShareDiscovery -Hostname $Hostname -ExcludeSystem $config.ExcludeSystemShares }
        catch { Write-Error -ErrorAction Continue -Message "Phase 1 failed: $($_.Exception.Message)" }

        $allScanPaths = [System.Collections.Generic.List[string]]::new()
        $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sp in $sharePaths) {
            if ($sp -and $seenPaths.Add($sp)) { $allScanPaths.Add($sp) }
        }
        foreach ($ap in $config.AdditionalScanPaths) {
            if ($ap -and $seenPaths.Add($ap)) { $allScanPaths.Add($ap) }
        }
        foreach ($sp in $ScanPath) {
            if ($sp -and $seenPaths.Add($sp)) { $allScanPaths.Add($sp) }
        }

        $remotePaths = @()
        try { $remotePaths = Invoke-RemoteShareDiscovery -Paths @($allScanPaths) -ExcludeSystem $config.ExcludeSystemShares }
        catch { Write-Error -ErrorAction Continue -Message "Remote share discovery failed: $($_.Exception.Message)" }
        foreach ($rp in $remotePaths) {
            if ($rp -and $seenPaths.Add($rp)) { $allScanPaths.Add($rp) }
        }

        if ($Mode -eq 'interactive') {
            $allScanPaths = Select-ScanTargets -Paths $allScanPaths
        } else {
            Write-Host "`n  Scan targets: $($allScanPaths.Count) paths"
            foreach ($p in $allScanPaths) {
                $exists = if (Test-Path $p -ErrorAction SilentlyContinue) { '[OK]' } else { '[NOT FOUND]' }
                Write-Host "    $exists $p"
            }
        }

        $targetArray = @($allScanPaths)

        if ($targetArray.Count -eq 0) {
            Write-Host ""
            Write-Host "[!] ERROR: No scan targets found." -ForegroundColor Red
            Write-Host ""
            Write-Host "    In automated mode, targets come from:" -ForegroundColor Yellow
            Write-Host "      1) Non-system SMB shares discovered in Phase 1"
            Write-Host "      2) Config file 'AdditionalScanPaths' (-ConfigPath)"
            Write-Host "      3) -ScanPath arguments"
            Write-Host ""
            Write-Host "    Quick test:" -ForegroundColor Cyan
            Write-Host "      .\scan_credentials.ps1 -ScanPath C:\SomeFolder"
            Write-Host "      .\scan_credentials.ps1 -Mode interactive"
            Write-Host ""
            return
        }

        foreach ($target in $targetArray) {
            Initialize-TargetOutputDir -OutputDir $Script:OutputDir -TargetPath $target | Out-Null
        }

        Distribute-Phase1Results -TempPath $phase1TempPath -OutputDir $Script:OutputDir -Targets $targetArray

        try { Invoke-FullScan -Hostname $Hostname -ScanPaths $targetArray -Config $config }
        catch { Write-Error -ErrorAction Continue -Message "Phase 2/3 failed: $($_.Exception.Message)" }

    } finally {
        Close-AllWriters
        # Clean up Phase 1 writer if still open
        if ($Script:Phase1Writer) {
            try { $Script:Phase1Writer.Close(); $Script:Phase1Writer.Dispose() } catch {}
        }
    }

    Write-SummaryFile -OutputDir $Script:OutputDir -Hostname $Hostname -Targets $targetArray -StartTime $startTime
}

Main