<#
.SYNOPSIS
    Scans disk drives for plain text passwords in files.
.DESCRIPTION
    Recursively scans a specified disk drive for files containing plain text password patterns.
    Supports multiple password-related patterns and outputs findings to a CSV report.

    Patterns detected:
    - password=, pwd=, secret=, api_key=, apikey=, token=, credential=
    - Multilingual support: EN/FR/ES/PT/DE/IT/NL/TR

    The script skips system directories (Windows, Program Files, Recycle Bin, etc.) and
    EFS-encrypted files to avoid unnecessary noise and access errors.

.PARAMETER DriveLetter
    The disk drive to scan (e.g., 'D:', 'E:'). Must be a valid drive letter.

.PARAMETER OutputPath
    Optional path for the output report. Defaults to the script directory.

.PARAMETER IncludeExtensions
    Optional array of file extensions to include in the scan. Defaults to common text-based extensions.

.PARAMETER ExcludeExtensions
    Optional array of file extensions to exclude from the scan.

.PARAMETER ThrottleDelayMs
    Optional delay in milliseconds between file scans to reduce resource consumption. Defaults to 10ms.

.PARAMETER ProcessPriority
    Optional process priority to set for the scan. Valid values: Low, BelowNormal, Normal. Defaults to BelowNormal.

.PARAMETER Quiet
    Optional switch to suppress console output for automated runs. Output is still written to LogPath if specified.

.PARAMETER LogPath
    Optional path for a log file. All output is appended to this file for audit trails.

.EXAMPLE
    .\Invoke-PasswordScanner.ps1 -DriveLetter 'D:'
    Scans drive D: for plain text passwords and outputs to default location.

.EXAMPLE
    .\Invoke-PasswordScanner.ps1 -DriveLetter 'E:' -OutputPath 'C:\Reports'
    Scans drive E: and saves report to C:\Reports.

.EXAMPLE
    .\Invoke-PasswordScanner.ps1 -DriveLetter 'D:' -IncludeExtensions @('.txt', '.config', '.xml')
    Scans drive D: but only checks .txt, .config, and .xml files.

.EXAMPLE
    .\Invoke-PasswordScanner.ps1 -DriveLetter 'D:' -ThrottleDelayMs 50 -ProcessPriority Low
    Scans drive D: with reduced resource consumption.

.EXAMPLE
    .\Invoke-PasswordScanner.ps1 -DriveLetter 'D:' -Quiet -LogPath 'C:\Logs\scan.log'
    Runs silently with output logged to file for scheduled task automation.

.NOTES
    Author:  Security Audit Team
    Version: 1.0.0
    PowerShell Security Auditing Script

    Exit Codes:
    0 = Success, no findings
    1 = Error occurred
    2 = Success, findings detected
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^[A-Za-z]:$')]
    [string]$DriveLetter,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$OutputPath = $(if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }),

    [Parameter(Mandatory = $false)]
    [string[]]$IncludeExtensions = @('.txt', '.config', '.xml', '.json', '.ini', '.yaml', '.yml', '.env', '.conf', '.cfg', '.ps1', '.psm1', '.bat', '.cmd', '.csv', '.log', '.md'),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeExtensions = @('.exe', '.dll', '.bin', '.dat', '.zip', '.rar', '.7z', '.pdf', '.docx', '.xlsx', '.pptx'),

    [Parameter(Mandatory = $false)]
    [int]$ThrottleDelayMs = 10,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Low', 'BelowNormal', 'Normal')]
    [string]$ProcessPriority = 'BelowNormal',

    [Parameter(Mandatory = $false)]
    [switch]$Quiet,

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

begin {
    # Set error action preference
    $ErrorActionPreference = 'Stop'

    # Script metadata
    $script:ScriptVersion = '1.0.0'
    $script:ScriptAuthor = 'Security Audit Team'

    # Script-level exit code
    $script:ExitCode = 0

    # Display ASCII banner (unless quiet mode)
    if (-not $Quiet) {
        $banner = @"

    ================================================================
    |                                                              |
    |        PASSWORD SCANNER - PLAIN TEXT DETECTION TOOL          |
    |                                                              |
    |  Scanning for exposed credentials on disk drives            |
    |                                                              |
    |  Version: $($script:ScriptVersion.PadRight(10)) Author: $($script:ScriptAuthor)  |
    |                                                              |
    ================================================================

"@
        Write-Host $banner -ForegroundColor Cyan
    }

    # Logging helper function
    function Write-ScanLog {
        param(
            [string]$Message,
            [string]$ForegroundColor = 'White'
        )
        if (-not $Quiet) {
            Write-Host $Message -ForegroundColor $ForegroundColor
        }
        if ($LogPath) {
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
            Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
        }
    }

    # Initialize variables
    $script:ScanStartTime = Get-Date
    $script:ScanEndTime = $null
    $script:ScanUser = "$($env:USERDOMAIN)\$($env:USERNAME)"
    $script:Results = @()

    # Lower process priority to avoid consuming server resources
    try {
        $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($currentProcess) {
            $currentProcess.PriorityClass = $ProcessPriority
            Write-Verbose "Process priority set to: $ProcessPriority"
        }
    }
    catch {
        Write-Verbose "Could not set process priority: $($_.Exception.Message)"
    }

    # Password patterns to detect (multilingual)
    $script:PasswordPatterns = @(
        'password\s*=\s*\S+',
        'pwd\s*=\s*\S+',
        'secret\s*=\s*\S+',
        'api[_-]?key\s*=\s*\S+',
        'apikey\s*=\s*\S+',
        'token\s*=\s*\S+',
        'credential\s*=\s*\S+',
        'mot de passe\s*=\s*\S+',           # French
        'clave\s*=\s*\S+',                  # Spanish
        'senha\s*=\s*\S+',                  # Portuguese
        'passwort\s*=\s*\S+',               # German
        'parola\s*=\s*\S+',                 # Italian
        'wachtwoord\s*=\s*\S+',            # Dutch
        'şifre\s*=\s*\S+'                   # Turkish
    )

    # System paths to exclude
    $script:SystemPaths = @(
        'Windows',
        'Program Files',
        'Program Files (x86)',
        '$Recycle.Bin',
        'System Volume Information',
        'AppData',
        'Temp',
        'Temporary Internet Files'
    )

    # Validate drive exists
    if (-not (Test-Path $DriveLetter)) {
        throw "Drive '$DriveLetter' does not exist or is not accessible."
    }

    Write-Verbose "Starting password scan on drive: $DriveLetter"
    Write-Verbose "Output path: $OutputPath"
    Write-Verbose "Include extensions: $($IncludeExtensions -join ', ')"
}

process {
    try {
        # Get all files on the drive
        Write-ScanLog "Scanning drive $DriveLetter for files..." -ForegroundColor Cyan

        $allFiles = Get-ChildItem -Path $DriveLetter -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                # Exclude system paths
                $relativePath = $_.FullName
                $isSystemPath = $false
                foreach ($sysPath in $script:SystemPaths) {
                    if ($relativePath -match [regex]::Escape($sysPath)) {
                        $isSystemPath = $true
                        break
                    }
                }

                # Exclude encrypted files
                $isEncrypted = $_.Attributes -band [System.IO.FileAttributes]::Encrypted

                # Check extension filters
                $extension = $_.Extension.ToLower()
                $isExcluded = $ExcludeExtensions -contains $extension
                $isIncluded = $IncludeExtensions -contains $extension

                -not $isSystemPath -and -not $isEncrypted -and -not $isExcluded -and $isIncluded
            }

        $totalFiles = $allFiles.Count
        Write-ScanLog "Found $totalFiles files to scan after filtering." -ForegroundColor Green

        # Scan each file
        $fileIndex = 0
        foreach ($file in $allFiles) {
            $fileIndex++
            $percentComplete = if ($totalFiles -gt 0) { [math]::Round(($fileIndex / $totalFiles) * 100, 1) } else { 100 }

            if (-not $Quiet) {
                Write-Progress -Activity "Scanning for passwords on $DriveLetter" -Status "Checking: $($file.Name) ($fileIndex of $totalFiles)" -PercentComplete $percentComplete
            }

            try {
                # Read file content with error handling
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop

                # Check each pattern
                foreach ($pattern in $script:PasswordPatterns) {
                    $regexObj = [regex]::new($pattern)
                    $regexMatch = $regexObj.Match($content)
                    if ($regexMatch.Success) {
                        $script:Results += [PSCustomObject]@{
                            Hostname      = $env:COMPUTERNAME
                            DriveLetter   = $DriveLetter
                            FilePath      = $file.FullName
                            FileName      = $file.Name
                            Extension     = $file.Extension
                            DetectionType = 'PlainTextPassword'
                            MatchedPattern = $regexMatch.Value
                            Severity      = 'High'
                            ContextSnippet = $regexMatch.Value.Substring(0, [Math]::Min(100, $regexMatch.Value.Length))
                            ScanTime      = $script:ScanStartTime
                            ScanUser      = $script:ScanUser
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not read file: $($file.FullName) - $($_.Exception.Message)"
                continue
            }

            # Throttle to avoid consuming server resources
            if ($ThrottleDelayMs -gt 0) {
                Start-Sleep -Milliseconds $ThrottleDelayMs
            }
        }

        if (-not $Quiet) {
            Write-Progress -Activity "Scanning for passwords" -Completed
        }
    }
    catch {
        Write-Error "An error occurred during scanning: $($_.Exception.Message)"
        $script:ExitCode = 1
        throw
    }
}

end {
    # Record end time
    $script:ScanEndTime = Get-Date
    $duration = $script:ScanEndTime - $script:ScanStartTime

    # Generate output file
    $timestamp = $script:ScanStartTime.ToString('yyyyMMdd_HHmmss')
    $outputFileName = "password_scan_${($DriveLetter.TrimEnd(':'))}_$timestamp.csv"
    $outputFilePath = Join-Path -Path $OutputPath -ChildPath $outputFileName

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    # Export results
    if ($script:Results.Count -gt 0) {
        $script:Results | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
        Write-ScanLog "Scan complete. Found $($script:Results.Count) potential password exposures." -ForegroundColor Yellow
        $script:ExitCode = 2  # Findings detected
    }
    else {
        # Create empty report with headers
        $script:Results | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
        Write-ScanLog "Scan complete. No password exposures found." -ForegroundColor Green
    }

    Write-ScanLog "Report saved to: $outputFilePath" -ForegroundColor Cyan

    # Display timing information
    Write-ScanLog "`n=== Scan Timing ===" -ForegroundColor Cyan
    Write-ScanLog "Start Time: $($script:ScanStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-ScanLog "End Time:   $($script:ScanEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-ScanLog "Duration:   $($duration.ToString('hh\:mm\:ss\.fff')) (HH:mm:ss.fff)" -ForegroundColor White

    # Set exit code for automation
    if ($script:ExitCode -eq 0) {
        Write-ScanLog "Exit Code: 0 (Success, no findings)" -ForegroundColor Green
    }
    elseif ($script:ExitCode -eq 2) {
        Write-ScanLog "Exit Code: 2 (Success, findings detected)" -ForegroundColor Yellow
    }

    # Set process exit code for automation/scheduled tasks
    if ($script:ExitCode -ne 0) {
        exit $script:ExitCode
    }

    # Return results for pipeline use
    return $script:Results
}