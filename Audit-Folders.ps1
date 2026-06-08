<#
.SYNOPSIS
    Audits folders under K:\FINANCE\FINANCE INTERNAL\Controlling up to 3 levels deep and exports results to CSV.
.VERSION
    1.1.0
#>

$ErrorActionPreference = 'SilentlyContinue'
$ScriptVersion = '1.1.0'
$ScriptVersion = '1.0.0'

$RootPath = 'K:\FINANCE\FINANCE INTERNAL\Controlling'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$outputDir = Join-Path $scriptDir 'AuditReports'

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputFile = Join-Path $outputDir ('FolderAudit_{0}.csv' -f $timestamp)

Write-Host ('Folder Audit Script v{0}' -f $ScriptVersion)
Write-Host ('Root Path : {0}' -f $RootPath)
Write-Host ''

$allDirs = Get-ChildItem -LiteralPath $RootPath -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue
$total = $allDirs.Count
$counter = 0

$results = foreach ($dir in $allDirs) {
    $counter++
    $percent = [math]::Round(($counter / $total) * 100, 1)
    Write-Progress -Activity 'Scanning folders' -Status ('{0}% complete ({1} of {2})' -f $percent, $counter, $total) -PercentComplete $percent

    [PSCustomObject]@{
        FullName        = $dir.FullName
        ParentFolder    = Split-Path -Path $dir.FullName -Parent | Split-Path -Leaf
        FolderName      = $dir.Name
        DepthLevel      = ($dir.FullName.Split('\').Count) - ($RootPath.Split('\').Count)
        SubfolderCount  = (Get-ChildItem -LiteralPath $dir.FullName -Directory -ErrorAction SilentlyContinue).Count
        CreationTime    = $dir.CreationTime
        LastWriteTime   = $dir.LastWriteTime
    }
}

Write-Progress -Activity 'Scanning folders' -Completed

$results | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host ('Audit complete. {0} folders recorded.' -f $results.Count)
Write-Host ('Report saved to: {0}' -f $outputFile)
