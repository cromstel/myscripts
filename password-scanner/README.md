# Password Scanner

PowerShell script for scanning disk drives for plain text passwords in files.

## Usage

```powershell
.\Invoke-PasswordScanner.ps1 -DriveLetter 'D:'
.\Invoke-PasswordScanner.ps1 -DriveLetter 'E:' -OutputPath 'C:\Reports'
.\Invoke-PasswordScanner.ps1 -DriveLetter 'D:' -IncludeExtensions @('.txt', '.config', '.xml')
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `DriveLetter` | Yes | The disk drive to scan (e.g., 'D:', 'E:') |
| `OutputPath` | No | Path for the output report. Defaults to script directory |
| `IncludeExtensions` | No | File extensions to include in scan |
| `ExcludeExtensions` | No | File extensions to exclude from scan |

## Patterns Detected

- `password=`, `pwd=`, `secret=`
- `api_key=`, `apikey=`, `token=`, `credential=`
- Multilingual: French, Spanish, Portuguese, German, Italian, Dutch, Turkish

## Output

CSV report with columns:
- Hostname, DriveLetter, FilePath, FileName, Extension
- DetectionType, MatchedPattern, Severity, ContextSnippet
- ScanTime, ScanUser