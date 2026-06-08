# PRD - Folder Audit Script
## VERSION
1.1.0

**Author:** Samuel Lamptey (BNP Paribas IT)  
**Date Created:** 2026-06-08  
**Date Modified:** 2026-06-08

## Overview
PowerShell script to audit folder structures under a defined root path and export results to CSV.

## Root Path
`K:\FINANCE\FINANCE INTERNAL`

## Scope
- Enumerates all directories up to **3 levels deep** from the root path.
- Outputs a timestamped CSV file under `.\AuditReports\` relative to the script execution directory.

## CSV Columns
| Column | Description |
|--------|-------------|
| FullName | Full path of the folder |
| ParentFolder | Name of the immediate parent folder |
| FolderName | Name of the folder |
| DepthLevel | Nesting level (1 = direct child of root, 2 = grandchild, 3 = great-grandchild) |
| SubfolderCount | Number of immediate subfolders under the folder |
| CreationTime | Folder creation timestamp |
| LastWriteTime | Folder last modified timestamp |

## Resource Considerations
- Uses `Get-ChildItem -Depth 3` to limit recursion depth natively.
- Streams results through the pipeline to `Export-Csv` to minimize memory footprint.
- Uses `-ErrorAction SilentlyContinue` to skip inaccessible paths without halting execution.

## Execution
Run `.\Audit-Folders.ps1` from PowerShell. Ensure execution policy permits script running if needed:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
.\Audit-Folders.ps1
```

## Changelog
- v1.1.0: Added scanning progress bar (`Write-Progress`) with percentage completion and folder count.
- v1.0.0: Initial implementation with folder enumeration, CSV export, and SubfolderCount column.
