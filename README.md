# Folder Audit Tool

![Folder Audit Tool](banner.svg)

PowerShell script to scan, analyze, and report folder structures with up to 3 levels of nesting.

**Author:** BNP Paribas IT  
**Date Created:** 2026-06-08  
**Date Modified:** 2026-06-08

## Features

- Scans `K:\FINANCE\FINANCE INTERNAL\Controlling` up to 3 child levels
- Records folder metadata: path, parent, name, depth, subfolder count, timestamps
- Exports results to a timestamped CSV file under `.\AuditReports\`
- Displays a real-time progress bar during scanning
- Resource-efficient: streams results through the pipeline and skips inaccessible paths

## Usage

```powershell
.\Audit-Folders.ps1
```

If needed, allow script execution first:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
.\Audit-Folders.ps1
```

## Output

The script creates a folder named `AuditReports` in the same directory as the script and saves a CSV file with the naming pattern:

```
AuditReports\FolderAudit_YYYYMMDD_HHMMSS.csv
```

### CSV Columns

| Column | Description |
|--------|-------------|
| FullName | Full path of the folder |
| ParentFolder | Name of the immediate parent folder |
| FolderName | Name of the folder |
| DepthLevel | Nesting level (1-3) |
| SubfolderCount | Number of immediate subfolders |
| CreationTime | Folder creation timestamp |
| LastWriteTime | Folder last modified timestamp |

## Version

Current version: **1.1.0**

See [PRD.md](PRD.md) for detailed requirements and changelog.
