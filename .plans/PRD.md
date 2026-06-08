# PowerShell Folder Audit Script Plan

## Goal
Generate a PowerShell script that audits all folders under `K:\FINANCE\FINANCE INTERNAL\Controlling`, captures up to 3 levels of nesting, and exports the result as a CSV file into a dedicated folder under the script's execution directory.

## Requirements
- **Root path**: `K:\FINANCE\FINANCE INTERNAL\Controlling`
- **Depth**: Capture folders up to the 3rd child level (root -> level-1 -> level-2 -> level-3)
- **Output**: CSV report saved under a dedicated folder created at the script's execution location
- **Resource efficiency**: Use streaming/pipeline approaches, avoid loading entire trees into memory at once, and limit object properties to only what is needed

## Script Behavior
1. Determine the script's execution directory using `$PSScriptRoot` or `Split-Path -Parent $MyInvocation.MyCommand.Path`
2. Create an output folder (e.g., `AuditReports`) under that execution directory if it does not already exist
3. Enumerate all directories under `K:\FINANCE\FINANCE INTERNAL\Controlling` with a maximum depth of 3 levels
4. For each directory found, capture:
   - Full path
   - Parent folder name
   - Folder name
   - Depth level (1, 2, or 3)
   - Creation time (optional but useful for audit)
   - Last write time (optional but useful for audit)
5. Export the collected objects to a timestamped CSV file in the output folder
6. Run with minimal resource footprint by:
   - Using `Get-ChildItem -Directory` with `-Depth` or controlled recursion instead of recursive wildcard
   - Streaming output directly to `Export-Csv` via pipeline
   - Using `-ErrorAction SilentlyContinue` on paths that may be inaccessible to avoid breaking the pipeline

## Implementation Notes
- Use `Get-ChildItem -Path "K:\FINANCE\FINANCE INTERNAL\Controlling" -Directory -Recurse -Depth 3` to limit depth natively (PowerShell 5+ / Core)
- Build a calculated property set with only the needed fields to reduce memory overhead
- Name the CSV with a timestamp: `FolderAudit_YYYYMMDD_HHMMSS.csv`
- Wrap execution in a lightweight try/catch and use `-ErrorAction` to skip permission-denied folders without halting the script

## Validation
1. Run the script from a test directory
2. Confirm `AuditReports` folder is created under the script's location
3. Open the CSV and verify:
   - All level-1, level-2, and level-3 folders under `K:\FINANCE\FINANCE INTERNAL\Controlling` are present
   - No level-4+ folders are included
   - Columns match the planned schema
4. Verify the script completes quickly and does not spike CPU/memory in Task Manager

## Open Questions
- Should the CSV include the root `K:\FINANCE\FINANCE INTERNAL\Controlling` folder itself? **Recommendation: Yes, as level 0 or level 1.**
- Should inaccessible folders be silently skipped or logged to a separate error file? **Recommendation: Silently skip for simplicity; add error logging only if user requests it.**
