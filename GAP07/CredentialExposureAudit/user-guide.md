# Invoke-CredentialExposureAudit.ps1 — User Guide

**Version covered:** 1.2.0
**Script type:** Pure PowerShell, no external dependencies, no modules required.

This guide covers three ways to run the script — manual (direct command line),
Interactive (guided menu), and Automated (headless, Ansible Tower) — plus
worked examples for scanning a drive letter with and without a specific file
excluded, and a troubleshooting section for the errors you are most likely
to hit.

---

## 1. Before You Start

### 1.1 Requirements

- Windows PowerShell 5.1 or later (built into Windows 8.1 / Server 2012 R2 and up)
- Read access to the paths or hosts you intend to scan
- For remote host discovery: WMI/DCOM access to the target, or PowerShell Remoting
  (WinRM) enabled, or at minimum `net view` connectivity
- No RSAT, no AD module, no SqlServer module — the script has zero external
  dependencies by design

### 1.2 Run As Administrator (recommended)

Local NTFS permission reads, remote WMI share enumeration, and `Get-Acl` calls
against admin shares all behave more reliably with an elevated session.
Right-click PowerShell → **Run as Administrator** before running any of the
examples below.

### 1.3 Execution Policy

If you see a message about scripts being disabled, run this once per session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This only affects the current PowerShell window and reverts when you close it.

### 1.4 Where Reports Go

By default, everything is written to:

```
%USERPROFILE%\Desktop\CredentialAudit\Session_<HOSTNAME>_<yyyyMMdd_HHmmss>\
```

Each scan target gets its own subfolder containing three CSVs:

| File | Contents |
|---|---|
| `open_shares.csv` | SMB/drive ACL findings, risk-scored |
| `credentials.csv` | Credential pattern matches (EN/SE/FR) |
| `vaultfiles.csv` | Detected password vault / key files |

A `session_summary.csv` is also written at the session root with totals and
scan identity (start time, user, hostname).

To change the default output location permanently, open the script and edit
the `$DefaultAuditRoot` variable near the top of **SECTION 0**. To override it
for a single run, use `-OutputFolder`.

---

## 2. Manual Mode (Direct Command Line)

"Manual" here means calling the script directly with explicit parameters —
no menus, no Ansible. This is the mode you'll use most often for one-off
audits from your own machine.

### 2.1 Simplest possible run (scan local machine)

```powershell
.\Invoke-CredentialExposureAudit.ps1
```

With no parameters at all, the script defaults to `-Mode Interactive` and
prompts you for targets (see Section 3). If you want a fully manual run with
no prompts, always pass `-Mode Automated` plus your target.

### 2.2 Scan a specific server's shares

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetHosts "SRV01"
```

### 2.3 Scan a specific UNC share directly (skip discovery)

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "\\SRV01\Finance"
```

### 2.4 All available parameters at a glance

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-Mode` | `Interactive` \| `Automated` | `Interactive` | Controls whether the script prompts you or runs headless |
| `-TargetHosts` | string[] | (none) | Hostnames/IPs to discover shares on |
| `-TargetShares` | string[] | (none) | Specific UNC paths or drive letters to scan directly |
| `-OutputFolder` | string | Desktop\CredentialAudit | Override the report destination |
| `-MaxFileSizeMB` | int | `50` | Skip files larger than this |
| `-RedactValues` | bool | `$true` | Redact matched values in the CSV |
| `-ThrottleMs` | int | `0` | Delay (ms) between file reads, for production servers |
| `-SkipPhase1` | switch | off | Skip share discovery / drive ACL analysis |
| `-SkipPhase2` | switch | off | Skip credential content scan |
| `-SkipPhase3` | switch | off | Skip vault file detection |
| `-ExcludePaths` | string[] | (none) | Exclude entire folders by path prefix |
| `-ExcludeFileNames` | string[] | (none) | Exclude specific file names anywhere in the tree (wildcards OK) |

---

## 3. Interactive Mode

Interactive mode discovers shares (or accepts drives/UNC paths you type in),
shows you a numbered menu, and lets you pick exactly which targets to scan.

### 3.1 Start interactive mode

```powershell
.\Invoke-CredentialExposureAudit.ps1
```

or explicitly:

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Interactive
```

### 3.2 What you'll be asked

If you didn't pass `-TargetHosts` or `-TargetShares`, the script prompts:

```
  Enter scan targets - any combination of:
    Hostnames  : SRV01, SRV02
    UNC paths  : \\SRV01\Finance
    Drive letters: H  or  H:  or  H:\
  Separate multiple entries with commas.
  Press ENTER to scan this machine only:

  Targets:
```

Type any combination, comma-separated, e.g.:

```
  Targets: SRV01, H:, \\SRV02\HR
```

Or press **Enter** with nothing typed to scan the local machine only.

### 3.3 The share selection menu

After discovery/drive analysis (Phase 1) completes, you'll see a table like:

```
  #    Host            Share Name                Risk       Reason
  -----------------------------------------------------------------------
  1    SRV01           Finance                   HIGH       Everyone has Read access
  2    SRV01           HR                        MEDIUM     Domain Users has Write access
  3    WORKSTATION01   H:\                        LOW        Access limited to specific named identities

  Enter the share numbers to scan (comma-separated),
  or type ALL to scan everything, or QUIT to exit:

  Selection:
```

Accepted answers:

| Input | Meaning |
|---|---|
| `2` | Scan only item #2 |
| `1,3` | Scan items #1 and #3 |
| `1-3` | Scan items #1 through #3 |
| `1,3-5` | Mix of single numbers and ranges |
| `ALL` | Scan every discovered item |
| `QUIT` | Exit without scanning anything further |

After you select, Phase 2 (credential scan) and Phase 3 (vault detection) run
against your chosen targets and CSVs are written per target.

---

## 4. Automated Mode (Headless / Ansible Tower)

Automated mode never prompts for input. Every target and option must be
supplied on the command line. This is what you point Ansible Tower's
**PowerShell module** or a **Run Command** template at.

### 4.1 Exit codes (important for Ansible)

| Code | Meaning |
|---|---|
| `0` | Completed, no findings — pipeline can proceed |
| `1` | Completed, findings present — trigger your remediation/alerting step |
| `2` | Fatal error — investigate before re-running |

### 4.2 Basic automated run

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetHosts "SRV01","SRV02"
```

### 4.3 Ansible Tower job template — PowerShell module example

```yaml
- name: Run credential exposure audit
  win_shell: |
    & "C:\Scripts\Invoke-CredentialExposureAudit.ps1" `
      -Mode Automated `
      -TargetHosts "SRV01","SRV02" `
      -OutputFolder "\\AuditServer\SecurityReports\CredentialAudit" `
      -ThrottleMs 25
  register: audit_result
  failed_when: audit_result.rc == 2
```

The `-ThrottleMs 25` example is recommended for production file servers being
scanned during business hours — it adds a small pause between file reads to
reduce I/O contention.

### 4.4 Skipping phases in automation

Run only the share/ACL audit (no content or vault scanning):

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetHosts "SRV01" `
    -SkipPhase2 -SkipPhase3
```

Run only the credential scan against a known-good share list (skip discovery):

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "\\SRV01\Finance","\\SRV02\HR" -SkipPhase1
```

---

## 5. Worked Example: Scanning Drive Letter H

This is the scenario most relevant to local or mapped network drives (e.g. a
departmental file share mapped as `H:` on a file server or workstation).

### 5.1 Accepted formats for a drive letter

All of these are equivalent — the script normalises them internally:

```powershell
-TargetShares "H"
-TargetShares "H:"
-TargetShares "H:\"
```

### 5.2 Example A — Scan H:\ and EXCLUDE "config.json"

Use `-ExcludeFileNames` to skip a specific file name anywhere in the scan
tree. This is filename-based (not path-based), so a single entry excludes
that file no matter how many subfolders contain a copy of it.

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" `
    -ExcludeFileNames "config.json"
```

What happens:
- Phase 1 reads the NTFS ACL on `H:\` and records risk-scored findings in
  `open_shares.csv`
- Phase 2 scans every matched file extension under `H:\` for credentials,
  **except** any file literally named `config.json`
- Phase 3 scans for vault/key files under `H:\`, also skipping `config.json`

You can exclude multiple file names, and wildcards are supported:

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" `
    -ExcludeFileNames "config.json","*.bak","secrets_template.*"
```

### 5.3 Example B — Scan H:\ and INCLUDE "config.json"

This is simply the same command with `-ExcludeFileNames` omitted — there is
no special "include" flag needed, since every matched file is scanned by
default unless you explicitly exclude it.

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:"
```

`config.json` (and every other file matching the scanned extension list)
will be fully included in the Phase 2 and Phase 3 results.

### 5.4 Example C — Same scan, but skip an entire folder instead of one file

If you want to exclude a whole folder (e.g. a known-clean archive directory)
rather than a single filename, use `-ExcludePaths` instead — it matches by
path prefix:

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" `
    -ExcludePaths "H:\Archive","H:\Backups"
```

You can combine both exclusion types in the same run:

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" `
    -ExcludePaths "H:\Archive" `
    -ExcludeFileNames "config.json","*.bak"
```

| Parameter | Matches on | Example |
|---|---|---|
| `-ExcludePaths` | Folder path prefix | `"H:\Archive"` excludes everything under that folder |
| `-ExcludeFileNames` | File name only, anywhere in the tree | `"config.json"` excludes that filename in every folder |

---

## 6. Additional Option Examples

### 6.1 Scan multiple drive letters in one run

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "H","K","L"
```

### 6.2 Redirect output to a network share (centralised reporting)

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetHosts "SRV01" `
    -OutputFolder "\\AuditServer\SecurityReports\CredentialAudit"
```

### 6.3 Increase the file size limit (default is 50 MB)

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" -MaxFileSizeMB 200
```

### 6.4 Show full match context instead of fully redacted values

By default, matches are fully redacted as `[REDACTED]` in the CSV. To show
the surrounding context with only the value masked:

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "H:" -RedactValues $false
```

> **Caution:** only disable redaction for reports that will stay strictly
> internal to the security team. Never disable it for reports that may be
> emailed, exported, or stored on a shared drive.

### 6.5 Throttle I/O for a busy production file server

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetShares "\\PRODFS01\Shared" -ThrottleMs 50
```

### 6.6 Combine everything: multi-target, exclusions, throttling, custom output

```powershell
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetHosts "SRV01","SRV02" `
    -TargetShares "H:" `
    -ExcludePaths "H:\Archive" `
    -ExcludeFileNames "config.json","*.bak" `
    -MaxFileSizeMB 100 `
    -ThrottleMs 25 `
    -OutputFolder "\\AuditServer\SecurityReports\CredentialAudit"
```

---

## 7. Troubleshooting / Common Errors

### 7.1 "running scripts is disabled on this system"

**Cause:** PowerShell's execution policy blocks unsigned scripts by default.

**Fix:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then re-run the script in the same window.

---

### 7.2 Script runs but finds 0 files / 0 shares

**Cause:** Usually one of:
- The account running the script lacks read access to the target
- `-ExcludePaths` is too broad and is excluding the entire target
- The target path doesn't actually exist or is offline

**Fix:**
- Re-run as Administrator
- Verify the path manually first: `Test-Path "H:\"`
- Temporarily remove `-ExcludePaths` / `-ExcludeFileNames` and re-test
- Check `session_summary.csv` — `ShareACEsFound`, `CredMatchesFound`, and
  `VaultFilesFound` will all read `0` if nothing was reachable

---

### 7.3 "The property 'Count' cannot be found on this object"

**Cause:** Historical bug in earlier single-purpose scanner versions — fixed
in this script via the comma-operator pattern (`return ,$result`) inside
`Get-FileLines`. If you see this error, you are running an outdated copy of
the script. Re-download the current version.

---

### 7.4 Progress bar appears stuck at 0% the whole scan

**Cause:** On very large shares, the progress bar updates every 200
(Phase 2) or 500 (Phase 3) files. If the share has fewer files than that
threshold, you may only see one update near the end. This is expected
behavior, not an error — check the console log lines for live activity in
the meantime.

---

### 7.5 "Access is denied" warnings during share discovery

**Cause:** WMI/DCOM, CIM, or `net view` could not reach the target with the
current credentials.

**Fix:**
- Confirm the account has at least read access to the target host's shares
- If discovery keeps failing, skip it and target the share directly:
  ```powershell
  .\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
      -TargetShares "\\SRV01\Finance" -SkipPhase1
  ```

---

### 7.6 Script exits with code 2 in Ansible

**Cause:** A fatal/unhandled error occurred (commonly: invalid output path,
or the account has no rights to create the session folder).

**Fix:**
- Run the exact same command manually outside Ansible first to see the full
  error text in the console
- Verify `-OutputFolder` is reachable and writable by the service account
- Check disk space on the destination

---

### 7.7 Drive letter not recognised / treated as a hostname

**Cause:** Typo in the drive format, or a single letter that collides with a
real hostname on your network (rare).

**Fix:** Use the explicit colon-backslash form to remove any ambiguity:
```powershell
-TargetShares "H:\"
```

---

### 7.8 CSV opens with garbled characters in Excel

**Cause:** Excel sometimes mis-detects encoding on UTF-8 files without a BOM.

**Fix:** Open Excel first, then use **Data → From Text/CSV** and explicitly
select UTF-8 as the file origin, rather than double-clicking the CSV file
directly.

---

### 7.9 Swedish or French credential text isn't being matched

**Cause:** The file is saved in an encoding the script's reader can't
auto-detect cleanly (rare, but possible with very old ANSI-saved files).

**Fix:** This is a known edge case — `Get-FileLines` falls back from UTF-8
to the system default code page automatically, but a third-party encoding
(e.g. ISO-8859-1 saved without a BOM) may still slip through. Re-save the
affected file as UTF-8 and re-run the scan if you suspect this is happening.

---

## 8. Quick Reference Card

```powershell
# Interactive, scan everything on local machine
.\Invoke-CredentialExposureAudit.ps1

# Automated, single host
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetHosts "SRV01"

# Automated, specific share
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "\\SRV01\Finance"

# Automated, drive H, excluding config.json
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "H:" -ExcludeFileNames "config.json"

# Automated, drive H, including everything
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "H:"

# Skip discovery, scan known shares directly
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetShares "\\SRV01\Finance" -SkipPhase1

# Share/ACL audit only, no content scanning
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated -TargetHosts "SRV01" -SkipPhase2 -SkipPhase3

# Full options example
.\Invoke-CredentialExposureAudit.ps1 -Mode Automated `
    -TargetHosts "SRV01" -TargetShares "H:" `
    -ExcludePaths "H:\Archive" -ExcludeFileNames "config.json","*.bak" `
    -MaxFileSizeMB 100 -ThrottleMs 25 `
    -OutputFolder "\\AuditServer\SecurityReports\CredentialAudit"
```

---

*This script is read-only and never modifies files, shares, or permissions.
Use only on systems you own or are explicitly authorised to audit. Treat all
generated CSV reports as confidential.*
