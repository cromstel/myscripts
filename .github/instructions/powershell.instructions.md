---
description: "PowerShell coding conventions and best practices for security auditing scripts. Use when: writing PowerShell, creating scripts, modifying .ps1 files, security auditing, credential scanning."
applyTo: "**/*.ps1"
---
# PowerShell Coding Guidelines

## Script Structure
- Use `param()` block at the top for all parameters
- Include comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`
- Use `$PSScriptRoot` for relative paths
- Prefer functions over inline code

## Security Best Practices
- Never hardcode credentials or secrets
- Use `Get-Credential` or secure credential stores
- Validate all input parameters
- Use `ShouldProcess` for destructive operations
- Log actions with `Write-Verbose`, `Write-Debug`

## Error Handling
- Use `try/catch/finally` blocks
- Set `$ErrorActionPreference = 'Stop'` at script start
- Return meaningful error messages with context

## Code Style
- Use PascalCase for function names: `Get-CredentialStatus`
- Use camelCase for variables: `$credentialPath`
- Prefer pipeline-friendly output
- Use `Write-Output` instead of `Write-Host` for data

## Common Patterns
- Use `Test-Path` before file operations
- Use `Get-ChildItem -Recurse` for file discovery
- Prefer `Where-Object` over `Where` alias
- Use `$null =` to suppress output when needed