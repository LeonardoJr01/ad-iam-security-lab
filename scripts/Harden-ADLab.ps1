<#
.SYNOPSIS
    Applies the security controls defined in DESIGN.md (section 3).

.DESCRIPTION
    1. Domain password and account lockout policy
    2. Documented exception: svc.backup password never expires
    3. Advanced audit policy (logon, lockout, account and group management)
    4. Windows Firewall stays enabled on all profiles

    Audit subcategories are addressed by GUID so the script does not depend
    on the display language of Windows.
    The script is idempotent and ASCII-only (safe for Windows PowerShell 5.1).

.NOTES
    Run on the domain controller as a Domain Admin, after Setup-ADLab.ps1.
    auditpol changes the local policy of this DC. A GPO that defines audit
    settings can override it later, so confirm the effective result with
    Test-ADLab.ps1.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$DnsRoot = (Get-ADDomain).DNSRoot

# ---------------------------------------------------------------- 1. password policy

Write-Host "`n=== 1. Password and lockout policy ===" -ForegroundColor Cyan

Set-ADDefaultDomainPasswordPolicy -Identity $DnsRoot `
    -MinPasswordLength 12 `
    -ComplexityEnabled $true `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -PasswordHistoryCount 5 `
    -LockoutThreshold 3 `
    -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
    -LockoutDuration (New-TimeSpan -Minutes 30) `
    -ReversibleEncryptionEnabled $false

Get-ADDefaultDomainPasswordPolicy -Identity $DnsRoot |
    Format-List MinPasswordLength, ComplexityEnabled, MaxPasswordAge, MinPasswordAge,
                PasswordHistoryCount, LockoutThreshold, LockoutObservationWindow,
                LockoutDuration, ReversibleEncryptionEnabled

# ---------------------------------------------------------------- 2. service account exception

Write-Host "`n=== 2. Service account exception ===" -ForegroundColor Cyan

if (Get-ADUser -Filter "SamAccountName -eq 'svc.backup'" -ErrorAction SilentlyContinue) {
    Set-ADUser -Identity 'svc.backup' -PasswordNeverExpires $true
    Write-Host '  [ok]   svc.backup: password never expires (documented exception)' -ForegroundColor Green
}
else {
    Write-Host '  [warn] svc.backup not found. Run Setup-ADLab.ps1 first.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 3. auditing

Write-Host "`n=== 3. Audit policy ===" -ForegroundColor Cyan

$AuditSubcategories = @(
    @{ Name = 'Logon';                     Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Account Lockout';           Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Credential Validation';     Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'User Account Management';   Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}' }
)

foreach ($s in $AuditSubcategories) {
    auditpol /set /subcategory:$($s.Guid) /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for subcategory '$($s.Name)'"
    }
    Write-Host "  [ok]   $($s.Name): success and failure" -ForegroundColor Green
}

# ---------------------------------------------------------------- 4. firewall

Write-Host "`n=== 4. Windows Firewall ===" -ForegroundColor Cyan

Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize

Write-Host 'Hardening complete. Run Test-ADLab.ps1 to validate.' -ForegroundColor Green
