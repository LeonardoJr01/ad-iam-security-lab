<#
.SYNOPSIS
    Validates the lab against the controls defined in DESIGN.md.

.DESCRIPTION
    Each check reports PASS or FAIL. The script prints a summary and exits with
    code 0 when everything passes, 1 otherwise. Use -OutFile to save the report
    as text evidence.

    Not automated: account lockout. Generate it manually (three wrong logons)
    and capture Event ID 4740 in the Security log.

.PARAMETER OutFile
    Optional path of a text file to save the report to.

.EXAMPLE
    .\Test-ADLab.ps1 -OutFile C:\lab-outputs\compliance.txt

.NOTES
    ASCII-only. The audit check reads English auditpol output
    ("Success and Failure"); on a localized Windows adjust the pattern.
#>

[CmdletBinding()]
param(
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$Domain   = Get-ADDomain
$DomainDN = $Domain.DistinguishedName
$DnsRoot  = $Domain.DNSRoot

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Area, [string]$Check, [bool]$Passed, [string]$Detail = '')
    $Results.Add([pscustomobject]@{
        Result = $(if ($Passed) { 'PASS' } else { 'FAIL' })
        Area   = $Area
        Check  = $Check
        Detail = $Detail
    })
}

# ---------------------------------------------------------------- OUs

foreach ($dn in @(
        "OU=Admins,$DomainDN", "OU=Employees,$DomainDN", "OU=Services,$DomainDN", "OU=Groups,$DomainDN",
        "OU=Standard,OU=Employees,$DomainDN", "OU=Sensitive,OU=Employees,$DomainDN")) {
    $found = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)
    Add-Result 'OU' "Exists: $dn" $found
}

# ---------------------------------------------------------------- groups and users

$Expected = @(
    @{ Sam = 'adm.master';      Group = 'GG-Lab-Admins';       Path = "OU=Admins,$DomainDN" },
    @{ Sam = 'joao.silva';      Group = 'GG-Standard-Users';   Path = "OU=Standard,OU=Employees,$DomainDN" },
    @{ Sam = 'maria.santos';    Group = 'GG-Standard-Users';   Path = "OU=Standard,OU=Employees,$DomainDN" },
    @{ Sam = 'finance.manager'; Group = 'GG-Sensitive-Users';  Path = "OU=Sensitive,OU=Employees,$DomainDN" },
    @{ Sam = 'svc.backup';      Group = 'GG-Service-Accounts'; Path = "OU=Services,$DomainDN" }
)

foreach ($g in ($Expected | ForEach-Object { $_.Group } | Select-Object -Unique)) {
    $found = [bool](Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue)
    Add-Result 'Group' "Exists: $g" $found
}

foreach ($e in $Expected) {
    $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Sam)'" -Properties PasswordNeverExpires -ErrorAction SilentlyContinue
    if (-not $u) {
        Add-Result 'User' "Exists: $($e.Sam)" $false
        continue
    }
    Add-Result 'User' "$($e.Sam) is enabled" ([bool]$u.Enabled)
    Add-Result 'User' "$($e.Sam) is in the correct OU" ($u.DistinguishedName -like "*,$($e.Path)")

    $members = Get-ADGroupMember -Identity $e.Group | Select-Object -ExpandProperty SamAccountName
    Add-Result 'Membership' "$($e.Sam) is in $($e.Group)" ($members -contains $e.Sam)

    $expectedNeverExpires = ($e.Sam -eq 'svc.backup')
    Add-Result 'Exception' "$($e.Sam) PasswordNeverExpires = $expectedNeverExpires" ([bool]$u.PasswordNeverExpires -eq $expectedNeverExpires)
}

# ---------------------------------------------------------------- password policy

$p = Get-ADDefaultDomainPasswordPolicy -Identity $DnsRoot
Add-Result 'Password' 'Minimum length = 12'           ($p.MinPasswordLength -eq 12)                    "actual: $($p.MinPasswordLength)"
Add-Result 'Password' 'Complexity enabled'            ([bool]$p.ComplexityEnabled)                     "actual: $($p.ComplexityEnabled)"
Add-Result 'Password' 'Maximum age = 90 days'         ($p.MaxPasswordAge.Days -eq 90)                  "actual: $($p.MaxPasswordAge.Days)"
Add-Result 'Password' 'Minimum age = 1 day'           ($p.MinPasswordAge.Days -eq 1)                   "actual: $($p.MinPasswordAge.Days)"
Add-Result 'Password' 'History = 5'                   ($p.PasswordHistoryCount -eq 5)                  "actual: $($p.PasswordHistoryCount)"
Add-Result 'Password' 'Reversible encryption disabled' (-not [bool]$p.ReversibleEncryptionEnabled)     "actual: $($p.ReversibleEncryptionEnabled)"
Add-Result 'Lockout'  'Threshold = 3'                 ($p.LockoutThreshold -eq 3)                      "actual: $($p.LockoutThreshold)"
Add-Result 'Lockout'  'Observation window = 30 min'   ($p.LockoutObservationWindow.TotalMinutes -eq 30) "actual: $($p.LockoutObservationWindow.TotalMinutes)"
Add-Result 'Lockout'  'Duration = 30 min'             ($p.LockoutDuration.TotalMinutes -eq 30)         "actual: $($p.LockoutDuration.TotalMinutes)"

# ---------------------------------------------------------------- weak password is rejected

# The literal below is a deliberately weak test value, not a secret.
$testSam  = 'zz.weakpwd.test'
$rejected = $false
try {
    New-ADUser -Name $testSam -SamAccountName $testSam `
        -Path "OU=Standard,OU=Employees,$DomainDN" `
        -AccountPassword (ConvertTo-SecureString '123' -AsPlainText -Force) `
        -Enabled $true -ErrorAction Stop
}
catch {
    $rejected = $true
}
if (Get-ADUser -Filter "SamAccountName -eq '$testSam'" -ErrorAction SilentlyContinue) {
    Remove-ADUser -Identity $testSam -Confirm:$false
}
Add-Result 'Password' 'Weak password (123) is rejected' $rejected

# ---------------------------------------------------------------- auditing

$AuditChecks = @(
    @{ Name = 'Logon';                     Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Account Lockout';           Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Credential Validation';     Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'User Account Management';   Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}' }
)

foreach ($a in $AuditChecks) {
    $setting = ''
    try {
        $row = auditpol /get /subcategory:$($a.Guid) /r | ConvertFrom-Csv
        $setting = $row.'Inclusion Setting'
    }
    catch {
        $setting = 'error reading auditpol'
    }
    Add-Result 'Audit' "$($a.Name): success and failure" ($setting -match 'Success and Failure') "actual: $setting"
}

# ---------------------------------------------------------------- firewall

foreach ($fw in (Get-NetFirewallProfile)) {
    Add-Result 'Firewall' "$($fw.Name) profile enabled" ([string]$fw.Enabled -eq 'True') "actual: $($fw.Enabled)"
}

# ---------------------------------------------------------------- report

$failed = @($Results | Where-Object { $_.Result -eq 'FAIL' }).Count
$total  = $Results.Count

$report = New-Object System.Collections.Generic.List[string]
$report.Add("AD IAM Security Lab - compliance report")
$report.Add("Domain: $DnsRoot   Host: $env:COMPUTERNAME   Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
$report.Add('')
$report.Add(($Results | Format-Table Result, Area, Check, Detail -AutoSize -Wrap | Out-String -Width 200).TrimEnd())
$report.Add('')
$report.Add("Total: $total   Passed: $($total - $failed)   Failed: $failed")
$report.Add('Not automated: account lockout (manual evidence, Event ID 4740).')

$report | ForEach-Object { Write-Host $_ }

if ($OutFile) {
    $report | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Report saved to $OutFile"
}

if ($failed -gt 0) { exit 1 } else { exit 0 }
