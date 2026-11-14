<#
.SYNOPSIS
    Provisions the OU structure, security groups and lab users for the AD IAM lab.

.DESCRIPTION
    Creates the OUs, global security groups and users described in DESIGN.md.
    The script is idempotent: objects that already exist are skipped.
    No password is stored in this file. Passwords are requested at run time.

    This file is intentionally ASCII-only so it runs the same way in Windows
    PowerShell 5.1 regardless of how it was saved or copied.

.NOTES
    Run on the domain controller as a Domain Admin (PowerShell as Administrator).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$Domain   = Get-ADDomain
$DomainDN = $Domain.DistinguishedName
$DnsRoot  = $Domain.DNSRoot

# ---------------------------------------------------------------- helpers

function Read-LabPassword {
    param([string]$Prompt)
    while ($true) {
        $secure = Read-Host $Prompt -AsSecureString
        $plain  = [System.Net.NetworkCredential]::new('', $secure).Password
        if ($plain.Length -ge 12) { return $secure }
        Write-Host '  Password must have at least 12 characters.' -ForegroundColor Yellow
    }
}

function Ensure-OU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue) {
        Write-Host "  [skip] OU $Name already exists"
    }
    else {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Host "  [ok]   OU $Name created" -ForegroundColor Green
    }
}

function Ensure-Group {
    param([string]$Name, [string]$Description, [string]$Path)
    if (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Host "  [skip] Group $Name already exists"
    }
    else {
        New-ADGroup -Name $Name -SamAccountName $Name `
            -GroupScope Global -GroupCategory Security `
            -Description $Description -Path $Path
        Write-Host "  [ok]   Group $Name created" -ForegroundColor Green
    }
}

function Ensure-User {
    param(
        [string]$Sam,
        [string]$GivenName,
        [string]$Surname,
        [string]$Path,
        [string]$Group,
        [securestring]$Password,
        [bool]$MustChangePassword = $true
    )

    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "  [skip] User $Sam already exists"
    }
    else {
        New-ADUser -Name "$GivenName $Surname" `
            -GivenName $GivenName -Surname $Surname `
            -SamAccountName $Sam -UserPrincipalName "$Sam@$DnsRoot" `
            -Path $Path -AccountPassword $Password `
            -Enabled $true -ChangePasswordAtLogon $MustChangePassword
        Write-Host "  [ok]   User $Sam created" -ForegroundColor Green
    }

    $members = Get-ADGroupMember -Identity $Group | Select-Object -ExpandProperty SamAccountName
    if ($members -notcontains $Sam) {
        Add-ADGroupMember -Identity $Group -Members $Sam
        Write-Host "         added to $Group"
    }
}

# ---------------------------------------------------------------- passwords

Write-Host "`n=== Passwords (not stored anywhere) ===" -ForegroundColor Cyan
$AdminPassword   = Read-LabPassword 'Initial password for adm.master (12+ chars)'
$UserPassword    = Read-LabPassword 'Initial password for standard and sensitive users (12+ chars)'
$ServicePassword = Read-LabPassword 'Password for svc.backup (12+ chars)'

# ---------------------------------------------------------------- OUs

Write-Host "`n=== Organizational Units ===" -ForegroundColor Cyan
Ensure-OU -Name 'Admins'    -Path $DomainDN
Ensure-OU -Name 'Users'     -Path $DomainDN
Ensure-OU -Name 'Services'  -Path $DomainDN
Ensure-OU -Name 'Groups'    -Path $DomainDN
Ensure-OU -Name 'Standard'  -Path "OU=Users,$DomainDN"
Ensure-OU -Name 'Sensitive' -Path "OU=Users,$DomainDN"

# ---------------------------------------------------------------- groups

Write-Host "`n=== Security groups ===" -ForegroundColor Cyan
$GroupsOU = "OU=Groups,$DomainDN"
Ensure-Group -Name 'GG-Lab-Admins'       -Description 'Lab administration'          -Path $GroupsOU
Ensure-Group -Name 'GG-Standard-Users'   -Description 'Basic access'               -Path $GroupsOU
Ensure-Group -Name 'GG-Sensitive-Users'  -Description 'Access to restricted data'  -Path $GroupsOU
Ensure-Group -Name 'GG-Service-Accounts' -Description 'Service accounts'            -Path $GroupsOU

# ---------------------------------------------------------------- users

Write-Host "`n=== Users ===" -ForegroundColor Cyan
Ensure-User -Sam 'adm.master'      -GivenName 'Admin'   -Surname 'Master'  `
    -Path "OU=Admins,$DomainDN"                 -Group 'GG-Lab-Admins'       -Password $AdminPassword

Ensure-User -Sam 'joao.silva'      -GivenName 'Joao'    -Surname 'Silva'   `
    -Path "OU=Standard,OU=Users,$DomainDN"      -Group 'GG-Standard-Users'   -Password $UserPassword

Ensure-User -Sam 'maria.santos'    -GivenName 'Maria'   -Surname 'Santos'  `
    -Path "OU=Standard,OU=Users,$DomainDN"      -Group 'GG-Standard-Users'   -Password $UserPassword

Ensure-User -Sam 'finance.manager' -GivenName 'Finance' -Surname 'Manager' `
    -Path "OU=Sensitive,OU=Users,$DomainDN"     -Group 'GG-Sensitive-Users'  -Password $UserPassword

Ensure-User -Sam 'svc.backup'      -GivenName 'Service' -Surname 'Backup'  `
    -Path "OU=Services,$DomainDN"               -Group 'GG-Service-Accounts' -Password $ServicePassword `
    -MustChangePassword $false

# ---------------------------------------------------------------- privileges

# Lab decision: GG-Lab-Admins is nested in Domain Admins so adm.master can administer the lab.
# In production, prefer delegated rights per OU instead of Domain Admins.
Write-Host "`n=== Privileged group membership ===" -ForegroundColor Cyan
$daMembers = Get-ADGroupMember -Identity 'Domain Admins' | Select-Object -ExpandProperty SamAccountName
if ($daMembers -notcontains 'GG-Lab-Admins') {
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'GG-Lab-Admins'
    Write-Host '  [ok]   GG-Lab-Admins added to Domain Admins' -ForegroundColor Green
}
else {
    Write-Host '  [skip] GG-Lab-Admins already in Domain Admins'
}

# ---------------------------------------------------------------- summary

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Domain: $DnsRoot"
Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDN |
    Select-Object Name, DistinguishedName | Format-Table -AutoSize
Get-ADGroup -Filter "Name -like 'GG-*'" |
    Select-Object Name, GroupScope | Format-Table -AutoSize
Get-ADUser -Filter * -SearchBase $DomainDN -Properties Enabled |
    Where-Object { $_.SamAccountName -match '^(adm|svc)\.|^(joao|maria|finance)\.' } |
    Select-Object SamAccountName, Enabled, DistinguishedName | Format-Table -AutoSize

Write-Host 'Setup complete.' -ForegroundColor Green
