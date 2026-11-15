# AD IAM Security Lab

A Windows Server 2022 Active Directory lab built to practice Identity and Access Management (IAM) fundamentals: organizational structure, role-based groups, password and lockout policy, auditing, and repeatable provisioning with PowerShell.

> **Status:** implemented and validated. All 48 automated checks pass. `dcdiag` passes 26 of 28 tests; the two failures are event-log tests and are explained under "Issues found and resolved".

## Goals

- Model a domain with a clear OU structure that separates administrative, standard, sensitive and service accounts.
- Grant access through role-based groups, never directly to individual users.
- Apply a password and account lockout policy aligned with NIST SP 800-63B and CIS guidance, and document the reasoning behind each value.
- Enable auditing for logon events and group membership changes.
- Provision everything with PowerShell so the lab can be rebuilt from scratch.
- Link every security control to a piece of verifiable evidence.

Out of scope for this phase: MFA, Entra ID integration, PAM, LAPS and GPO hardening. These are candidates for follow-up projects.

## Lab architecture

| Item | Value |
|------|-------|
| Hypervisor | Oracle VirtualBox on Windows 11 |
| Operating system | Windows Server 2022 Standard (Desktop Experience), evaluation edition |
| Hostname | `DC01` |
| Domain | `lab.local` (NetBIOS: `LAB`) |
| Functional level | Windows Server 2016 (`WinThreshold`) |
| Network | Static IP `192.168.1.10/24`, DC acts as its own DNS |

### OU structure

```
lab.local
├── Admins              administrative accounts
├── Employees
│   ├── Standard        standard users
│   └── Sensitive       users with access to restricted data
├── Services            service accounts
└── Groups              security groups
```

### Groups

| Group | Purpose |
|-------|---------|
| `GG-Lab-Admins` | Lab administration |
| `GG-Standard-Users` | Standard access |
| `GG-Sensitive-Users` | Access to restricted data |
| `GG-Service-Accounts` | Service accounts |

Full rationale and trade-offs are in [`DESIGN.md`](DESIGN.md).

## Security controls

| Control | Value | Rationale |
|---------|-------|-----------|
| Minimum password length | 12 characters | Length matters more than composition rules (NIST SP 800-63B) |
| Complexity | Enabled | Keeps compatibility with common audit baselines |
| Maximum password age | 90 days | Common corporate baseline; revisit if MFA is adopted |
| Password history | 5 | Prevents immediate reuse |
| Account lockout | 3 attempts / 30 min observation, 30 min lockout | Limits brute force without enabling trivial denial of service |
| First logon | Password change required | No initial password is reused |
| Service accounts | Password never expires, documented exception | Services cannot change passwords interactively; mitigated by long passwords and group-based restriction |
| Auditing | Logon and security group management, success and failure | Enables detection of access attempts and privilege changes |

## Secrets handling

No passwords are stored in this repository. Scripts prompt for credentials at run time (`Read-Host -AsSecureString`). Lab passwords are kept in a password manager.

## Control to evidence map

Each control is backed by a command anyone can run and an output file or screenshot.

| Control | Validation command | Evidence | Status |
|---------|--------------------|----------|--------|
| Domain and forest | `Get-ADDomain`, `Get-ADForest` | `docs/outputs/ad-domain.txt`, `docs/outputs/ad-forest.txt`, `docs/evidence/01-domain.png`, `docs/evidence/01-forest.png` | done |
| DNS resolution | `Resolve-DnsName lab.local` | `docs/outputs/dns.txt` | done |
| Firewall enabled | `Get-NetFirewallProfile` | `docs/outputs/firewall.txt`, `docs/evidence/02-firewall-enabled.png` | done |
| OU structure | `Get-ADOrganizationalUnit -Filter *` | `docs/outputs/ous.txt`, `docs/evidence/05-ou-structure.png` | done |
| Groups and membership | `Get-ADGroupMember -Identity <group>` | `docs/outputs/groups.txt`, `docs/outputs/users.txt` | done |
| Password policy | `Get-ADDefaultDomainPasswordPolicy` | `docs/outputs/password-policy.txt`, `docs/evidence/06-password-policy.png` | done |
| Weak password rejected | Attempt to set a weak password on a test user | `docs/evidence/03-weak-password.png` | done |
| Account lockout | 3 failed logons, then Event ID 4740 in the Security log | `docs/evidence/04-lockout-4740.png` | done |
| Auditing enabled | `auditpol /get /category:*` | `docs/outputs/auditpol.txt` | done |
| Service account exception | `Get-ADUser -Filter {PasswordNeverExpires -eq $true}` | `docs/outputs/service-accounts.txt` | done |
| Automated compliance | `scripts/Test-ADLab.ps1 -OutFile compliance.txt` | `docs/outputs/compliance.txt` (48 of 48 pass) | done |
| Domain controller health | `dcdiag` | `docs/outputs/dcdiag.txt` (26 of 28 tests pass, 2 known failures) | done |

Account lockout is validated manually because it needs real failed logons.

## Repository layout

```
.
├── README.md
├── DESIGN.md
├── scripts/
│   ├── Setup-ADLab.ps1      OUs, groups, users
│   ├── Harden-ADLab.ps1     password policy and auditing
│   └── Test-ADLab.ps1       compliance checks
└── docs/
    ├── evidence/            numbered screenshots
    └── outputs/             command output as text
```

## How to reproduce

Flow used to build and validate the lab:

1. Create a `DC01` VM in VirtualBox with Windows Server 2022, 4 GB RAM, 2 vCPUs and 30 GB disk.
2. Set a static IP, point DNS to `127.0.0.1` and rename the host to `DC01`.
3. Install AD DS and promote the server to a new forest (`lab.local`).
4. Run `scripts/Setup-ADLab.ps1`, then `scripts/Harden-ADLab.ps1`, then `scripts/Test-ADLab.ps1`.
5. Compare the output with the files in `docs/outputs/`.

The Windows Firewall stays enabled on all profiles (see `docs/outputs/firewall.txt`). The AD DS promotion creates the rules that AD DS and DNS need.

The scripts ask for three passwords at run time (administrative account, standard and sensitive users, service account), each with at least 12 characters.

## Issues found and resolved

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `Set-NetFirewallProfile -Enabled $false` fails with a `GpoBoolean` cast error | The parameter takes `True` or `False`, not a PowerShell boolean | Use `-Enabled True` or `-Enabled False` |
| A script fails to parse with "string is missing the terminator" | Non-ASCII characters in a file without BOM were read as Windows-1252 by Windows PowerShell 5.1, and one byte became a quotation mark | Scripts are ASCII-only |
| `New-ADOrganizationalUnit` fails with "name already in use" for `OU=Users` | The built-in `CN=Users` container uses the same name at the domain root | The OU was renamed to `Employees` |
| `dcdiag` fails the `DFSREvent` and `SystemLog` tests | The VM was shut down uncleanly (Windows logged unexpected shutdowns on 10 and 14 November) and both tests flag error events from the last 24 hours. Startup also logged DNS lookups timing out before the DNS service was ready, plus warnings about WinRM SPNs, DCOM permissions and the time provider | Evidence kept as generated. The other 26 tests pass, including replication, SYSVOL, NetLogon and RID manager. To clear the failures, shut the VM down from Windows and re-run after 24 hours of clean uptime. The logs are not cleared |
| First compliance run reported 6 failures | The copy of the test script inside the VM still used the old OU name | Test script updated; second run passed 48 of 48 |

## Known limitations

- The built-in `Administrator` account has a password that never expires (visible in `service-accounts.txt`). It is not remediated in this phase.
- `GG-Lab-Admins` is nested in `Domain Admins` to keep the lab simple. In production, rights would be delegated per OU.
- Audit settings are applied with `auditpol` on DC01 only; a GPO could override them later.
- No MFA, LAPS, GPO hardening or tiered administration yet.
- Single domain controller with an evaluation license.

## Roadmap

- [x] Design document
- [x] DC01 deployed and domain created
- [x] Provisioning script
- [x] Password policy and auditing
- [x] Compliance test script
- [x] Evidence and control map completed (`dcdiag`: 2 known event-log failures)
- [ ] Follow-up: GPO hardening, LAPS, Entra ID sync, MFA

## References

- [NIST SP 800-63B: Digital Identity Guidelines, Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Microsoft Learn: Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
