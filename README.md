# AD IAM Security Lab

A Windows Server 2022 Active Directory lab built to practice Identity and Access Management (IAM) fundamentals: organizational structure, role-based groups, password and lockout policy, auditing, and repeatable provisioning with PowerShell.

> **Status:** work in progress. The design is documented; implementation, scripts and evidence are being added step by step. Sections marked `pending` are not yet done.

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
| Network | Internal or host-only adapter, static IP, DC acts as its own DNS |

### OU structure

```
lab.local
├── Administradores     administrative accounts
├── Usuarios
│   ├── Padrao          standard users
│   └── Sensivel        users with access to restricted data
├── Servicos            service accounts
└── Grupos              security groups
```

### Groups

| Group | Purpose |
|-------|---------|
| `GG-Admins-Lab` | Lab administration |
| `GG-Usuarios-Padrao` | Standard access |
| `GG-Usuarios-Sensivel` | Access to restricted data |
| `GG-Servicos` | Service accounts |

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

Each control is meant to be backed by a command anyone can run and an output file or screenshot.

| Control | Validation command | Evidence | Status |
|---------|--------------------|----------|--------|
| OU structure | `Get-ADOrganizationalUnit -Filter *` | `docs/saidas/ous.txt` | pending |
| Groups and membership | `Get-ADGroupMember -Identity <group>` | `docs/saidas/grupos.txt` | pending |
| Password policy | `Get-ADDefaultDomainPasswordPolicy` | `docs/saidas/password-policy.txt` | pending |
| Weak password rejected | Attempt to set `123` on a test user | `docs/evidencias/03-weak-password.png` | pending |
| Account lockout | 3 failed logons, then Event ID 4740 in the Security log | `docs/evidencias/04-lockout-4740.png` | pending |
| Auditing enabled | `auditpol /get /category:*` | `docs/saidas/auditpol.txt` | pending |
| Service account exception | `Get-ADUser -Filter {PasswordNeverExpires -eq $true}` | `docs/saidas/service-accounts.txt` | pending |

## Repository layout

```
.
├── README.md
├── DESIGN.md
├── scripts/
│   ├── Setup-ADLab.ps1      OUs, groups, users (planned)
│   ├── Harden-ADLab.ps1     password policy and auditing (planned)
│   └── Test-ADLab.ps1       compliance checks (planned)
└── docs/
    ├── evidencias/          numbered screenshots
    └── saidas/              command output as text
```

## How to reproduce

Planned flow once the scripts are published:

1. Create a `DC01` VM in VirtualBox with Windows Server 2022, 4 GB RAM, 2 vCPUs and 30 GB disk.
2. Set a static IP, point DNS to `127.0.0.1` and rename the host to `DC01`.
3. Install AD DS and promote the server to a new forest (`lab.local`).
4. Run `scripts/Setup-ADLab.ps1`, then `scripts/Harden-ADLab.ps1`, then `scripts/Test-ADLab.ps1`.
5. Compare the output with the files in `docs/saidas/`.

The Windows Firewall stays enabled. Only the ports required by AD DS and DNS are allowed (53, 88, 135, 389, 445, 464, 636, 3268, 3269 and the dynamic RPC range).

## Roadmap

- [x] Design document
- [ ] DC01 deployed and domain created
- [ ] Provisioning script
- [ ] Password policy and auditing
- [ ] Compliance test script
- [ ] Evidence and control map completed
- [ ] Follow-up: GPO hardening, LAPS, Entra ID sync, MFA

## References

- [NIST SP 800-63B: Digital Identity Guidelines, Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Microsoft Learn: Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
