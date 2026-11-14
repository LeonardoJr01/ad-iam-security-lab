# Lab Design: Active Directory for IAM

## 1. Objective

Build a lab Active Directory domain that demonstrates:

- An OU model that separates account types (administrative, standard, sensitive, service)
- Role-based groups, with access granted through groups rather than individual users
- Password and lockout policy aligned with good practice (NIST SP 800-63B, CIS)
- Auditing of logon events and group membership changes
- Reproducible provisioning with PowerShell

Out of scope for this phase: MFA, cloud integration (Entra ID), PAM, LAPS.

## 2. Architecture

| Item | Value |
|------|-------|
| Hypervisor | VirtualBox 7.x on Windows 11 |
| Operating system | Windows Server 2022 Standard (Desktop Experience) |
| VM name | DC01 |
| Domain | lab.local (NetBIOS: LAB) |
| Functional level | WinThreshold (2016+) |
| Network | Internal network or Host-only adapter, static IP 192.168.56.10 |
| DNS | Served by the DC itself (127.0.0.1) |

Network note: do not use NAT for the DC. With NAT, a client VM cannot resolve the domain or reach the DC, which blocks authentication tests from a second machine.

### OU structure

```
lab.local
├── Admins              ← administrative accounts (adm.*)
├── Users
│   ├── Standard        ← regular users
│   └── Sensitive       ← users with access to restricted data
├── Services            ← service accounts (svc.*)
└── Groups              ← security groups
```

Reason: GPOs and delegated permissions apply per OU. Keeping administrative accounts apart from regular ones allows a different policy for each and prevents an admin account from sitting alongside user workstations.

### Groups

| Group | Purpose | Initial members |
|-------|---------|-----------------|
| GG-Lab-Admins | Lab administration | adm.master |
| GG-Standard-Users | Basic access | joao.silva, maria.santos |
| GG-Sensitive-Users | Access to restricted data | finance.manager |
| GG-Service-Accounts | Service accounts | svc.backup |

Convention: the `GG-` prefix marks a global group by role. Permissions on resources are granted to groups, never to individual users.

## 3. Controls and decisions

| Control | Value | Rationale |
|---------|-------|-----------|
| Minimum length | 12 characters | NIST 800-63B favors length over rigid composition rules. 12 is a practical floor for a lab with complexity enabled. |
| Complexity | Enabled | Keeps compatibility with CIS-style audit checks and with environments that still require it. |
| Maximum age | 90 days | Common corporate baseline. Revisit if the organization adopts NIST guidance (no periodic expiry when MFA is in place). |
| History | 5 passwords | Prevents immediate reuse. |
| Lockout | 3 attempts in 30 min, 30 min lockout | Limits brute force without creating a trivial denial of service. |
| Initial password | Must change at first logon | No initial password defined for the lab is meant to be reused elsewhere. |
| Service accounts | Password never expires, documented exception | Services cannot change passwords interactively. Mitigation: long password, access restricted by group, periodic review. |
| Auditing | Logon and group management (success and failure) | Allows detection of access attempts and privilege changes. |

## 4. Secrets

- No password is written in the scripts. They prompt for passwords at run time (`Read-Host -AsSecureString`).
- Lab passwords are kept only in the author's password manager.
- If any test password was ever committed, treat it as compromised: change it and rewrite the history before making the repository public.

## 5. Execution plan

| Step | Deliverable | Suggested commit |
|------|-------------|------------------|
| 1 | DESIGN.md and initial README | `docs: initial lab design` |
| 2 | VM setup and DC promotion | `docs: domain controller installation steps` |
| 3 | OUs, groups and users | `feat: script to create OUs, groups and users` |
| 4 | Password policy and auditing | `feat: password policy and auditing` |
| 5 | Compliance validation | `test: control validation script` |
| 6 | Evidence and control-to-evidence table | `docs: README with evidence` |

## 6. Completion criteria

- `Test-ADLab.ps1` runs without errors on a freshly built VM
- Every control in section 3 has a matching piece of evidence in the README
- A weak password is rejected both on user creation and on password change
- Three wrong attempts generate event 4740 in the DC Security log
