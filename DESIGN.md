# Design do Lab: Active Directory para IAM

## 1. Objetivo

Construir um domínio Active Directory em laboratório que demonstre:

- Modelo de OUs separando tipos de conta (administrativa, usuário, serviço)
- Grupos por função, com concessão de acesso via grupo (não por usuário)
- Política de senha e bloqueio alinhada a boas práticas (NIST SP 800-63B, CIS)
- Auditoria de logon e alterações de grupo
- Provisionamento automatizado em PowerShell, reproduzível

Fora de escopo nesta fase: MFA, integração com cloud (Entra ID), PAM, LAPS.

## 2. Arquitetura

| Item | Valor |
|------|-------|
| Hypervisor | VirtualBox 7.x no Windows 11 |
| Sistema | Windows Server 2022 Standard (Desktop Experience) |
| Nome da VM | DC01 |
| Domínio | lab.local (NetBIOS: LAB) |
| Nível funcional | WinThreshold (2016+) |
| Rede | Adaptador interno (Host-only ou Rede Interna), IP estático 192.168.56.10 |
| DNS | Servido pelo próprio DC (127.0.0.1) |

Rede: não usar NAT para o DC. Com NAT, o cliente não resolve o domínio nem fica acessível para testes de autenticação a partir de outra VM.

### Estrutura de OUs

```
lab.local
├── Administradores      ← contas administrativas (adm.*)
├── Usuarios
│   ├── Padrao           ← usuários comuns
│   └── Sensivel         ← usuários com acesso a dados restritos
├── Servicos             ← contas de serviço (svc.*)
└── Grupos               ← grupos de segurança
```

Motivo: GPOs e permissões são aplicadas por OU. Separar contas administrativas das comuns permite aplicar política diferente em cada uma e evita que uma conta admin fique exposta em estações de usuário.

### Grupos

| Grupo | Função | Membros iniciais |
|-------|--------|------------------|
| GG-Admins-Lab | Administração do lab | adm.master |
| GG-Usuarios-Padrao | Acesso básico | joao.silva, maria.santos |
| GG-Usuarios-Sensivel | Acesso a dados restritos | financeiro.manager |
| GG-Servicos | Contas de serviço | svc.backup |

Convenção: `GG-` para grupos globais de função. Permissões em recursos são concedidas a grupos, nunca a usuários individuais.

## 3. Controles e decisões

| Controle | Valor | Justificativa |
|----------|-------|---------------|
| Comprimento mínimo | 12 caracteres | NIST 800-63B recomenda extensão a comprimento, não complexidade rígida. 12 é o piso prático para lab com complexidade habilitada. |
| Complexidade | Habilitada | Mantém compatibilidade com controles de auditoria do CIS e com ambientes que ainda exigem. |
| Idade máxima | 90 dias | Alinha com política corporativa comum. Revisar se a organização adotar NIST (sem expiração periódica quando há MFA). |
| Histórico | 5 senhas | Evita reutilização imediata. |
| Lockout | 3 tentativas em 30 min, bloqueio de 30 min | Limita brute force sem criar negação de serviço trivial. |
| Senha inicial | Troca no primeiro logon | Nenhuma senha inicial definida no script é reaproveitada em produção. |
| Contas de serviço | Senha sem expiração, documentada como exceção | Serviços não suportam troca interativa. Mitigação: senha longa, acesso restrito por grupo, revisão periódica. |
| Auditoria | Logon e gerenciamento de grupos (sucesso e falha) | Permite detectar tentativas de acesso e alteração de privilégio. |

## 4. Segredos

- Nenhuma senha é gravada nos scripts. Os scripts pedem as senhas em tempo de execução (`Read-Host -AsSecureString`).
- Senhas de laboratório ficam apenas no gerenciador de senhas do autor.
- Se alguma senha de teste tiver sido commitada, considerar comprometida: trocar e reescrever o histórico antes de tornar o repositório público.

## 5. Plano de execução

| Etapa | Entrega | Commit sugerido |
|-------|---------|-----------------|
| 1 | DESIGN.md e README inicial | `docs: design inicial do lab` |
| 2 | Setup da VM e promoção a DC | `docs: passo a passo de instalação do DC` |
| 3 | OUs, grupos e usuários | `feat: script de criação de OUs, grupos e usuários` |
| 4 | Política de senha e auditoria | `feat: política de senha e auditoria` |
| 5 | Validação de conformidade | `test: script de validação de controles` |
| 6 | Evidências e tabela controle → evidência | `docs: README com evidências` |

## 6. Critérios de conclusão

- `Test-ADLab.ps1` roda sem erro em uma VM recém-criada
- Cada controle da seção 3 tem uma evidência correspondente no README
- Uma senha fraca é rejeitada na criação e na troca
- Três tentativas erradas geram evento 4740 no Security log do DC
