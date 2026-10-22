# Secure SDLC Standard

| | |
|---|---|
| Owner | Security (AppSec) |
| Approver | CISO delegate |
| Applies to | Every repository that deploys to AWS through Azure DevOps |
| Effective | Week 9 of the hardening program (tier-1), week 12 (all) |

## 1. Requirements

| # | Requirement | Verified by |
|---|---|---|
| S1 | Pipelines extend `security-scan.yml` at a pinned tag | ADO pipeline audit script (KPI) |
| S2 | No secrets in source, history, pipeline variables (non-secret), or Lambda env vars | Gitleaks, Inspector Lambda code scanning |
| S3 | New CRITICAL/HIGH SAST, SCA (with fix), IaC, IAM findings block merge | Security stage |
| S4 | Every release has a CycloneDX SBOM | Artefact + Dependency-Track |
| S5 | Tier-1 services have a current threat model (≤ 12 months or since last major change) | Repo `docs/threat-model/` |
| S6 | Changes to IAM, auth, crypto, or new public routes require a security-champion review | Branch policy |
| S7 | APIs publish an OpenAPI spec that passes the lint gate | `api-lint.yml` |
| S8 | Staging receives DAST after each deploy (baseline) and nightly (full API scan) | `dast-zap.yml` |
| S9 | Suppressions reference a ticket and expire ≤ 90 days | Ignore-file review, DefectDojo |
| S10 | ADO → AWS authentication uses OIDC service connections only | ADO service-connection inventory |

## 2. Exceptions

Raised in Jira `SECVULN` (type *Exception*), approved per the Vulnerability Management Standard §6.

## 3. Training

Security champions: OWASP Top 10 + API Top 10 + this standard within 30 days of nomination; annual refresh.
