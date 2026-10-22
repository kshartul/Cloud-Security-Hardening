# Suppression register

Every org-wide disabled control, automation-rule suppression, or scanner skip is listed here with an owner
and a review date. Individual risk exceptions live in Jira/Security Hub, not here.

| ID | Tool | Control / check | Scope | Reason | Ticket | Owner | Review by |
|---|---|---|---|---|---|---|---|
| SUP-001 | Security Hub | EKS.1, EKS.2 | Org | No EKS clusters in estate; re-enable automatically if EKS adopted (Config rule alerts on first cluster) | SEC-120 | Platform | 2027-04-30 |
| SUP-002 | Security Hub automation rule 20 | LOW findings | Sandbox OU | Noise reduction; sandbox has no data | SEC-121 | SecOps | 2027-01-31 |
| SUP-003 | Checkov | CKV_AWS_116 (Lambda DLQ) | Org default | EventBridge destinations / on-failure destinations used instead | SEC-142 | AppSec | 2027-01-31 |
| SUP-004 | Checkov | CKV_AWS_117 (Lambda in VPC) | Org default | Only functions needing private resources run in VPC; reviewed per function in threat model | SEC-143 | AppSec | 2027-01-31 |
| SUP-005 | Checkov | CKV_AWS_173 (Lambda env CMK) | Org default | No secrets in env vars by policy (Gitleaks + Inspector code scan enforce) | SEC-144 | AppSec | 2027-01-31 |
| SUP-006 | ZAP | 10020, 10038, 10055 (frame/CSP headers) | JSON APIs | Not applicable to JSON-only APIs | SEC-160 | AppSec | 2027-04-30 |
