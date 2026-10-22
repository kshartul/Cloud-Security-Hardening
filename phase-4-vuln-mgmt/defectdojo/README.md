# DefectDojo deployment (P4.2) and configuration (P4.3)

## Deployment (Security Tooling account)

| Component | Choice |
|---|---|
| Compute | ECS Fargate service: `defectdojo/defectdojo-django` (uwsgi) + `defectdojo/defectdojo-nginx`, Celery worker + beat tasks (same image) |
| Database | RDS PostgreSQL (Multi-AZ, KMS, IAM auth disabled, 35-day PITR) |
| Broker | ElastiCache Redis (TLS, auth token) |
| Ingress | **Internal** ALB in private subnets; reachable from corporate network/VPN and ADO self-hosted agents only; ACM cert; WAF ACL |
| Auth | SAML/OIDC SSO with Entra ID / Okta; local admin disabled after bootstrap |
| Secrets | `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, DB password in Secrets Manager, injected as ECS secrets |
| Backups | RDS snapshots + AWS Backup (copy to Log Archive vault) |
| Version pin | Pin image tag; upgrade monthly in a maintenance window (migrations run as one-off task) |

> Microsoft-hosted ADO agents cannot reach an internal ALB. Either use a self-hosted agent pool in the
> Infrastructure VPC for the upload step, or expose `/api/v2/` only through an API Gateway private integration
> with an IP allow-list for Azure DevOps service tags. Choose in ADR-002.

## Configuration

1. **Product types**: `Omni Platform`, `External attack surface`, `Cloud posture`.
2. **Products**: one per service/repo (auto-created by `push_to_defectdojo.py` with `auto_create_context`).
3. **Engagements**: `CI-<branch>` (CI/CD type), `DAST-baseline`, `DAST-api`, `Pentest-<year>`, `Nuclei-weekly`.
4. **Deduplication**: enable deduplication; algorithm `hash_code` for SARIF tools, `unique_id_from_tool` for Security Hub.
5. **SLA configuration**: import `sla_configuration.json` (matches the standard).
6. **Jira**: instance → project `SECVULN`, push Critical/High only, bidirectional status sync, "Finding ID" mapping.
7. **Security Hub import** (optional, for one-pane AppSec view): weekly `AWS Security Hub Scan` import per account.
8. **API key**: service account `ado-pipeline` with *Writer* on product type `Omni Platform`, key stored in ADO variable group linked to Key Vault.

## Notifications

Slack/Teams webhook for: new Critical, SLA breach, risk acceptance expiring.
