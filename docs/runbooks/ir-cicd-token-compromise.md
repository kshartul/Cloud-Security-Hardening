# IR runbook — Compromised CI/CD (Azure DevOps) token or service connection

**Triggers:** SIEM AWS-CICD-001, ADO audit alerts (service connection modified, new PAT with full scope, pipeline YAML change bypassing review),
Gitleaks hit for an ADO PAT, unexpected deploys outside change windows.

## 1. Contain

1. ADO: disable the affected service connection(s); revoke the PAT / OAuth token; pause pipelines for the project.
2. AWS: on every role trusting the ADO OIDC issuer for that connection → *Revoke active sessions*; temporarily tighten the
   trust policy `sub` condition to an impossible value.
3. If secrets were exposed via variable groups: rotate them (Key Vault / Secrets Manager).

## 2. Scope

* ADO audit log: who created/modified the token/connection, pipelines run, approvals bypassed, branch policy changes.
* CloudTrail: all `AssumeRoleWithWebIdentity` with that subject, then every action by the resulting sessions (stack updates, IAM changes, Lambda code updates).
* Diff deployed artefacts vs. git (Lambda code SHA256 vs. build artefacts; CloudFormation drift detection).

## 3. Eradicate / recover

Redeploy known-good versions from protected `main` via a clean pipeline run; re-create service connection with least-privilege role and
`sub` scoped to project/connection; enforce required reviewers on pipeline YAML; enable ADO "limit job authorization scope".

## 4. Learn

Annual CI/CD review (Phase 5) adds the gap; detection rule tuned.
