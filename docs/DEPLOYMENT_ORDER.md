# Deployment order

Each row is one Terraform stack (own state key). Apply strictly top-to-bottom the first time;
afterwards the pipeline in `pipelines/azure-pipelines.yml` plans every stack on each PR and applies only changed ones.

| # | Stack path | Run in account | Role assumed | Week | Notes |
|---|---|---|---|---|---|
| 0 | `phase-0-foundation/terraform/stacks/bootstrap-state` | Security Tooling | `SecurityPipelineDeploy` | 1 | S3 state bucket (versioned, KMS, native lockfile); run once with local state, then migrate |
| 1 | `phase-0-foundation/terraform/stacks/organization` | Management | `SecurityPipelineDeploy` | 1 | OUs, SCPs (attached to Sandbox only via `scp_attach_ous`) |
| 2 | *(console)* Control Tower landing zone | Management | admin | 2 | See `docs/runbooks/control-tower-enrolment.md` |
| 3 | `phase-0-foundation/terraform/stacks/log-archive` | Log Archive | `SecurityPipelineDeploy` | 2 | Object Lock bucket, KMS logs key, bucket policies |
| 4 | `phase-0-foundation/terraform/stacks/org-trail` | Management | `SecurityPipelineDeploy` | 2 | Org CloudTrail → Log Archive bucket |
| 5 | `phase-0-foundation/terraform/stacks/identity-center` | Management | `SecurityPipelineDeploy` | 2–3 | Permission sets & assignments (groups from IdP via SCIM) |
| 6 | `phase-0-foundation/terraform/stacks/account-baseline` | every account (for_each via provider alias / pipeline matrix) | `SecurityPipelineDeploy` | 3 | S3 BPA, EBS encryption, IMDSv2 defaults, password policy, KMS domain keys |
| 7 | `phase-0-foundation/terraform/stacks/delegated-admins` | Management | `SecurityPipelineDeploy` | 3 | Registers Security Tooling for all services |
| 8 | `phase-1-detection/terraform/stacks/security-tooling` | Security Tooling | `SecurityPipelineDeploy` | 4–5 | `security-baseline` module (SH, GD, Inspector, Config agg., Macie, Detective, FMS admin) |
| 9 | `phase-3-dast-api/terraform/stacks/fms-waf` | Security Tooling | `SecurityPipelineDeploy` | 9 | WAF ACL policy via FMS (count first) |
| 10 | `phase-4-vuln-mgmt/terraform/stacks/findings-routing` | Security Tooling | `SecurityPipelineDeploy` | 11 | EventBridge rules, router/expiry/jira-sync Lambdas |
| 11 | `phase-4-vuln-mgmt/defectdojo` | Security Tooling | `SecurityPipelineDeploy` | 11 | ECS Fargate + RDS |
| 12 | `phase-5-pentest/terraform/pentest-access` | in-scope accounts | `SecurityPipelineDeploy` | 15 | Created per engagement, destroyed after |
| 13 | `phase-6-integration/terraform/stacks/security-lake` | Log Archive (delegated admin) | `SecurityPipelineDeploy` | 16 | Security Lake + subscriber |
| 14 | `phase-6-integration/terraform/stacks/response` | Security Tooling + workload role stack | `SecurityPipelineDeploy` | 18–22 | Alert routing, SOAR, remediation roles |

## SCP promotion

Change `scp_attach_ous` in `phase-0-foundation/terraform/stacks/organization/terraform.tfvars`:

```hcl
# week 3 day 1
scp_attach_ous = ["sandbox"]
# day 3 (after 72h AccessDenied review)
scp_attach_ous = ["sandbox", "dev"]
# day 6
scp_attach_ous = ["sandbox", "dev", "stage"]
# week 4 (CAB)
scp_attach_ous = ["sandbox", "dev", "stage", "prod", "security", "infrastructure"]
```

## Security Hub configuration policy promotion

`phase-1-detection/terraform/stacks/security-tooling/terraform.tfvars` → `policy_target_ous` follows the same pattern.
