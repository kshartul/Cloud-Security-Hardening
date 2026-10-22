# Threat model — omni-dw-api-services (draft for workshop)

## Context

REST API (API Gateway + Python Lambdas, Serverless Framework v3) serving data-warehouse
read endpoints to internal apps and selected B2B partners. Data lives in Redshift (fed by DMS CDC)
and S3 staging. Deployed via Azure DevOps.

## Data flow (trust boundaries marked ‖)

```
Internal app / B2B partner ‖ WAF → API Gateway (authorizer) ‖ Lambda (VPC) ─► Redshift (Data API / driver)
                                                            └─► S3 staging (KMS)
                                                            └─► Secrets Manager (DB creds)
ADO pipeline ‖ OIDC → deploy role ‖ CloudFormation stack
DMS replication ‖ source DB ─► Redshift
```

## Threats (initial)

| ID | Element | STRIDE | Threat | Rating | Mitigation (control / ticket) |
|---|---|---|---|---|---|
| T1 | API → Lambda | S | API key used as sole authentication by partner | High | Replace with Cognito client-credentials + scopes (P3.5) |
| T2 | Lambda | I | `GET /orders/{id}` returns rows for other tenants (BOLA) | High | `authz.assert_owner` + unit tests (P3.10), Semgrep `kf-missing-owner-check` |
| T3 | Lambda → Redshift | T/I | SQL built with f-strings from query params | High | Parameterised queries; Semgrep `kf-sql-string-concat-execute` gate |
| T4 | API | D | Unbounded `limit` param causes large Redshift scans | Medium | Request validator max=1000, WLM queue timeout, usage plan |
| T5 | Lambda env | I | Redshift password in env var / serverless.yml | High | Secrets Manager + rotation (P1.8) |
| T6 | Pipeline | E | Deploy role can modify IAM beyond stack | Medium | Permission boundary on CFN-created roles, OIDC subject scoped to repo/branch |
| T7 | API GW | R | No principal in access logs | Medium | JSON access log with `$context.authorizer.claims.sub` (P3.5) |
| T8 | Lambda | I | Exceptions returned to callers leak schema | Low | Generic errors; Semgrep `kf-lambda-returns-exception-detail` |
| T9 | DMS | I | Replication instance publicly accessible | Medium | SCP + Config rule `dms-replication-not-public` |
| T10 | S3 staging | I | Bucket policy allows `*` principal within account | Medium | Access Analyzer + bucket policy restricted to function roles |

## Open questions for the workshop

1. Which partners still use API keys? Migration deadline?
2. Is any endpoint returning PII? Classification of each route.
3. Do any Lambdas call third-party URLs (egress allow-list scope)?
