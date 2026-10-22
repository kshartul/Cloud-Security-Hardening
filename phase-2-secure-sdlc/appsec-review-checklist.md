# AppSec review checklist (required for PRs touching IAM, auth, crypto, or new public routes)

Reviewer: security champion of the owning team (branch policy enforces for paths below).

Paths that trigger a champion review: `**/serverless.yml` (iamRoleStatements, http events),
`**/*.tf` with `aws_iam_*`/`aws_kms_*`, `src/**/auth*`, `src/**/crypto*`, `openapi/**`.

## Authentication & authorization
- [ ] Every new route has an authorizer and explicit scopes (no `authorizer: NONE` unless documented public endpoint)
- [ ] Object-level check (`assert_owner`/tenant check) before returning or mutating any record fetched by id
- [ ] Admin functionality lives on the private admin API

## Input & output
- [ ] Request model/validator defined (types, max lengths, max items, `additionalProperties: false`)
- [ ] Response model excludes internal fields
- [ ] Parameterised SQL only; no SQL/URL/path built from request data
- [ ] Errors return generic messages; details only in logs (no PII in logs)

## Secrets & crypto
- [ ] No secrets in code, env vars, serverless.yml, or test fixtures
- [ ] Uses domain CMK (`alias/omni-*`); no custom crypto

## IAM
- [ ] Function role: specific actions + resource ARNs; no `*` on `iam:`, `kms:`, `s3:`
- [ ] Access Analyzer gate passed (pipeline artefact `iam-policy-findings.json`)

## Resilience / abuse
- [ ] Reserved concurrency and throttling set; payload limits reviewed
- [ ] Idempotent handler for retried events

## Supply chain
- [ ] New dependency: maintained, licence allowed, no HIGH/CRITICAL CVE (Trivy)
- [ ] Lockfile updated; no git/URL dependencies
