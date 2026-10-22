# Checkov baseline for this repository

Result on 22 Oct 2026 (Terraform framework, org `.checkov.yaml`): **464 passed, 31 accepted** (listed below).
Re-run with `make scan`. New failures block the pipeline; the items below are reviewed and accepted.

| Check | Where | Why accepted | Revisit |
|---|---|---|---|
| CKV_AWS_272 (Lambda code signing) | findings-router, SOAR Lambdas | Code is built and deployed only by this repo's pipeline from protected `main`; AWS Signer profile planned with the Phase 2 artefact-signing work | Week 20 |
| CKV_AWS_355 / 356 / 111 / 290 / 289 / 287 (`Resource: "*"`) | KMS key policies; Security Hub `BatchUpdateFindings`; EC2 describe/revoke; IAM key deactivate; SNS/STS | KMS key policies always use `*` (= this key). Security Hub and EC2 describe APIs do not support resource-level permissions; remediation role must act on any bucket/SG/key in its account — scoped by trust policy to SOAR roles only, and every action is logged | Each policy review |
| CKV_AWS_18 (S3 access logging) | Log Archive bucket, state bucket | CloudTrail data events cover object access; access-logging the log bucket into itself would loop | — |
| CKV2_AWS_62 (event notifications) | Log Archive bucket, state bucket | Not needed; GuardDuty S3 protection + CloudTrail data events monitor access | — |
| CKV_AWS_144 (cross-region replication) | Log Archive bucket, state bucket | Security Lake replicates to roll-up region; Object Lock bucket is the compliance copy; evaluate CRR with AWS Backup in Phase 6 | Week 22 |
| CKV_AWS_252 (CloudTrail SNS topic) | org trail | Alerting is done via CloudWatch metric filters + Security Lake/SIEM, not per-file SNS | — |
