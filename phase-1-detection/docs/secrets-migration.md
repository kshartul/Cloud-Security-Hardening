# P1.8 — Secrets migration (serverless.yml / env vars → Secrets Manager / SSM)

## Rules

1. No secret values in `serverless.yml`, `.env`, Terraform variables, ADO variable groups (non-secret), or Lambda env vars.
2. Credentials (Redshift, RDS, third-party API keys) → **Secrets Manager** with a CMK (`alias/omni-secrets`) and rotation.
3. Non-credential config → **SSM Parameter Store** (`String`); sensitive config → `SecureString` with CMK.
4. Lambdas read at cold start via the **AWS Parameters and Secrets Lambda Extension** (cached) or Powertools `parameters`.
5. IAM: function role gets `secretsmanager:GetSecretValue` on its own secret ARN prefix only.

## Pattern

```yaml
# serverless.yml (before)
environment:
  REDSHIFT_PASSWORD: ${env:REDSHIFT_PASSWORD}     # ❌

# serverless.yml (after)
environment:
  REDSHIFT_SECRET_ARN: ${ssm:/omni/dw/redshift-secret-arn}   # ✅ ARN only
iamRoleStatements:
  - Effect: Allow
    Action: secretsmanager:GetSecretValue
    Resource: ${ssm:/omni/dw/redshift-secret-arn}
  - Effect: Allow
    Action: kms:Decrypt
    Resource: ${ssm:/omni/kms/secrets-key-arn}
```

```python
from aws_lambda_powertools.utilities import parameters
creds = parameters.get_secret(os.environ["REDSHIFT_SECRET_ARN"], transform="json", max_age=300)
```

## Rotation

* Redshift: use Secrets Manager managed rotation for Redshift (or `manage_master_password` on the cluster) — 30 days.
* DMS endpoints: reference the same secret (`SecretsManagerSecretId` + access role) so rotation needs no endpoint edit.
* Third-party API keys: 90-day manual rotation, Jira reminder via `exception_expiry` Lambda pattern.

## Migration checklist per repo

- [ ] `gitleaks detect` on full history; rotate anything found **before** removal
- [ ] Create secret in Terraform (value set out-of-band with `aws secretsmanager put-secret-value`)
- [ ] Update `serverless.yml` to ARN reference + least-privilege IAM
- [ ] Remove old ADO variable / env var
- [ ] Inspector Lambda code scanning shows no hard-coded secret findings
