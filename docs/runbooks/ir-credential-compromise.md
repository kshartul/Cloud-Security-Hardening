# IR runbook — AWS credential compromise

**Triggers:** GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*`, `CredentialAccess:IAMUser/AnomalousBehavior`,
Inspector Lambda code "hardcoded secret", Gitleaks hit on a real key, AWS Health "exposed credentials" notice, SIEM AWS-CRED-*.
**Severity:** P1 · **Automation:** `soar-iam-key-deactivate` (long-term keys) runs first.

## 1. Contain (≤ 15 min)

| Credential type | Action |
|---|---|
| IAM user access key (`AKIA…`) | Confirm SOAR deactivated it: `aws iam list-access-keys --user-name <u>` (Status Inactive). If not, deactivate manually. |
| Role session (`ASIA…`) e.g. EC2/Lambda creds | Revoke **all** sessions issued before now: IAM console → role → *Revoke active sessions* (adds `aws:TokenIssueTime` deny). For EC2: also isolate instance (EC2 runbook). |
| Identity Center user | Disable user in IdP; Identity Center → *revoke sessions*. |
| ADO OIDC / service connection | Disable service connection in ADO; revoke sessions on the deploy role; see CI/CD runbook. |

## 2. Scope (≤ 2 h)

1. Detective → principal profile: API calls, geo, new resources for the last 30 days.
2. Security Lake / SIEM query: all events where `userIdentity.accessKeyId = <key>` (or session name) since first seen.
3. Look for persistence: `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `CreateFunction`, `AddPermission`, new OIDC/SAML providers, new EC2 instances in unusual regions (should be blocked by region SCP).
4. Data access: S3 data events `GetObject` volume by the principal; `GetSecretValue`; Redshift `GetClusterCredentials`.

## 3. Eradicate

Delete attacker-created resources (after snapshot/evidence), rotate every secret the principal could read,
re-issue credentials only via OIDC/roles (no new keys).

## 4. Recover & learn

Re-enable services; confirm GuardDuty/Security Hub quiet for 24 h; post-incident review within 5 business days;
add detection/prevention (feedback loop).

## Evidence

Export CloudTrail query results + Detective screenshots to the Forensics account case bucket (`case-<id>/`).
