# Phase 0 — Foundation and governance (weeks 1–3)

**Objective:** multi-account guardrails every later control depends on — Security Tooling and Log Archive
accounts, immutable org trail, preventive SCPs, federated identity, secure account defaults.

## Contents

| Path | What it is |
|---|---|
| `policies/scp/protect-security-services.json` | Deny disabling GuardDuty/Security Hub/Config/CloudTrail/Inspector/Macie/Access Analyzer, deny leave-org, deny root |
| `policies/scp/data-and-compute-guardrails.json` | IMDSv2, encryption on PutObject, protect account BPA, no new IAM users/keys, no `AuthType NONE` Lambda URLs, no public Redshift |
| `policies/scp/region-deny.json.tftpl` | Region allow-list with global-service exemptions |
| `terraform/modules/scp` | Creates SCPs, attaches per OU from a promotion list |
| `terraform/modules/log-archive-bucket` | Object Lock (COMPLIANCE 365 d) bucket + logs CMK + restrictive bucket policy |
| `terraform/modules/org-cloudtrail` | Org trail, advanced selectors (mgmt + S3/Lambda data), CIS 4.x metric filters/alarms |
| `terraform/modules/identity-center` | Permission sets, inline denies, boundary, group assignments |
| `terraform/modules/account-defaults` | S3 account BPA, EBS default encryption, IMDSv2 default, snapshot/AMI public-access block, password policy, per-domain CMKs |
| `terraform/modules/access-analyzer` | Org external + unused-access analyzers, archive rules |
| `terraform/stacks/*` | Deployable roots — order in `docs/DEPLOYMENT_ORDER.md` |
| `scripts/baseline_inventory.py` | P0.1 org-wide inventory (IAM users/keys, public S3/snapshots/AMIs, open Lambda URLs) |
| `scripts/iam_user_retirement.py` | P0.10 plan → deactivate → (rollback) → delete waves |
| `scripts/prowler_snapshot.sh` | P0.1 Prowler v4 baseline for every account |

## Steps

1. **Inventory** — `python scripts/baseline_inventory.py --out inventory.json`; `./scripts/prowler_snapshot.sh`.
   Attach results to Jira epic `SEC-P0`. Use the region footprint to set `allowed_regions`.
2. **State bucket** — apply `stacks/bootstrap-state` with local state, then migrate.
3. **OUs + SCPs** — apply `stacks/organization` with `scp_attach_ous = ["sandbox"]`.
4. **Control Tower** — set up / update landing zone, enrol accounts (runbook `docs/runbooks/control-tower-enrolment.md`).
   Control Tower creates Log Archive & Audit (rename *Audit* → *Security Tooling* or create a dedicated account).
5. **Log Archive** — apply `stacks/log-archive`; then `stacks/org-trail` in management.
   *If Control Tower already manages an org trail*, keep the CT trail and only add the data-event trail from this module
   (set `trail_name = "org-data-events"` and remove management selector) — never run two management-event org trails.
6. **Identity Center** — connect IdP (SCIM), then apply `stacks/identity-center`.
7. **Account baseline** — pipeline matrix applies `stacks/account-baseline` per account workspace.
8. **Delegated admins** — apply `stacks/delegated-admins`.
9. **Promote SCPs** Sandbox → Dev → Stage → Prod (72 h between, watch AccessDenied).
10. **Retire IAM users** — `iam_user_retirement.py plan`, review owners, `deactivate --grace-days 14`, `delete` after grace.

### AccessDenied watch query (CloudWatch Logs Insights on the org trail log group)

```
fields @timestamp, recipientAccountId, userIdentity.arn, eventSource, eventName, errorCode, errorMessage
| filter errorCode like /AccessDenied|UnauthorizedOperation/
| filter errorMessage like /service control policy/
| stats count(*) as denies by recipientAccountId, eventSource, eventName, userIdentity.arn
| sort denies desc
```

## Verification

```bash
aws organizations list-policies-for-target --target-id <ou-id> --filter SERVICE_CONTROL_POLICY
aws cloudtrail get-trail-status --name org-trail
aws s3api get-object-lock-configuration --bucket <log-bucket>
aws ec2 get-instance-metadata-defaults --region ap-south-1
aws ec2 get-ebs-encryption-by-default --region ap-south-1
aws s3control get-public-access-block --account-id <id>
python scripts/baseline_inventory.py --check-console-users   # exit 0 required
```

## Exit criteria

- [ ] All accounts enrolled in Control Tower
- [ ] Zero IAM users with console passwords outside break-glass
- [ ] Org trail immutable (Object Lock COMPLIANCE) and validated
- [ ] SCPs attached to every OU
- [ ] CI pipelines use OIDC roles; no active long-lived keys for CI

## Rollback

* SCP: remove the OU from `scp_attach_ous`, apply (≈ 1 min to take effect).
* IAM users: `iam_user_retirement.py reactivate --user <name>` during grace period.
* Object Lock: **cannot** be reduced in COMPLIANCE mode — test retention on a sandbox bucket first.
