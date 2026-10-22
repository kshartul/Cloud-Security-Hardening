# Phase 1 — AWS-native detection and posture (weeks 3–7)

**Objective:** every AWS security service enabled org-wide from the Security Tooling account, with
Security Hub as the single pane, codified so drift is visible.

## Contents

| Path | What it is |
|---|---|
| `terraform/modules/security-baseline/securityhub.tf` | Central configuration, FSBP + CIS v3.0 policy, per-OU association, cross-region aggregator, automation rules, team insight |
| `terraform/modules/security-baseline/guardduty.tf` | Org auto-enable ALL; S3, EBS malware, RDS login, Lambda network, EKS audit, optional Runtime; S3 export |
| `terraform/modules/security-baseline/inspector_macie_detective.tf` | Inspector EC2/ECR/Lambda/Lambda code; Macie org + custom identifiers; Detective graph |
| `terraform/modules/security-baseline/config.tf` | Org aggregator, organization conformance packs, org rules (WAF on API stages, Lambda public access, required tags) |
| `terraform/modules/guardduty-regional` | Same GuardDuty org config for every additional region |
| `terraform/stacks/security-tooling` | Deployable root (home region + us-east-1) |
| `scripts/macie_setup.py` | Automated discovery + priority classification job for DW/data-lake buckets |
| `scripts/fetch_conformance_packs.sh` | Vendors pinned conformance-pack templates |
| `docs/secrets-migration.md` | P1.8 secrets pattern and checklist |

## Steps

1. `phase-0 delegated-admins` applied (prerequisite).
2. `./scripts/fetch_conformance_packs.sh` and commit the templates.
3. Apply `stacks/security-tooling` with `policy_target_ous = [sandbox]`.
4. Enable existing members where auto-enable only covers new accounts:
   ```bash
   ACCTS=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)
   aws inspector2 enable --account-ids $ACCTS --resource-types EC2 ECR LAMBDA LAMBDA_CODE
   aws guardduty create-members --detector-id $DET --account-details $(for a in $ACCTS; do echo "AccountId=$a,Email=noreply@example.com"; done)
   aws inspector2 update-configuration --ecr-configuration rescanDuration=DAYS_30
   ```
5. `python scripts/macie_setup.py --account-ids <dw accounts>`.
6. Promote `policy_target_ous`: Dev → Stage → Prod → Security/Infrastructure (Week 5).
7. **Triage sprint** (weeks 5–6) — see below.
8. Record baseline score (KPI Lambda in Phase 4 publishes `Security/FSBPScore`).

## Triage sprint playbook (P1.10)

| Day | Activity |
|---|---|
| 1 | Export all CRITICAL/HIGH (`aws securityhub get-findings`), group by control ID and account |
| 1 | For each control: **fix**, **suppress with reason** (add to `docs/standards/suppression-register.md`), or **disable org-wide** (add to `disabled_control_ids` with reason) |
| 2–8 | Fix in code (Terraform / serverless.yml) — never in console; top offenders first (S3.x, IAM.x, Lambda.x, KMS.x) |
| 9 | Re-score; open Jira for the long tail with Phase 4 SLAs |
| 10 | Exit review: no CRITICAL older than 7 days |

## Verification

```bash
aws securityhub describe-organization-configuration      # ConfigurationType = CENTRAL
aws securityhub list-configuration-policy-associations
aws guardduty get-detector --detector-id $DET --query 'Features[].{n:Name,s:Status}'
aws inspector2 batch-get-account-status --account-ids $ACCTS --query 'accounts[].state.status'
aws macie2 get-automated-discovery-configuration
aws configservice describe-organization-conformance-pack-statuses
aws guardduty create-sample-findings --detector-id $DET   # appears in Security Hub < 5 min
```

## Exit criteria

- [ ] Every service enabled in 100% of accounts and regions in use
- [ ] FSBP score baseline recorded; target ≥ 90% agreed
- [ ] No open CRITICAL older than 7 days
- [ ] Stack applied by pipeline only (no console drift)

## Rollback

Remove an OU from `policy_target_ous` (disassociates the policy). Services stay enabled.
