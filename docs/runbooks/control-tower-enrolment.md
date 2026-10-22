# Runbook — Control Tower landing zone and account enrolment

**Owner:** Cloud/DevOps Platform · **When:** Phase 0, week 2 · **Change type:** Normal (CAB)

## Pre-checks (per account to be enrolled)

1. `AWSControlTowerExecution` role exists (create via StackSet / manually) with trust to the management account.
2. No conflicting **AWS Config recorder / delivery channel** in governed regions:
   ```bash
   for r in ap-south-1 us-east-1; do
     aws configservice describe-configuration-recorders --region $r
     aws configservice describe-delivery-channels --region $r
   done
   ```
   If present: export history, then `delete-delivery-channel` + `delete-configuration-recorder` in the change window.
3. No account-level CloudTrail that would duplicate the org trail (keep data-event trails only if justified).
4. STS regional endpoints active in governed regions.
5. Account email reachable (root password reset may be needed for break-glass registration).

## Landing zone settings

| Setting | Value |
|---|---|
| Home region | `ap-south-1` |
| Governed regions | `ap-south-1`, `us-east-1` (+ any region found in inventory with workloads) |
| Region deny control | Enabled |
| Log Archive / Audit | Dedicated accounts; Audit renamed **Security Tooling** |
| CloudTrail | Organization-level (CT-managed) — retention 365 d |
| KMS | Customer-managed key for CT logs |
| IAM Identity Center | Enabled; external IdP connected afterwards |

## Enrolment order

1. Sandbox accounts (low risk) → validate guardrails/drift for 24 h.
2. Dev accounts.
3. Stage accounts.
4. Prod accounts (one per change window).

## Controls to enable on every OU

* All **mandatory** controls (automatic).
* **Strongly recommended** controls, e.g. disallow public read/write on S3, enable MFA for root,
  disallow root access keys, detect EBS unencrypted, detect public RDS snapshots.
* Proactive controls (CloudFormation hooks) for Workloads OU after week 6.

## Validation

```bash
aws controltower list-landing-zones
aws controltower list-enabled-controls --target-identifier arn:aws:organizations::<mgmt>:ou/<org-id>/<ou-id>
aws organizations list-accounts-for-parent --parent-id <ou-id>
```

## Rollback

Un-enrolment is possible per account (Account Factory → unmanage) but leaves CT resources behind;
rehearse on Sandbox. Do not decommission the landing zone without architecture review.
