# Phase 4 — Vulnerability management lifecycle (weeks 10–16)

**Objective:** one owner per finding, end to end: discovered → de-duplicated → risk-ranked → ticketed with SLA →
fixed → verified by rescan → reported.

## Contents

| Path | What it is |
|---|---|
| `lambda/findings_router/` | EventBridge target: EPSS + CISA KEV enrichment, tag lookup (cross-account), risk score + SLA (`risk.py`), idempotent Jira create, Security Hub `NOTIFIED` + UDFs, P1 pager; resolved → Jira `Verified` |
| `lambda/exception_expiry/` | Daily: reopen expired / malformed exceptions, remind owners, publish exception metrics |
| `lambda/kpi_snapshot/` | Daily: FSBP score, open/overdue critical & high (total + per team) → CloudWatch `Security` namespace |
| `terraform/modules/findings-router` | Rules, targets with retry + DLQ, Lambdas (arm64, KMS, X-Ray), least-privilege roles, alarms |
| `terraform/stacks/findings-routing` | Deployable root incl. KMS key and SNS topics |
| `tests/test_risk.py` | Unit tests for scoring/SLA |
| `defectdojo/` | Deployment design, configuration steps, SLA JSON |
| `jira/fields.md` | SECVULN issue types, workflow, custom fields, automation, dashboards |
| `scripts/lambda_runtime_report.py` | Org-wide deprecated runtime report |
| `../docs/standards/vulnerability-management-standard.md` | The standard (SLAs, exceptions, roles, metrics) |

## Flow

```
Inspector / GuardDuty / Config / Macie ─► Security Hub (aggregated, automation rules)
        ─► EventBridge "Findings - Imported" (CRITICAL/HIGH, NEW, ACTIVE)
        ─► findings-router ─► Jira SECVULN (due date = SLA) ─► team
                           └► Security Hub Workflow=NOTIFIED, UDF{jira, risk_score, sla_due, team}
Scanner stops reporting ─► ARCHIVED / PASSED event ─► findings-router ─► Jira "Verified"
Pipelines / DAST / pentest ─► DefectDojo (dedupe, SLA, Jira sync, close_old_findings on reimport)
SBOM ─► Dependency-Track ─► new CVE on deployed version ─► DefectDojo / Jira
```

## Rollout

| Week | Step |
|---|---|
| 10 | Publish standard (CISO sign-off); Jira project + fields; DefectDojo deployed |
| 11 | Apply `findings-routing` with `dry_run = true`; review CloudWatch logs for scoring/owner resolution |
| 12 | Fix untagged resources surfaced by the router (Config `org-required-tags`); `dry_run = false` for Dev/Stage findings |
| 13 | Enable for Prod; Jira SLA automation; DefectDojo ↔ Jira sync |
| 14 | Exception workflow live; `exception-expiry` running |
| 15 | Dashboards; first weekly team report |
| 16 | Exit review |

## Patch & runtime hygiene

* **SSM Patch Manager** (EC2, DMS-adjacent bastions/agents): patch baseline per OS — security patches auto-approved after
  7 days (Critical) / 14 days (Important); maintenance windows Dev Tue, Stage Wed, Prod Sat; compliance → Config → Security Hub.
* **Lambda**: `scripts/lambda_runtime_report.py` monthly; Inspector Lambda findings for packages; layer rebuild via pipeline.
* **Containers** (DefectDojo, any ECS): rebuild on base-image CVE (Inspector ECR enhanced scanning, continuous).

## Acceptance tests

```bash
# Unit tests
pytest -q tests/
# End-to-end (Dev): create a sample critical finding, expect Jira + NOTIFIED in < 2 min
aws securityhub batch-import-findings --findings file://tests/fixtures/sample-critical.json
aws securityhub get-findings --filters '{"Id":[{"Value":"<id>","Comparison":"EQUALS"}]}' \
  --query 'Findings[0].[Workflow.Status,UserDefinedFields]'
# Exception expiry: suppress with an expiry in the past, invoke the job, expect Workflow NEW
aws lambda invoke --function-name secvuln-exception-expiry out.json && cat out.json
```

## Exit criteria

- [ ] Single backlog: 100% of CRITICAL/HIGH findings have an owner and due date
- [ ] SLA compliance ≥ 90% for critical/high (rolling 30 days)
- [ ] Exception register live with expiry alerts; 0 expired exceptions
- [ ] Weekly team + monthly leadership reports published

## Rollback

Set `dry_run = true` (router keeps logging but stops creating tickets/updating findings) or disable the EventBridge rules.
