# Phase 6 — Enterprise security integration (weeks 16–24)

**Objective:** every AWS and pipeline signal lands in the enterprise SIEM, ticketing and chat tools, and the most
common findings get an automated first response with human approval where production is affected.

## Contents

| Path | What it is |
|---|---|
| `terraform/modules/security-lake` | Security Lake org-wide (CloudTrail mgmt, S3 data, Lambda, VPC Flow, Route 53, Security Hub, WAF), KMS, 90 d → IA → Glacier, 365 d expiry, regional roll-up, SIEM subscriber (S3/SQS or Lake Formation) |
| `terraform/modules/alert-routing` | Severity fan-out: SNS topics for AWS Chatbot channels, PagerDuty via EventBridge API destination, root-login & break-glass rules, org PutEvents bus policy |
| `terraform/modules/event-forwarder` | Member-account rule forwarding sign-in / break-glass / IAM-user events to Security Tooling |
| `terraform/modules/soar` | 5 playbook Lambdas, approval workflow (Step Functions + DynamoDB + Security Hub custom actions), EventBridge triggers |
| `terraform/modules/remediation-role` | Per-account roles: `SecurityAutoRemediation`, `SecurityReadOnlyAutomation`, `ProwlerAudit` |
| `terraform/stacks/security-lake`, `terraform/stacks/response` | Deployable roots |
| `lambda/remediation/*` | Playbooks: S3 BPA, IAM key deactivate, SG admin-port revoke, EC2 isolate, Lambda URL auth |
| `lambda/approval/*` | Task-token request + custom-action approval handler |
| `stepfunctions/remediation-with-approval.asl.json` | Generic run → (approval) → run workflow with timeout escalation |
| `siem/detections/` | Sigma rules mapped to MITRE ATT&CK + test mapping |
| `../docs/runbooks/ir-*.md` | IR runbooks: credential compromise, EC2 compromise, data exfiltration, CI/CD token |

## Playbooks

| # | Trigger | Action | Approval | Path |
|---|---|---|---|---|
| 1 | S3.2 / S3.3 / S3.8 / S3.19 FAILED | Re-apply bucket BPA (skip `public-website=approved`), notify owner | none | direct Lambda |
| 2 | GuardDuty credential exfiltration / anomalous behaviour | Deactivate long-term key, tag user, P1; temp creds → manual IR | none | direct Lambda |
| 3 | EC2.13 / EC2.14 / EC2.53 / EC2.54 (0.0.0.0/0 on 22/3389) | Revoke rules, tag SG | none in non-prod; on-call in prod | Step Functions |
| 4 | GuardDuty crypto-mining / C&C / trojan (sev ≥ 7) | ASG detach, quarantine SG, remove profile, snapshots → Forensics | always on-call | Step Functions |
| 5 | Root sign-in / break-glass use | Page on-call, incident | n/a (alert only) | alert-routing |
| 6 | Lambda.1 FAILED (public function / URL `NONE`) | Set URL `AuthType=AWS_IAM` (skip `public-url=approved`) | prod | Step Functions |

All playbooks start with `soar_dry_run = true` (log + notify only). Promote per playbook after 2 weeks of clean dry-run logs.

## Integration architecture

```
Sources ─► Security Lake (Log Archive, OCSF) ─► SIEM subscriber (Splunk / Sentinel / OpenSearch)
         ─► Security Hub / GuardDuty (Security Tooling) ─► EventBridge
                 ├─► findings-router (Phase 4) ─► Jira SECVULN
                 ├─► alert-routing ─► SNS ─► AWS Chatbot ─► Teams/Slack  |  API destination ─► PagerDuty
                 └─► SOAR (Lambda / Step Functions) ─► SecurityAutoRemediation role in member account
Entra ID / Okta sign-in logs ─► SIEM (correlation with CloudTrail AssumeRoleWithSAML / console sign-in)
ADO audit stream ─► SIEM
```

## SIEM onboarding options

| SIEM | Ingest path | Notes |
|---|---|---|
| Splunk | Splunk Add-on for AWS — Security Lake input (SQS-based S3) | `subscriber_access_type = "S3"` |
| Microsoft Sentinel | Amazon Security Lake connector (S3 + SQS, OIDC role) | `subscriber_access_type = "S3"` |
| OpenSearch Security Analytics | Zero-ETL / ingestion pipeline from Security Lake, or query via Lake Formation | Use `LAKEFORMATION` for query access |

## AWS Chatbot

One-time: Chatbot console → configure Microsoft Teams (tenant consent) or Slack (workspace). Then create channel
configurations for `sec-critical`, `sec-high`, `sec-oncall` subscribed to the SNS topics from `alert-routing`
(guardrail policy: `ReadOnlyAccess`; no write actions from chat).

## Acceptance tests

```bash
aws guardduty create-sample-findings --detector-id $DET --finding-types "CryptoCurrency:EC2/BitcoinTool.B!DNS"
# → #sec-critical message, PagerDuty incident, Step Functions execution waiting for approval
# Make a sandbox bucket public → BPA re-applied within ~2 min (dry_run=false in sandbox)
# Sigma rule test: stratus detonate aws.defense-evasion.cloudtrail-stop (sandbox) → AWS-DEF-001 fires in SIEM
```

## Exit criteria

- [ ] All sources in SIEM with ≥ 20 tested detections
- [ ] 6 playbooks automated (dry-run off in non-prod, approval flow live in prod)
- [ ] MTTA critical < 15 min (PagerDuty analytics, 30-day window)
- [ ] IR runbooks reviewed; tabletop #1 complete; AWS Support / CIRT escalation path documented
