# AWS Security Hardening — Detailed Implementation Plan

| | |
|---|---|
| Version | 1.0 — 22 Oct 2026 |
| Author / Program owner | Shartul Kumar (Cloud/DevOps Platform) |
| Duration | 24 weeks (Phase 0 → Phase 6), then BAU |
| Home region | `ap-south-1` (cross-region aggregation from all enabled regions) |
| Source plan | *AWS Security Hardening Plan* (Oct 22, 2026) |
| Repository | this repo — each work package below points at the folder that implements it |

---

## 1. Purpose, scope and assumptions

**Purpose.** Close eight security gaps — application security assessments, SAST, DAST,
penetration testing, vulnerability management, API security, AWS-native security tooling and
enterprise security integration — with controls that are *code*, *measured* and *auditable*.

**In scope.** All AWS accounts in the organization; all workloads built on Lambda, API Gateway,
Serverless Framework v3, Terraform, DMS and Redshift; all Azure DevOps (ADO) repos and pipelines
that deploy to AWS; human and machine identities that touch AWS.

**Out of scope (v1).** Endpoint/EDR on laptops, M365/Entra hardening (consumed only as signals),
non-AWS clouds, physical security.

**Assumptions**

1. Organization management account is reachable by the platform team with an admin role.
2. Control Tower can be enabled (or is enabled) in the home region; existing accounts can be enrolled.
3. An enterprise IdP (Entra ID or Okta) exists and the identity team will create SCIM provisioning.
4. A SIEM decision (Splunk / Sentinel / OpenSearch) is made by week 12 (Phase 6 dependency).
5. Budget is approved for: Security Hub, GuardDuty, Inspector, Macie, Detective, Config, Security Lake,
   WAF, third-party pen test, and optionally SonarQube/Snyk/Burp Enterprise licences.

---

## 2. Gap-to-closure traceability

| # | Gap | Closed in | Implemented in (repo path) | Evidence produced |
|---|---|---|---|---|
| G1 | Application security assessments | P2, P3, P5 | `phase-2-secure-sdlc/threat-models`, `phase-5-pentest` | Threat model per tier-1 service, AppSec review checklist |
| G2 | SAST | P2 | `phase-2-secure-sdlc/pipelines/templates/security-scan.yml` | Pipeline quality gates, SARIF artefacts, findings trend |
| G3 | DAST | P3 | `phase-3-dast-api/pipelines/templates/dast-zap.yml` | Nightly ZAP reports against staging |
| G4 | Penetration testing | P5 | `phase-5-pentest/` | Annual + per-release report, retest letters |
| G5 | Vulnerability management | P4 | `phase-4-vuln-mgmt/` | SLA dashboard, exception register |
| G6 | API security | P3 | `phase-3-dast-api/terraform/modules/waf-api`, `serverless/` | OpenAPI lint gate, WAF metrics, authorizer coverage |
| G7 | AWS security tooling | P0, P1 | `phase-0-foundation/`, `phase-1-detection/` | Delegated admin everywhere, FSBP/CIS score |
| G8 | Enterprise security integration | P6 | `phase-6-integration/` | Integration architecture, playbooks, SIEM detections |

---

## 3. Program governance

### 3.1 Team

| Role | Person/team | Allocation |
|---|---|---|
| Program owner / architect | Cloud/DevOps Platform lead | 60% |
| Platform engineers (Terraform, ADO) | 2 engineers | 100% weeks 1–16, 50% after |
| AppSec engineer | Security (AppSec) | 100% weeks 5–20 |
| SecOps / detection engineer | Security (SecOps) | 50% weeks 3–7, 100% weeks 16–24 |
| Security champions | 1 per app team (omni-dw-api, WMS, DW backend) | 10% |
| CISO delegate | approves exceptions, SLAs, pen-test scope | as needed |

### 3.2 Cadence

* **Weekly** 30-min program stand-up: burndown per work package, blockers, decisions.
* **Bi-weekly** steering with CISO delegate: KPI snapshot, exception approvals, scope changes.
* **Per phase** go/no-go review against the exit criteria listed in each phase below.
* Decisions are recorded as ADRs in `docs/adr/` (template in Appendix B).

### 3.3 Change and rollout strategy (applies to every control)

Every preventive control follows the same promotion path so nothing breaks production delivery:

```
 Audit / report-only  ──►  Sandbox OU  ──►  Dev OU  ──►  Stage OU  ──►  Prod OU
      (1–2 weeks)          (2–3 days)     (1 week)     (3–5 days)    (CAB approval)
```

* SCPs are attached first to the **Sandbox OU**, then **Dev**, with CloudTrail `AccessDenied` monitoring
  for 72 hours before promotion (query in `phase-0-foundation/README.md`).
* Pipeline gates start with `failOnFindings: false` for two weeks, then flip to `true`, diff-aware only.
* Auto-remediation playbooks run in **notify-only** mode in prod first; prod enforcement requires an approval step.

### 3.4 Environments for this repo's own pipelines

| Stage | Target | Approval |
|---|---|---|
| `plan` | all stacks | none — runs on every PR, plan posted as PR comment |
| `scan` | Checkov + tfsec + Gitleaks on this repo | none — blocking |
| `apply-nonprod` | Sandbox/Dev/Stage-scoped stacks | 1 platform reviewer |
| `apply-org` | Management / Security Tooling / Log Archive / Prod | 2 reviewers incl. Security, ADO environment check |

---

## 4. Target account and OU model

```
Root (SCP: FullAWSAccess + Guardrails)
├── Security OU
│   ├── Log Archive          — org CloudTrail (Object Lock), Config history, Security Lake, WAF/Flow logs
│   ├── Security Tooling     — delegated admin: Security Hub, GuardDuty, Inspector, Macie, Detective,
│   │                          Config aggregator, Access Analyzer, Firewall Manager, findings router, SOAR
│   └── Forensics            — isolated VPC, snapshot copies, analyst roles (no internet egress)
├── Infrastructure OU        — shared networking (TGW, Network Firewall), shared CI runners
├── Workloads OU
│   ├── Dev OU               — omni-*-dev accounts
│   ├── Stage OU             — omni-*-stage accounts (DAST + pen-test target)
│   └── Prod OU              — omni-*-prod accounts
├── Sandbox OU               — experiments; strongest region/budget guardrails
└── Suspended OU             — deny-all SCP for closed accounts
```

Management account runs **only** Organizations, Control Tower, Identity Center and billing — no workloads.

---

## 5. Phase plans

Effort is in engineer-days (ed). Owner codes: **PLT** = Cloud/DevOps Platform, **SEC** = Security (AppSec/SecOps),
**APP** = application teams, **CISO** = CISO delegate.

---

### Phase 0 — Foundation and governance (weeks 1–3)

**Objective.** Multi-account guardrails every later control depends on.

**Entry criteria.** Management-account admin access; IdP team engaged; list of all AWS accounts.

#### Work packages

| ID | Task | Owner | Effort | Depends on | Deliverable (repo path) |
|---|---|---|---|---|---|
| P0.1 | Baseline inventory: accounts, regions in use, IAM users with console/keys, key age, public S3/snapshots/AMIs/Lambda URLs; one-off Prowler snapshot | PLT | 3 ed | — | `phase-0-foundation/scripts/baseline_inventory.py`, `prowler_snapshot.sh` |
| P0.2 | Enable Organizations *all features*; create OU tree (§4) | PLT | 1 ed | P0.1 | `terraform/stacks/organization` |
| P0.3 | Deploy / update Control Tower landing zone (v3.x), region deny, enrol existing accounts | PLT | 4 ed | P0.2 | Console + `docs/runbooks/control-tower-enrolment.md` |
| P0.4 | Create Security Tooling, Log Archive, Forensics accounts (Account Factory) | PLT | 1 ed | P0.3 | AFT / Account Factory |
| P0.5 | Org CloudTrail (mgmt + S3/Lambda data events) → Object Lock bucket in Log Archive, KMS CMK, CloudWatch Logs | PLT | 2 ed | P0.4 | `terraform/modules/org-cloudtrail` |
| P0.6 | KMS CMKs per data domain (dw, api, logs, secrets) with rotation | PLT | 1 ed | P0.4 | `terraform/modules/kms-domain-keys` |
| P0.7 | SCP library authored + unit-tested with IAM policy simulator | PLT+SEC | 3 ed | P0.2 | `policies/scp/*.json`, `terraform/modules/scp` |
| P0.8 | Account defaults in every account: S3 BPA, EBS default encryption, IMDSv2 default, password policy | PLT | 1 ed | P0.4 | `terraform/modules/account-defaults` |
| P0.9 | IAM Identity Center with external IdP (SCIM), MFA, permission sets | PLT + Identity | 4 ed | P0.3 | `terraform/modules/identity-center` |
| P0.10 | Retire IAM users & access keys (extend IAM username standardization tooling): migrate CI to OIDC roles | PLT | 5 ed | P0.9 | `scripts/iam_user_retirement.py`, `pipelines/README.md` |
| P0.11 | Access Analyzer: org external + unused access (90 days) | PLT | 0.5 ed | P0.4 | `terraform/modules/access-analyzer` |
| P0.12 | Break-glass: 2 root-equivalent `SecurityBreakGlass` roles, hardware MFA, sealed procedure, alarm on use | PLT+SEC | 1 ed | P0.9 | `docs/runbooks/break-glass.md` |

#### Schedule

| Week | Work |
|---|---|
| 1 | P0.1 inventory, P0.2 OUs, P0.7 SCP authoring, Identity Center design workshop |
| 2 | P0.3 Control Tower + enrolment, P0.4 accounts, P0.5 org trail, P0.6 KMS, P0.9 IdP integration |
| 3 | P0.7 SCP rollout Sandbox→Dev→Stage→Prod, P0.8 defaults, P0.10 user retirement wave 1, P0.11, P0.12 |

#### Acceptance tests

```bash
# Every account enrolled & governed
aws controltower list-enabled-controls --target-identifier <ou-arn>
# Trail is org-wide, multi-region, validated
aws cloudtrail describe-trails --query 'trailList[?IsOrganizationTrail].[Name,IsMultiRegionTrail,LogFileValidationEnabled]'
# Object Lock is COMPLIANCE / 365 days
aws s3api get-object-lock-configuration --bucket <org-trail-bucket>
# SCP denies tampering (expect AccessDenied from a member-account admin)
aws guardduty delete-detector --detector-id <id>
# No IAM users with console passwords outside break-glass
python phase-0-foundation/scripts/baseline_inventory.py --check-console-users
```

**Exit criteria.** All accounts enrolled; zero IAM users with console passwords outside break-glass;
org trail immutable; SCPs attached to every OU; CI pipelines use OIDC roles.

**Rollback.** SCPs: detach from the OU (Terraform `attach_to_ous` list); Identity Center: IAM users remain
disabled-not-deleted for 30 days; Control Tower enrolment cannot be "rolled back" cheaply — rehearse on Sandbox first.

**Risks.** *SCP breaks a deployment* → staged rollout + AccessDenied dashboard. *Legacy pipelines use IAM user keys*
→ P0.10 inventory maps every key to a pipeline before deactivation; deactivate (not delete) for 14 days.

---

### Phase 1 — AWS-native detection and posture (weeks 3–7)

**Objective.** All AWS security services org-wide from the Security Tooling account; Security Hub is the single pane.

**Entry criteria.** P0.4 accounts exist; delegated admin not yet assigned elsewhere.

#### Work packages

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P1.1 | Register Security Tooling as delegated admin for Security Hub, GuardDuty, Inspector, Macie, Detective, Config, Access Analyzer, Firewall Manager | PLT | 1 ed | P0.4 | `phase-0-foundation/terraform/stacks/delegated-admins` |
| P1.2 | Security Hub central configuration, FSBP + CIS v3.0, cross-region aggregator, policy per OU | PLT | 2 ed | P1.1 | `phase-1-detection/terraform/modules/security-baseline/securityhub.tf` |
| P1.3 | GuardDuty org auto-enable ALL + S3, Lambda network, RDS login, Malware (EC2/S3), runtime where applicable; export to S3 | PLT | 1.5 ed | P1.1 | `.../guardduty.tf` |
| P1.4 | AWS Config org recorder + aggregator + conformance packs (CIS, Serverless, Redshift) | PLT | 2 ed | P1.1 | `.../config.tf`, `conformance-packs/` |
| P1.5 | Inspector: EC2, ECR, Lambda standard + code scanning | PLT | 1 ed | P1.1 | `.../inspector.tf` |
| P1.6 | Macie: org enable, automated sensitive data discovery, custom identifiers (employee ID, candidate ID) | PLT+SEC | 2 ed | P1.1 | `.../macie.tf`, `scripts/macie_custom_identifiers.py` |
| P1.7 | Detective for GuardDuty/Security Hub | PLT | 0.5 ed | P1.3 | `.../detective.tf` |
| P1.8 | Secrets: move secrets out of `serverless.yml`/env vars into Secrets Manager / SSM SecureString; rotation for Redshift/RDS | APP+PLT | 5 ed | P0.6 | `phase-1-detection/docs/secrets-migration.md` |
| P1.9 | Security Hub automation rules (suppress accepted, raise severity for `exposure=internet`) | SEC | 1 ed | P1.2 | `.../securityhub_automation.tf` |
| P1.10 | **Triage sprint** (2 weeks): fix critical/high misconfigurations, document suppressions | PLT+APP+SEC | 15 ed | P1.2–P1.5 | Jira epic SEC-P1, `docs/standards/suppression-register.md` |
| P1.11 | Record baseline FSBP/CIS score; set target ≥ 90% | SEC | 0.5 ed | P1.10 | KPI dashboard |

#### Schedule

| Week | Work |
|---|---|
| 3 | P1.1 delegated admins (management account apply) |
| 4 | P1.2–P1.7 security-baseline module applied to Sandbox + Dev policy association |
| 5 | Associate policy with Stage + Prod OUs; start P1.10 triage sprint; P1.8 secrets migration starts |
| 6 | Triage sprint continued; P1.9 automation rules |
| 7 | P1.11 baseline score, exit review |

#### Acceptance tests

```bash
aws securityhub list-organization-admin-accounts
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'length(Findings)'
aws guardduty list-members --detector-id <id> --query 'Members[?RelationshipStatus!=`Enabled`]'
aws inspector2 batch-get-account-status --account-ids <ids>
aws configservice describe-configuration-aggregators
# Generate a sample GuardDuty finding and watch it reach Security Hub < 5 min
aws guardduty create-sample-findings --detector-id <id> --finding-types UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
```

**Exit criteria.** Every service enabled in 100% of accounts/regions-in-use; FSBP baseline recorded; no
critical older than 7 days; the `security-baseline` module applied via pipeline (no console drift).

**Rollback.** Disassociate the configuration policy from an OU (`aws_securityhub_configuration_policy_association`).
Services stay enabled; only standards/controls revert.

**Cost control.** Enable Config *daily* recording for high-churn types; Macie automated discovery samples
(not full scans) by default; GuardDuty Runtime only where containers exist. Review the Cost Explorer
"Security" cost category weekly during weeks 4–8.

---

### Phase 2 — Secure SDLC: SAST, SCA, secrets and IaC (weeks 5–10)

**Objective.** Every ADO pipeline has a security stage that fails on *new* critical/high findings.

#### Work packages

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P2.1 | Threat-model tier-1 services (omni-dw-api-services, WMS Lambdas, DW backend) with STRIDE in Threat Dragon | SEC+APP | 6 ed | — | `phase-2-secure-sdlc/threat-models/` |
| P2.2 | Reusable template `security-scan.yml` (Gitleaks, Semgrep, Bandit, Trivy, Syft, Checkov, cfn-nag, Access Analyzer policy checks) in a shared `security-templates` ADO repo | PLT | 5 ed | — | `pipelines/templates/security-scan.yml` |
| P2.3 | Custom Semgrep rules for internal patterns (boto3 without region, hard-coded ARNs, `pickle`, SQL string concat to Redshift) | SEC | 3 ed | P2.2 | `configs/semgrep/` |
| P2.4 | Pre-commit hooks distributed to all repos | PLT | 1 ed | P2.2 | `configs/.pre-commit-config.yaml` |
| P2.5 | Gitleaks full-history scan of every repo; rotate anything found | SEC+APP | 4 ed | P2.2 | Rotation log in Jira SEC-P2 |
| P2.6 | SonarQube/SonarCloud project per repo; quality gate (0 new vulns, 100% hotspots reviewed, 80% new-code coverage) | PLT | 2 ed | — | `configs/sonar-project.properties` |
| P2.7 | SBOM: Syft CycloneDX per build → Dependency-Track | PLT | 2 ed | P2.2 | Template step + `phase-4-vuln-mgmt/dependency-track/` |
| P2.8 | Roll template into tier-1 repos (audit mode) | PLT+APP | 3 ed | P2.2 | PRs per repo |
| P2.9 | Baseline existing findings in DefectDojo; flip to enforce (`failOnFindings: true`) for new criticals/highs | SEC | 2 ed | P2.8 + 2 weeks | Branch policy change |
| P2.10 | Branch policies: security stage required; security-champion reviewer for IAM/auth/crypto paths | PLT | 1 ed | P2.9 | `pipelines/branch-policies.md` |
| P2.11 | Roll to tier-2/3 repos | PLT+APP | 4 ed | P2.9 | — |

#### Schedule

| Week | Work |
|---|---|
| 5 | P2.1 threat-modeling workshops start; P2.2 template build |
| 6 | P2.3 rules, P2.4 hooks, P2.5 history scans; P2.6 Sonar |
| 7 | P2.8 audit-mode rollout to tier-1; P2.7 SBOM |
| 8 | Audit-mode data collection; triage false positives; tune `.checkov.yaml`/`.semgrepignore` |
| 9 | P2.9 enforce on tier-1; P2.10 branch policies |
| 10 | P2.11 tier-2/3 rollout; exit review |

#### Acceptance tests

* Open a PR that adds `AKIA…` test string → pipeline fails at *Secrets scan*.
* Open a PR adding an S3 bucket without encryption in Terraform → fails at *IaC scan*.
* Open a PR with a vulnerable `requests==2.19.0` pin → fails at *SCA*.
* Legacy finding (present on `main`) does **not** fail the PR (diff-aware baseline works).

**Exit criteria.** 100% tier-1 repos run the stage on `main` with gates enforced; secrets in history rotated;
SBOM for every release artefact.

**Rollback.** Set template parameter `failOnFindings: false` (single change in the shared template repo).

---

### Phase 3 — DAST and API security (weeks 8–14)

**Objective.** Every API Gateway route authenticated, validated, throttled and behind WAF; nightly DAST on staging.

#### Work packages

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P3.1 | API inventory: export OpenAPI for every REST/HTTP API stage, tag owner + classification, flag undocumented routes | PLT | 2 ed | P1.4 | `phase-3-dast-api/scripts/export_api_inventory.py` |
| P3.2 | Spectral OWASP lint gate (or 42Crunch, score ≥ 75) in CI | PLT | 1.5 ed | P3.1 | `pipelines/templates/api-lint.yml`, `configs/.spectral.yaml` |
| P3.3 | WAF web ACL module (managed rules, rate-based, IP reputation, logging to Firehose → Log Archive) | PLT | 2 ed | P0.5 | `terraform/modules/waf-api` |
| P3.4 | Firewall Manager policy: associate the WAF ACL to every API Gateway stage & CloudFront org-wide | PLT | 1 ed | P1.1, P3.3 | `terraform/stacks/fms-waf-policy` |
| P3.5 | Harden Serverless stacks: Cognito/JWT authorizer + scopes on every route, request validators, throttling, reserved concurrency, access logs, X-Ray, TLS 1.2 | APP+PLT | 8 ed | P3.1 | `serverless/serverless.hardened.yml` pattern |
| P3.6 | Private APIs for internal consumers (VPC endpoint + resource policy) — admin routes separated | APP+PLT | 3 ed | P3.5 | `serverless/private-api.snippet.yml` |
| P3.7 | ZAP baseline per staging deploy (passive, warn) | PLT | 1 ed | — | `pipelines/templates/dast-zap.yml` (mode `baseline`) |
| P3.8 | ZAP API full scan nightly with Cognito test user token; rules file tuning | SEC | 3 ed | P3.7 | `configs/zap-rules.conf`, `scripts/get_cognito_token.py` |
| P3.9 | Nuclei weekly on public DNS inventory | SEC | 1 ed | P3.1 | `pipelines/nuclei-weekly.yml` |
| P3.10 | IDOR / BOLA unit test pattern + library for Lambda handlers | APP+SEC | 3 ed | P3.5 | `serverless/src/authz.py`, `tests/test_authz.py` |
| P3.11 | Egress control for VPC Lambdas: Network Firewall domain allow-list (SSRF, API7) | PLT | 3 ed | Infra OU | `docs/architecture/ARCHITECTURE.md §5` |

#### Schedule

| Week | Work |
|---|---|
| 8 | P3.1 inventory, P3.3 WAF module, P3.7 ZAP baseline |
| 9 | P3.2 lint gate (audit), P3.4 FMS in *count* mode on Dev/Stage |
| 10 | P3.5 hardening omni-dw-api-services; P3.8 nightly ZAP |
| 11 | P3.5 WMS + DW backend; WAF *block* mode in Stage |
| 12 | P3.6 private APIs; P3.10 authz library; WAF block in Prod after 7 days of count data |
| 13 | P3.9 Nuclei; P3.11 egress; P3.2 enforce |
| 14 | Exit review |

**WAF promotion rule.** Each managed rule group starts in `count` override; promote to block when the
false-positive rate in the WAF logs is < 0.1% of requests over 7 days (Athena query in `phase-3-dast-api/README.md`).

**Exit criteria.** 100% routes behind authorizer + WAF; OpenAPI lint gate on; nightly DAST with zero untriaged HIGH.

**Rollback.** Per-rule `override_action = count` in WAF; FMS policy `remediation_enabled = false`.

---

### Phase 4 — Vulnerability management lifecycle (weeks 10–16)

**Objective.** One owner per finding from discovery to verified closure, with SLAs.

#### Work packages

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P4.1 | Publish Vulnerability Management Standard (SLAs, exceptions, metrics) — CISO sign-off | SEC | 2 ed | — | `docs/standards/vulnerability-management-standard.md` |
| P4.2 | Deploy DefectDojo (ECS Fargate + RDS PostgreSQL, private ALB, SSO) in Security Tooling | PLT | 4 ed | P1.1 | `phase-4-vuln-mgmt/defectdojo/` |
| P4.3 | DefectDojo config: product per service, engagement per release, SLA config, dedupe, Jira bidirectional | SEC | 2 ed | P4.2 | `defectdojo/sla_configuration.json`, `scripts/push_to_defectdojo.py` |
| P4.4 | Jira project `SECVULN`, issue type *Vulnerability*, fields (CVE, CVSS, EPSS, KEV, asset, SLA due) + dashboards | SEC | 1.5 ed | — | `phase-4-vuln-mgmt/jira/fields.md` |
| P4.5 | Findings router: EventBridge → Lambda (EPSS + CISA KEV enrichment, risk score, owner lookup via tags, Jira create, Security Hub workflow → NOTIFIED) | PLT | 5 ed | P4.4 | `terraform/modules/findings-router`, `lambda/findings_router/` |
| P4.6 | Ticket-close sync: Jira webhook → Lambda; scanner auto-resolve closes Jira (verify-by-rescan) | PLT | 2 ed | P4.5 | `lambda/jira_sync/` |
| P4.7 | Exception register: Security Hub `SUPPRESSED` + note; daily expiry checker → re-open + notify | PLT | 2 ed | P4.5 | `lambda/exception_expiry/` |
| P4.8 | SSM Patch Manager baselines + maintenance windows (EC2/DMS replication hosts N/A — managed) | PLT | 2 ed | P1.4 | `terraform/modules/patch-baselines` |
| P4.9 | Lambda runtime/layer currency: report of deprecated runtimes, upgrade backlog | PLT+APP | 2 ed | P1.5 | `scripts/lambda_runtime_report.py` |
| P4.10 | Dependency-Track ingest of SBOMs; alert on new CVEs in deployed versions | PLT | 2 ed | P2.7 | `dependency-track/` |
| P4.11 | Dashboards: weekly team, monthly leadership (MTTR, SLA %, aging, exceptions) | SEC | 2 ed | P4.5 | QuickSight / Jira dashboards |

**Risk scoring (implemented in `findings_router`).**

```
risk = cvss_or_severity_base(0–10)
       × (1.5 if CISA KEV else 1.0)
       × (1 + EPSS probability)
       × (1.3 if exposure=internet else 1.0)
       × (1.2 if data-classification in {confidential, restricted} else 1.0)
       × (1.2 if criticality=tier-1 else 1.0)
priority:  ≥ 15 → P1 (Critical SLA) | ≥ 10 → P2 | ≥ 5 → P3 | else P4
```

**SLA table** (also in the standard): Critical/KEV 7 days internet-facing, 15 internal; High 30/45;
Medium 90/120; Low next release/backlog. Escalation at day 3 (critical) and at 75% of SLA (high).

**Exit criteria.** Single backlog with owner for 100% of items; SLA compliance ≥ 90% critical/high;
exception register live with expiry alerts.

---

### Phase 5 — Penetration testing program (weeks 14–20, then recurring)

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P5.1 | Vendor selection (CREST/OSCP), MSA + NDA, data-handling clauses | SEC+CISO | 5 ed (elapsed 3 wks) | — | Procurement |
| P5.2 | Scope by risk: public APIs, auth flows, DW access paths, AWS config review, ADO service connections | SEC+PLT | 2 ed | P3.1 | `phase-5-pentest/scope-template.md` |
| P5.3 | Confirm AWS pen-test policy (no pre-approval for listed services; DoS/phishing simulation need separate approval) | SEC | 0.5 ed | — | Note in RoE |
| P5.4 | Rules of engagement signed | SEC+CISO | 1 ed | P5.2 | `rules-of-engagement.md` |
| P5.5 | Prepare: test users, time-boxed `PentestCloudReview` role (ReadOnly + SecurityAudit, expires), WAF tester allow rule w/ logging, SOC notification + GuardDuty suppression *tagging* (not muting) | PLT | 2 ed | P5.4 | `terraform/pentest-access`, `waf-tester-allow` |
| P5.6 | Internal self-assessment before vendor arrives (Prowler, ScoutSuite, PMapper, Stratus) | PLT+SEC | 3 ed | P1 | `scripts/self_assessment.sh` |
| P5.7 | Execute (2–3 weeks), daily stand-ups, immediate escalation of criticals | Vendor | — | P5.5 | Daily notes |
| P5.8 | Import findings to DefectDojo, apply P4 SLAs | SEC | 1 ed | P5.7 | — |
| P5.9 | Retest + letter of attestation | Vendor | — | fixes | Retest letter |
| P5.10 | Feedback loop: each finding → Semgrep rule / Config rule / ZAP script / unit test | SEC+APP | 4 ed | P5.8 | `phase-5-pentest/feedback-loop.md` |
| P5.11 | Purple-team exercise with Stratus Red Team; fix ≥ 1 detection gap | SEC | 3 ed | P6 partial | `purple-team/` write-up |

**Exit criteria.** First external test done; all critical/high retested & closed; RoE template approved;
≥ 1 purple-team detection gap fixed.

---

### Phase 6 — Enterprise security integration (weeks 16–24)

| ID | Task | Owner | Effort | Depends on | Deliverable |
|---|---|---|---|---|---|
| P6.1 | Amazon Security Lake org-wide in Log Archive (CloudTrail mgmt+data, VPC Flow, Route 53, Security Hub, Lambda execution); 365-day retention + Glacier | PLT | 3 ed | P0.5 | `terraform/modules/security-lake` |
| P6.2 | Non-native sources (WAF logs, API GW access logs) via Firehose → S3 → Security Lake custom source | PLT | 3 ed | P6.1 | `.../custom-sources.tf` |
| P6.3 | SIEM subscriber (Splunk / Sentinel / OpenSearch) — query or S3 notification subscriber | SEC+PLT | 4 ed | P6.1, SIEM decision | `.../subscriber.tf` |
| P6.4 | Detection content mapped to MITRE ATT&CK cloud matrix (≥ 20 rules), IdP ↔ AWS correlation | SEC | 8 ed | P6.3 | `phase-6-integration/siem/detections/` |
| P6.5 | EventBridge central routing: severity-based to Chatbot (Teams/Slack), PagerDuty (API destination), Jira | PLT | 2 ed | P4.5 | `terraform/modules/alert-routing` |
| P6.6 | Six auto-remediation playbooks (Lambda + Step Functions with approval in prod) | PLT+SEC | 8 ed | P6.5 | `lambda/remediation/`, `stepfunctions/` |
| P6.7 | IR runbooks + Forensics account tooling (snapshot share, isolated analysis VPC) | SEC | 4 ed | P0.4 | `docs/runbooks/` |
| P6.8 | Quarterly tabletop #1; AWS Support / CIRT escalation path documented | SEC+CISO | 1 ed | P6.7 | Tabletop report |
| P6.9 | Optional CNAPP evaluation (Wiz/Prisma/Orca) — 30-day POC, buy/no-buy ADR | SEC | 3 ed | P1 | ADR |

**Starter playbooks**

| Trigger | Action | Approval |
|---|---|---|
| S3 bucket made public (Security Hub S3.8 / Config) | Re-apply Block Public Access; notify owner | none |
| Access key exposed (GuardDuty / Inspector Lambda code secret) | Deactivate key; P1 ticket; notify | none |
| SG 0.0.0.0/0 on 22/3389 | Revoke rule; tag; notify | none in dev, approval in prod |
| GuardDuty EC2 crypto-mining / C&C | Quarantine SG, EBS snapshot → Forensics | on-call approval |
| Root login | Page on-call, open incident | alert only |
| Lambda public URL with `AuthType NONE` | Set `AWS_IAM`; notify | approval in prod |

**Exit criteria.** All sources in SIEM with tested detections; 6 playbooks automated; MTTA critical < 15 min.

---

## 6. Integrated timeline

```
Week        1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
P0 Found.  ██ ██ ██
P1 Detect.       ██ ██ ██ ██ ██
P2 SDLC                ██ ██ ██ ██ ██ ██
P3 DAST/API                     ██ ██ ██ ██ ██ ██ ██
P4 VulnMgmt                           ██ ██ ██ ██ ██ ██ ██
P5 Pentest                                        ██ ██ ██ ██ ██ ██ ██
P6 Integr.                                              ██ ██ ██ ██ ██ ██ ██ ██ ██
Milestones       M1          M2          M3          M4          M5          M6    M7
```

| Milestone | Week | Definition |
|---|---|---|
| M1 | 3 | Landing zone, SCPs, org trail, Identity Center live |
| M2 | 7 | All detective services org-wide, FSBP baseline recorded |
| M3 | 10 | Security gates enforced on all tier-1 repos |
| M4 | 14 | 100% API routes behind authorizer + WAF; nightly DAST |
| M5 | 16 | Single findings backlog with SLAs and routing |
| M6 | 20 | First external pen test retested & closed |
| M7 | 24 | SIEM + 6 playbooks; program moves to BAU |

**Critical path.** P0.4 accounts → P1.1 delegated admin → P1.2 Security Hub → P4.5 router → P6.5 routing → P6.6 playbooks.
Any slip in P0.3 (Control Tower enrolment) moves everything; start enrolment rehearsal in week 1.

---

## 7. RACI

| Activity | Cloud/DevOps platform | App engineering | Security (AppSec/SecOps) | CISO / leadership |
|---|---|---|---|---|
| Landing zone, SCPs, Identity Center | R/A | I | C | I |
| Security Hub, GuardDuty, Inspector rollout | R | I | A | I |
| Pipeline security templates | R | C | A | I |
| Fixing findings within SLA | C | R/A | C | I |
| DAST and API hardening | R | R | A | I |
| Pen-test scoping and coordination | R | C | A | I |
| Risk exceptions | I | R (requests) | C | A |
| SIEM detections and playbooks | C | I | R/A | I |

---

## 8. KPIs and how each is measured

| KPI | Target | Source / query |
|---|---|---|
| Security Hub FSBP score | ≥ 90% | `aws securityhub get-security-control-definition` + Security Hub summary; weekly snapshot Lambda → CloudWatch metric `Security/FSBPScore` |
| Accounts with all services enabled | 100% | Config aggregator advanced query + `inspector2 batch-get-account-status` |
| Tier-1 repos with SAST/SCA/secrets/IaC gates | 100% | ADO REST: pipelines whose YAML extends `security-scan.yml` ÷ tier-1 repos |
| MTTR critical / high | ≤ 7 / ≤ 30 days | Jira `SECVULN` resolved − created, by priority |
| SLA compliance (critical + high) | ≥ 90% | DefectDojo SLA report |
| API routes with authorizer + WAF | 100% | `export_api_inventory.py --coverage` |
| Pen-test crit/high retested & closed | 100% within 30 days | DefectDojo engagement *Pentest-YYYY* |
| MTTA critical alerts | < 15 min | PagerDuty analytics |
| Open exceptions past expiry | 0 | `exception_expiry` Lambda metric `Security/ExpiredExceptions` |

---

## 9. Risk register

| # | Risk | L | I | Mitigation | Owner |
|---|---|---|---|---|---|
| R1 | SCP or WAF blocks legitimate traffic/deployments | M | H | Staged promotion, count mode, AccessDenied dashboard, fast rollback via Terraform | PLT |
| R2 | Alert fatigue from initial Security Hub/Inspector volume | H | M | 2-week triage sprint, automation rules, consolidated control findings, only crit/high routed | SEC |
| R3 | Pipeline gates slow delivery / developer pushback | M | M | Diff-aware scanning, 2-week audit mode, champions, < 6 min stage budget | PLT |
| R4 | Cost overrun (Config, Macie, Security Lake, GuardDuty data events) | M | M | Daily recording for high-churn types, Macie sampling, cost category + budget alarms | PLT |
| R5 | IdP integration delayed | M | H | Start week 1; fallback: Identity Center directory with MFA for 4 weeks | PLT |
| R6 | SIEM decision late | M | M | Security Lake is SIEM-agnostic; OpenSearch fallback | CISO |
| R7 | Pen-test vendor procurement > 4 weeks | M | M | Start P5.1 in week 10 | SEC |
| R8 | Secrets found in git history in use by prod | H | H | Rotate first, then purge; coordinate change windows | APP |
| R9 | Control Tower enrolment conflicts with existing Config recorders/CloudTrail | M | H | Pre-check script, delete conflicting recorders in a change window | PLT |

---

## 10. Cost drivers and controls

Prices change; size with the AWS Pricing Calculator before week 3. Main drivers:

* **AWS Config** — configuration items recorded; use daily periodic recording for high-churn types.
* **Security Hub** — security checks + finding ingestion events; disable controls that don't apply (e.g. EKS if none).
* **GuardDuty** — CloudTrail/VPC/DNS volume, S3 data events, Lambda network activity, malware scans.
* **Inspector** — number of Lambda functions, ECR images, EC2 instances.
* **Macie** — bucket inventory + bytes inspected; automated discovery samples by default.
* **Security Lake** — normalized GB ingested; tier to Glacier after 90 days hot if SIEM retains.
* **WAF** — web ACLs × rules + requests; Bot Control only on public sites.
* Controls: AWS Budgets on cost category `Security`, anomaly detection, monthly review in steering.

---

## 11. Communications and enablement

* Week 1: announcement to engineering (what changes, when, who to ask).
* Week 5: AppSec training for champions (OWASP Top 10, API Top 10, reading SARIF, fixing Checkov findings).
* Week 8: "How to pass the security stage" wiki + office hours twice a week during rollout.
* Monthly security newsletter with KPI chart and "fix of the month".

---

## 12. Portfolio evidence checklist

- [ ] Terraform `security-baseline` module on GitHub (kshartul) with README + architecture diagram
- [ ] ADO `security-scan.yml` with sample SARIF from Semgrep, Gitleaks, Trivy, Checkov
- [ ] DVSA scanned with ZAP before/after hardening (report diff)
- [ ] DefectDojo dashboard screenshot + vulnerability management standard
- [ ] Pen-test RoE template + Stratus Red Team purple-team write-up with the GuardDuty finding that fired
- [ ] EventBridge → Lambda → Jira/Teams playbook code
- [ ] AWS Certified Security – Specialty (optionally CCSP / GIAC GCLD)

---

## Appendix A — Definition of done for every work package

1. Code merged to `main` via PR with plan output and Checkov pass.
2. Applied by pipeline (never console) to Sandbox → Dev → Stage → Prod as applicable.
3. Acceptance test recorded (command + output snippet) in the Jira ticket.
4. Runbook/README updated; rollback documented.
5. KPI source exists for anything the work package claims to improve.

## Appendix B — ADR template

```
# ADR-NNN: <decision>
Date / Status (proposed|accepted|superseded)
Context — what forces are at play
Decision — what we chose
Alternatives — what we rejected and why
Consequences — cost, risk, operational impact
```

Initial ADRs to write: ADR-001 Security Hub central configuration over local; ADR-002 DefectDojo as AppSec
aggregator; ADR-003 Security Lake over direct SIEM ingestion; ADR-004 OIDC federation for ADO → AWS;
ADR-005 SIEM selection.
