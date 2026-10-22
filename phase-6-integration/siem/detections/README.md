# SIEM detection content (P6.4)

Detections are written in **Sigma** (vendor-neutral) and converted with `sigma-cli` to the chosen SIEM
(Splunk SPL / Microsoft Sentinel KQL / OpenSearch). Log source = Security Lake OCSF tables
(`cloudtrail` → OCSF API Activity 6003, `vpcflow` → Network Activity 4001, etc.) or raw CloudTrail.

```bash
pip install sigma-cli
sigma plugin install splunk        # or: microsoft365defender / opensearch
sigma convert -t splunk -p splunk_windows  aws/*.yml    # pick the AWS/CloudTrail pipeline for your backend
```

| ID | Rule | ATT&CK | Severity | Purple-team test |
|---|---|---|---|---|
| AWS-IAM-001 | Root account usage | T1078.004 | critical | console-login root (sandbox) |
| AWS-IAM-002 | Console login without MFA | T1078.004 | high | stratus initial-access.console-login-without-mfa |
| AWS-IAM-005 | Break-glass role used | T1078 | critical | quarterly break-glass test |
| AWS-CRED-002 | Secrets Manager mass retrieval | T1555 | high | stratus credential-access.secretsmanager-batch-retrieve-secrets |
| AWS-DEF-001 | CloudTrail / GuardDuty / Security Hub tamper attempt | T1562.008 | critical | stratus defense-evasion.cloudtrail-stop |
| AWS-EXF-001 | S3 bucket policy opened to external principal | T1537 | high | stratus exfiltration.s3-backdoor-bucket-policy |
| AWS-PER-002 | Lambda permission granted to `*` | T1546 | high | stratus persistence.lambda-backdoor-function |
| AWS-ID-001 | IdP sign-in followed by AWS console from different country within 1 h | T1078 | high | manual (VPN egress) |
| AWS-CICD-001 | ADO OIDC role used outside pipeline source IPs / unusual repo subject | T1199 | high | manual |

Every rule must have: test case (purple-team row), owner, triage notes, false-positive guidance.
