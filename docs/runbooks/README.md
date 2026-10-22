# Runbooks

| Runbook | When |
|---|---|
| [control-tower-enrolment.md](control-tower-enrolment.md) | Phase 0 — landing zone + account enrolment |
| [break-glass.md](break-glass.md) | IdP / Identity Center unavailable |
| [ir-credential-compromise.md](ir-credential-compromise.md) | Exposed or abused AWS credentials |
| [ir-ec2-compromise.md](ir-ec2-compromise.md) | Crypto-mining, C&C, malware, ransomware on EC2 |
| [ir-data-exfiltration.md](ir-data-exfiltration.md) | S3 / Redshift data leaving the estate |
| [ir-cicd-token-compromise.md](ir-cicd-token-compromise.md) | Azure DevOps token / service connection abuse |

Common to all IR: open incident in ServiceNow/Jira (P1), incident channel `#inc-<date>-<short>`, incident commander
named, timeline kept in the ticket, evidence in Forensics account case bucket, post-incident review within 5 business days.
AWS escalation: open an AWS Support case (category *Security*) — Business/Enterprise support; AWS CIRT engagement via the case.
