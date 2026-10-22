# IR runbook — EC2 compromise (crypto-mining, C&C, trojan, ransomware)

**Triggers:** GuardDuty `CryptoCurrency:EC2/*`, `Backdoor:EC2/C&CActivity*`, `Trojan:EC2/*`, Malware Protection detections, Runtime Monitoring.
**Automation:** Step Function `soar-remediation` → approval (SOAR-Approve in Security Hub) → `soar-ec2-isolate`.

## 1. Approve isolation (on-call, ≤ 15 min)

Security Hub → finding → Actions → **SOAR-Approve**. Isolation = ASG detach, quarantine SG (no ingress/egress),
instance profile removed, EBS snapshots shared to Forensics, instance tagged `security-incident`.
**Do not stop or terminate** — memory evidence would be lost.

## 2. Collect

1. Memory (if SSM agent reachable — SSM uses VPC endpoints, not the SG): run `AWS-RunShellScript` with the IR collection script (LiME / avml) to an S3 case bucket in Forensics.
2. If snapshots are CMK-encrypted: grant Forensics account `kms:CreateGrant`/`Decrypt` on the key, copy snapshot re-encrypting with the Forensics key.
3. In Forensics: create volumes from snapshots, attach read-only to the analysis instance (isolated VPC).

## 3. Scope

Detective: instance profile role activity; VPC Flow Logs to C&C IPs; other instances talking to the same IPs;
was the instance role used from outside (credential exfiltration finding)?

## 4. Eradicate / recover

Rebuild from golden AMI via pipeline (never "clean" a compromised host), rotate credentials accessible to the role,
patch the entry vector (Inspector finding / exposed port), then terminate the isolated instance after evidence sign-off.

## Ransomware variant

If S3/EBS encryption-for-ransom is suspected: check Object Lock / versioning on affected buckets, restore from AWS Backup
vault (Log Archive copy), engage AWS Support / AWS CIRT via the Support case (Business/Enterprise plan, *security incident* category).
