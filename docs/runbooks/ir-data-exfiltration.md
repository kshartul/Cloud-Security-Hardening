# IR runbook — Data exfiltration (S3 / Redshift)

**Triggers:** GuardDuty `Exfiltration:S3/*`, `Impact:S3/*`, S3 Protection anomalies, Macie sensitive-data findings on a newly public/shared bucket,
Access Analyzer external access on DW buckets, SIEM AWS-EXF-001, abnormal Redshift `UNLOAD` to external buckets.

## 1. Contain

* S3: confirm SOAR re-applied BPA; remove external principals from bucket policy; if the principal is internal, revoke its sessions.
* Redshift: revoke the DB user/IAM role used; check `STL_UNLOAD_LOG` for destinations; block egress by SG if UNLOAD to external S3.
* Snapshot policies & object versions before changing anything (evidence).

## 2. Scope

1. S3 data events (CloudTrail / Security Lake) for `GetObject`, `CopyObject`, `ListObjects` by the principal: object keys, bytes, source IPs.
2. Macie: which objects contained sensitive data (classification results).
3. Redshift: `STL_QUERY`, `SVL_STATEMENTTEXT`, `STL_UNLOAD_LOG`, `STL_CONNECTION_LOG` for the time window.

## 3. Notify

If personal data was accessed: Legal/Privacy within 24 h for breach-notification assessment (GDPR/DPDP Act etc.). CISO informs leadership.

## 4. Eradicate / learn

Tighten bucket policy (`aws:PrincipalOrgID`, VPC endpoint conditions), add SCP if a pattern emerged, add detection, rotate any credentials found in exfiltrated data.
