# Runbook — Break-glass access

**Purpose:** regain administrative access when Identity Center / the IdP is unavailable.

## Design

* Two IAM users in the **management account** only: `breakglass-01`, `breakglass-02`.
  * Hardware FIDO2 MFA each; passwords split (two halves, two custodians) in sealed envelopes in the safe.
  * Only permission: `sts:AssumeRole` on `arn:aws:iam::*:role/SecurityBreakGlass` with `aws:MultiFactorAuthPresent=true`.
* `SecurityBreakGlass` role in every account (AdministratorAccess); excluded from SCP denies.
* Any use triggers the `BreakGlassUse` metric filter → SNS → PagerDuty P1 and SIEM rule `AWS-IAM-005`.

## Use

1. Incident commander declares break-glass in the incident channel and records reason.
2. Two custodians retrieve envelopes; sign the access log.
3. Sign in, assume `SecurityBreakGlass` in the target account, perform only the recovery action.
4. Record every action in the incident timeline.

## After use (within 24 h)

1. Rotate both password halves; re-seal.
2. Review CloudTrail for the session (`userIdentity.arn` contains `SecurityBreakGlass`).
3. Post-incident review: why was normal access unavailable?

## Quarterly test

Sign in with each break-glass user, assume the role in Sandbox, confirm the alarm fired, rotate.
