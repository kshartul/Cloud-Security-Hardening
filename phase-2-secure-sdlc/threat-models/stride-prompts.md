# STRIDE prompt sheet — serverless / data platform

| STRIDE | Ask for every element | Typical AWS controls |
|---|---|---|
| **S**poofing | Can a caller pretend to be another user, service, or tenant? Are JWTs validated (iss, aud, exp, signature)? Are DMS/Redshift users shared? | Cognito/JWT authorizer, mTLS for B2B, IAM roles per function, Identity Center, no shared DB users |
| **T**ampering | Can request bodies, S3 objects, CDC streams or pipeline artefacts be altered in transit or at rest? | Request validators, TLS 1.2, S3 Object Lock/versioning, KMS, signed artefacts, branch policies |
| **R**epudiation | Can we prove who did what? Are API calls and data changes logged with principal id? | API GW JSON access logs with `sub`, CloudTrail data events, Object Lock log archive |
| **I**nformation disclosure | Can a user read another tenant's object (BOLA)? Do errors leak stack traces? Is PII in logs? | Owner check in handler, response models, Macie, log redaction, KMS key policies |
| **D**enial of service | Can one caller exhaust concurrency, Redshift slots or DMS throughput? | Usage plans, WAF rate rules, reserved concurrency, WLM queues, payload limits |
| **E**levation of privilege | Can a function role do more than it needs? Can a pipeline identity reach prod? Can PassRole be abused? | Least-privilege roles, Access Analyzer gates, SCPs, permission boundaries, OIDC subject conditions |

## Serverless-specific questions

* Does any Lambda accept a URL, bucket/key or SQL fragment from the event? (SSRF / injection)
* Are function URLs used? With which `AuthType`?
* Are secrets fetched at runtime from Secrets Manager or baked into env vars / layers?
* Is the event source (SQS, EventBridge, S3) restricted by resource policy to the expected account/source?
* What happens on retry — is the handler idempotent (replay attacks / duplicate writes)?
* Who can update the function code / alias (pipeline role only)?
