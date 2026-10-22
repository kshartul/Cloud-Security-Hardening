"""
Playbook 2 — IAM access key exposed / compromised.
Triggers: GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*, CredentialAccess:*,
          Inspector Lambda code scanning "hardcoded secret" (AWS access key), Gitleaks (manual).
Action: deactivate key (never delete — forensics), tag user, P1 notify. No approval.
"""
from common import DRY_RUN, annotate_finding, first_finding, notify, session_for


def _key_and_user(f: dict) -> tuple[str | None, str | None]:
    # GuardDuty native event shape
    ak = (f.get("resource") or {}).get("accessKeyDetails") or {}
    if ak.get("accessKeyId"):
        return ak.get("accessKeyId"), ak.get("userName")
    # Security Hub ASFF shape
    for r in f.get("Resources", []):
        if r.get("Type") == "AwsIamAccessKey":
            d = r.get("Details", {}).get("AwsIamAccessKey", {})
            return d.get("AccessKeyId") or r["Id"].split("/")[-1], d.get("PrincipalName") or d.get("UserName")
    return None, None


def handler(event, _ctx):
    f = first_finding(event)
    account = f.get("AwsAccountId") or f.get("accountId")
    region = f.get("Region") or f.get("region") or "ap-south-1"
    key_id, user = _key_and_user(f)
    if not key_id or not user or key_id.startswith("ASIA"):
        # ASIA* = temporary creds (role session) → revoke sessions via role policy, handled by IR runbook
        notify("Credential finding needs manual IR (temporary or unknown key)", {"account": account, "key": key_id, "user": user})
        return {"action": "manual"}
    iam = session_for(account, region).client("iam")
    if not DRY_RUN:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        iam.tag_user(UserName=user, Tags=[{"Key": "security-incident", "Value": "key-deactivated-by-soar"}])
    annotate_finding(f, f"SOAR: access key …{key_id[-4:]} deactivated for {user}")
    notify(f"P1: access key deactivated ({user})", {"account": account, "user": user, "key_suffix": key_id[-4:],
                                                   "next": "docs/runbooks/ir-credential-compromise.md", "dry_run": DRY_RUN})
    return {"action": "deactivated", "user": user}
