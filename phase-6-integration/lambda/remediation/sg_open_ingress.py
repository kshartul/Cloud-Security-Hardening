"""
Playbook 3 — Security group allows 0.0.0.0/0 or ::/0 on 22/3389 (Security Hub EC2.13/EC2.14/EC2.53/EC2.54).
Non-prod: revoke immediately. Prod: invoked by the approval Step Function after on-call approves.
"""
from common import DRY_RUN, annotate_finding, first_finding, is_prod, notify, session_for

ADMIN_PORTS = {22, 3389}
OPEN = {"0.0.0.0/0", "::/0"}


def _covers_admin(rule: dict) -> bool:
    if rule.get("IpProtocol") == "-1":
        return True
    lo, hi = rule.get("FromPort", 0), rule.get("ToPort", 65535)
    return any(lo <= p <= hi for p in ADMIN_PORTS)


def handler(event, _ctx):
    f = first_finding(event)
    res = f["Resources"][0]
    sg_id = res["Id"].split("/")[-1]
    account, region = f["AwsAccountId"], res.get("Region", "ap-south-1")
    if is_prod(account) and not event.get("approved"):
        return {"action": "needs-approval", "sg": sg_id}

    ec2 = session_for(account, region).client("ec2")
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [sg_id]}])["SecurityGroupRules"]
    bad = [r for r in rules if not r["IsEgress"] and _covers_admin(r)
           and (r.get("CidrIpv4") in OPEN or r.get("CidrIpv6") in OPEN)]
    if bad and not DRY_RUN:
        ec2.revoke_security_group_ingress(GroupId=sg_id, SecurityGroupRuleIds=[r["SecurityGroupRuleId"] for r in bad])
        ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "security-remediated", "Value": "open-admin-port-revoked"}])
    annotate_finding(f, f"SOAR: revoked {len(bad)} open admin-port rule(s); use SSM Session Manager instead")
    notify(f"Revoked open admin ports on {sg_id}", {"account": account, "sg": sg_id,
                                                    "rules": [r["SecurityGroupRuleId"] for r in bad], "dry_run": DRY_RUN})
    return {"action": "revoked", "count": len(bad)}
