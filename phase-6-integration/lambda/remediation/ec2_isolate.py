"""
Playbook 4 — GuardDuty EC2 crypto-mining / C&C (CryptoCurrency:EC2/*, Backdoor:EC2/C&CActivity*, Trojan:EC2/*).
Invoked by Step Functions AFTER on-call approval. Steps (idempotent):
  1. detach from ASG (so it is not replaced and terminated)
  2. create quarantine SG (no ingress, no egress) and attach as the only SG
  3. disassociate instance profile (stop credential use)
  4. snapshot all EBS volumes, tag, share with Forensics account
"""
import os

from common import DRY_RUN, notify, session_for

FORENSICS_ACCOUNT = os.getenv("FORENSICS_ACCOUNT_ID", "")


def _quarantine_sg(ec2, vpc_id: str) -> str:
    name = "soar-quarantine"
    existing = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]},
                                                     {"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]
    sg = ec2.create_security_group(GroupName=name, Description="SOAR quarantine - no traffic", VpcId=vpc_id)["GroupId"]
    ec2.revoke_security_group_egress(GroupId=sg, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    return sg


def handler(event, _ctx):
    detail = event.get("detail", event)
    account = detail.get("accountId") or detail.get("AwsAccountId")
    region = detail.get("region") or detail.get("Region") or "ap-south-1"
    instance_id = (detail.get("resource", {}).get("instanceDetails", {}) or {}).get("instanceId") or event.get("instanceId")
    sess = session_for(account, region)
    ec2, asg = sess.client("ec2"), sess.client("autoscaling")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    actions = []

    if DRY_RUN:
        return {"action": "dry-run", "instance": instance_id}

    groups = asg.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
    if groups:
        asg.detach_instances(InstanceIds=[instance_id], AutoScalingGroupName=groups[0]["AutoScalingGroupName"],
                             ShouldDecrementDesiredCapacity=False)
        actions.append("detached-asg")

    sg = _quarantine_sg(ec2, inst["VpcId"])
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg])
    actions.append(f"quarantine-sg:{sg}")

    for assoc in ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}])["IamInstanceProfileAssociations"]:
        ec2.disassociate_iam_instance_profile(AssociationId=assoc["AssociationId"])
        actions.append("profile-removed")

    snaps = ec2.create_snapshots(
        InstanceSpecification={"InstanceId": instance_id, "ExcludeBootVolume": False},
        Description=f"forensics {instance_id}",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "forensics", "Value": instance_id}]}],
        CopyTagsFromSource="volume",
    )["Snapshots"]
    if FORENSICS_ACCOUNT:
        for s in snaps:
            # Snapshots encrypted with a CMK also need a KMS grant for the forensics account (IR runbook step)
            ec2.modify_snapshot_attribute(SnapshotId=s["SnapshotId"], Attribute="createVolumePermission",
                                          OperationType="add", UserIds=[FORENSICS_ACCOUNT])
    actions.append(f"snapshots:{','.join(s['SnapshotId'] for s in snaps)}")
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "security-incident", "Value": "isolated-by-soar"}])

    notify(f"P1: EC2 {instance_id} isolated", {"account": account, "instance": instance_id, "actions": actions,
                                              "next": "docs/runbooks/ir-ec2-compromise.md"})
    return {"action": "isolated", "instance": instance_id, "steps": actions}
