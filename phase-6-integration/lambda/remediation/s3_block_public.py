"""Playbook 1 — S3 bucket made public (Security Hub S3.2/S3.3/S3.8, Config). Re-apply BPA, notify. No approval."""
from common import DRY_RUN, annotate_finding, first_finding, notify, session_for

ALLOW_TAG = ("public-website", "approved")   # bucket tag that documents an approved public site (behind CloudFront OAC ideally)


def handler(event, _ctx):
    f = first_finding(event)
    res = f["Resources"][0]
    bucket = res["Id"].split(":::")[-1]
    account, region = f["AwsAccountId"], res.get("Region", f.get("Region", "ap-south-1"))
    s3 = session_for(account, region).client("s3")

    try:
        tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    except s3.exceptions.ClientError:
        tags = {}
    if tags.get(ALLOW_TAG[0]) == ALLOW_TAG[1]:
        notify(f"S3 public bucket left as approved: {bucket}", {"account": account, "bucket": bucket})
        return {"action": "skipped-approved", "bucket": bucket}

    if not DRY_RUN:
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    annotate_finding(f, "SOAR: bucket-level Block Public Access re-applied")
    notify(f"Auto-remediated public S3 bucket {bucket}", {"account": account, "bucket": bucket,
                                                        "owner": tags.get("owner"), "dry_run": DRY_RUN})
    return {"action": "blocked", "bucket": bucket}
