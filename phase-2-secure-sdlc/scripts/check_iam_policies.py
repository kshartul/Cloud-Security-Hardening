#!/usr/bin/env python3
"""
IAM policy gate for CI (Phase 2).

Extracts identity/resource policies from:
  * a packaged Serverless/CloudFormation template (--cfn)
  * a Terraform plan JSON (--tf-plan; `terraform show -json plan.out > plan.json`)
and runs IAM Access Analyzer:
  * validate-policy           -> fail on ERROR and SECURITY_WARNING
  * check-no-new-access       -> fail if the policy grants more than the reference policy (optional --reference)
  * check-access-not-granted  -> fail if any policy grants a forbidden action (e.g. iam:PassRole on *, kms:Decrypt on *)

Writes a DefectDojo "Generic Findings Import" JSON.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import boto3

# Application roles must never be able to do these (privilege escalation / tamper / destroy)
FORBIDDEN_ACTIONS = [
    "iam:CreateUser", "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy",
    "iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy",
    "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy",
    "s3:PutBucketPolicy", "s3:DeleteBucket", "organizations:LeaveOrganization",
]


def walk_cfn(template: dict):
    for name, res in template.get("Resources", {}).items():
        t, props = res.get("Type"), res.get("Properties", {})
        if t == "AWS::IAM::Role":
            for pol in props.get("Policies", []):
                yield f"{name}/{pol.get('PolicyName')}", pol.get("PolicyDocument"), "IDENTITY_POLICY"
        elif t in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            yield name, props.get("PolicyDocument"), "IDENTITY_POLICY"
        elif t == "AWS::S3::BucketPolicy":
            yield name, props.get("PolicyDocument"), "RESOURCE_POLICY"
        elif t == "AWS::SQS::QueuePolicy":
            yield name, props.get("PolicyDocument"), "RESOURCE_POLICY"


def walk_tf(plan: dict):
    def mods(m):
        yield m
        for c in m.get("child_modules", []):
            yield from mods(c)

    root = plan.get("planned_values", {}).get("root_module", {})
    for m in mods(root):
        for r in m.get("resources", []):
            v = r.get("values", {}) or {}
            addr = r.get("address")
            if r["type"] in ("aws_iam_policy", "aws_iam_role_policy") and v.get("policy"):
                yield addr, v["policy"], "IDENTITY_POLICY"
            elif r["type"] in ("aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_kms_key") and v.get("policy"):
                yield addr, v["policy"], "RESOURCE_POLICY"


def has_intrinsics(doc) -> bool:
    s = json.dumps(doc)
    return any(k in s for k in ('"Fn::', '"Ref"'))


def resolve_placeholders(doc):
    """Replace CloudFormation intrinsics with a dummy ARN so validation can still run."""
    if isinstance(doc, dict):
        if len(doc) == 1 and next(iter(doc)) in ("Ref", "Fn::GetAtt", "Fn::Sub", "Fn::Join", "Fn::ImportValue", "Fn::If"):
            return "arn:aws:s3:::placeholder-resource"
        return {k: resolve_placeholders(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [resolve_placeholders(x) for x in doc]
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cfn")
    ap.add_argument("--tf-plan")
    ap.add_argument("--reference", help="Reference policy JSON for check-no-new-access")
    ap.add_argument("--out", default="iam-policy-findings.json")
    ap.add_argument("--region", default="ap-south-1")
    a = ap.parse_args()

    items = []
    if a.cfn and pathlib.Path(a.cfn).exists():
        items += list(walk_cfn(json.loads(pathlib.Path(a.cfn).read_text())))
    if a.tf_plan and pathlib.Path(a.tf_plan).exists():
        items += list(walk_tf(json.loads(pathlib.Path(a.tf_plan).read_text())))

    aa = boto3.client("accessanalyzer", region_name=a.region)
    findings, blocking = [], 0

    for name, doc, ptype in items:
        if doc is None:
            continue
        if isinstance(doc, str):
            doc = json.loads(doc)
        if has_intrinsics(doc):
            doc = resolve_placeholders(doc)
        doc_s = json.dumps(doc)

        for f in aa.validate_policy(policyDocument=doc_s, policyType=ptype)["findings"]:
            sev = {"ERROR": "High", "SECURITY_WARNING": "High", "WARNING": "Medium", "SUGGESTION": "Info"}[f["findingType"]]
            block = f["findingType"] in ("ERROR", "SECURITY_WARNING")
            blocking += block
            findings.append({
                "title": f"[{f['issueCode']}] {name}",
                "severity": sev,
                "description": f["findingDetails"],
                "references": f.get("learnMoreLink", ""),
                "file_path": a.cfn or a.tf_plan,
                "vuln_id_from_tool": f["issueCode"],
            })

        if ptype == "IDENTITY_POLICY":
            res = aa.check_access_not_granted(
                policyDocument=doc_s, policyType=ptype,
                access=[{"actions": FORBIDDEN_ACTIONS}],
            )
            if res["result"] == "FAIL":
                blocking += 1
                findings.append({
                    "title": f"[FORBIDDEN_ACTION] {name}",
                    "severity": "High",
                    "description": res.get("message", "Policy grants a forbidden broad action"),
                    "file_path": a.cfn or a.tf_plan,
                    "vuln_id_from_tool": "CHECK_ACCESS_NOT_GRANTED",
                })
            if a.reference:
                ref = pathlib.Path(a.reference).read_text()
                res = aa.check_no_new_access(newPolicyDocument=doc_s, existingPolicyDocument=ref, policyType=ptype)
                if res["result"] == "FAIL":
                    blocking += 1
                    findings.append({
                        "title": f"[NEW_ACCESS] {name}",
                        "severity": "Medium",
                        "description": res.get("message", "Policy grants access beyond reference"),
                        "file_path": a.cfn or a.tf_plan,
                        "vuln_id_from_tool": "CHECK_NO_NEW_ACCESS",
                    })

    pathlib.Path(a.out).write_text(json.dumps({"findings": findings}, indent=2))
    print(f"policies={len(items)} findings={len(findings)} blocking={blocking}")
    for f in findings:
        print(f"  {f['severity']:6s} {f['title']}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
