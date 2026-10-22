"""
Playbook 6 — Lambda function URL with AuthType NONE (Config LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED / Security Hub Lambda.1).
Set AuthType=AWS_IAM. Non-prod: automatic. Prod: via approval Step Function.
Functions tagged public-url=approved (reviewed exception) are skipped.
"""
from common import DRY_RUN, annotate_finding, first_finding, is_prod, notify, session_for


def handler(event, _ctx):
    f = first_finding(event)
    res = f["Resources"][0]
    fn_arn = res["Id"]
    account, region = f["AwsAccountId"], res.get("Region", "ap-south-1")
    if is_prod(account) and not event.get("approved"):
        return {"action": "needs-approval", "function": fn_arn}

    lam = session_for(account, region).client("lambda")
    try:
        cfg = lam.get_function_url_config(FunctionName=fn_arn)
    except lam.exceptions.ResourceNotFoundException:
        return {"action": "no-url"}
    tags = lam.list_tags(Resource=fn_arn.split(":alias")[0]).get("Tags", {})
    if tags.get("public-url") == "approved":
        return {"action": "skipped-approved"}
    if cfg["AuthType"] == "NONE" and not DRY_RUN:
        lam.update_function_url_config(FunctionName=fn_arn, AuthType="AWS_IAM")
    annotate_finding(f, "SOAR: function URL AuthType set to AWS_IAM")
    notify(f"Lambda URL secured: {fn_arn.split(':')[-1]}", {"account": account, "function": fn_arn, "dry_run": DRY_RUN})
    return {"action": "secured", "function": fn_arn}
