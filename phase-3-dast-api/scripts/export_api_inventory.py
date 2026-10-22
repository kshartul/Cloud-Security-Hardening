#!/usr/bin/env python3
"""
P3.1 — API inventory across the organization.

For every account/region: REST + HTTP APIs, stages, routes, authorizer per method,
WAF association, owner / data-classification tags, OpenAPI export (REST).
Outputs:
  inventory.csv            one row per route (feeds KPI "API routes with authorizer + WAF")
  openapi/<api>-<stage>.json  exported specs (REST)
  --hostnames-only         public custom domains + execute-api hostnames for Nuclei

Exit code 1 with --coverage if any route lacks an authorizer or WAF (use as KPI/gate).
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys

import boto3
from botocore.exceptions import ClientError


def sessions(role: str):
    org = boto3.client("organizations")
    sts = boto3.client("sts")
    for page in org.get_paginator("list_accounts").paginate():
        for acct in page["Accounts"]:
            if acct["Status"] != "ACTIVE":
                continue
            try:
                c = sts.assume_role(RoleArn=f"arn:aws:iam::{acct['Id']}:role/{role}", RoleSessionName="api-inventory")["Credentials"]
            except ClientError:
                print(f"skip {acct['Id']} (cannot assume {role})", file=sys.stderr)
                continue
            yield acct, boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                      aws_session_token=c["SessionToken"])


def rest_apis(sess, region, acct, rows, hosts, export_dir):
    apigw = sess.client("apigateway", region_name=region)
    waf = sess.client("wafv2", region_name=region)
    for api in apigw.get_paginator("get_rest_apis").paginate().build_full_result().get("items", []):
        tags = api.get("tags", {})
        endpoint = ",".join(api.get("endpointConfiguration", {}).get("types", []))
        resources = apigw.get_paginator("get_resources").paginate(restApiId=api["id"], embed=["methods"]).build_full_result()["items"]
        for stage in apigw.get_stages(restApiId=api["id"])["item"]:
            arn = f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage['stageName']}"
            try:
                acl = waf.get_web_acl_for_resource(ResourceArn=arn).get("WebACL", {}).get("Name", "")
            except ClientError:
                acl = ""
            if "PRIVATE" not in endpoint:
                hosts.add(f"{api['id']}.execute-api.{region}.amazonaws.com")
            if export_dir:
                try:
                    body = apigw.get_export(restApiId=api["id"], stageName=stage["stageName"], exportType="oas30",
                                            accepts="application/json")["body"].read()
                    (export_dir / f"{api['name']}-{stage['stageName']}.json").write_bytes(body)
                except ClientError:
                    pass
            for res in resources:
                for method, m in (res.get("resourceMethods") or {}).items():
                    if method == "OPTIONS":
                        continue
                    rows.append({
                        "account": acct["Name"], "account_id": acct["Id"], "region": region, "type": "REST",
                        "api": api["name"], "api_id": api["id"], "stage": stage["stageName"], "endpoint": endpoint,
                        "method": method, "path": res["path"],
                        "auth": m.get("authorizationType", "NONE"),
                        "api_key_required": m.get("apiKeyRequired", False),
                        "waf": acl, "owner": tags.get("owner", ""),
                        "classification": tags.get("data-classification", ""),
                    })


def http_apis(sess, region, acct, rows, hosts):
    v2 = sess.client("apigatewayv2", region_name=region)
    for api in v2.get_apis().get("Items", []):
        if api.get("ProtocolType") != "HTTP":
            continue
        hosts.add(api["ApiEndpoint"].replace("https://", ""))
        for r in v2.get_routes(ApiId=api["ApiId"]).get("Items", []):
            method, _, path = r["RouteKey"].partition(" ")
            rows.append({
                "account": acct["Name"], "account_id": acct["Id"], "region": region, "type": "HTTP",
                "api": api["Name"], "api_id": api["ApiId"], "stage": "*", "endpoint": "REGIONAL",
                "method": method, "path": path or r["RouteKey"], "auth": r.get("AuthorizationType", "NONE"),
                "api_key_required": r.get("ApiKeyRequired", False),
                "waf": "n/a (HTTP API: use CloudFront+WAF)", "owner": api.get("Tags", {}).get("owner", ""),
                "classification": api.get("Tags", {}).get("data-classification", ""),
            })


def custom_domains(sess, region, hosts):
    for d in sess.client("apigateway", region_name=region).get_domain_names().get("items", []):
        hosts.add(d["domainName"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", default="SecurityReadOnlyAutomation")
    ap.add_argument("--regions", nargs="+", default=["ap-south-1", "us-east-1"])
    ap.add_argument("--out", default="inventory.csv")
    ap.add_argument("--export-openapi", action="store_true")
    ap.add_argument("--hostnames-only", action="store_true")
    ap.add_argument("--coverage", action="store_true")
    a = ap.parse_args()

    rows, hosts = [], set()
    export_dir = pathlib.Path("openapi") if a.export_openapi else None
    if export_dir:
        export_dir.mkdir(exist_ok=True)

    for acct, sess in sessions(a.role):
        for region in a.regions:
            rest_apis(sess, region, acct, rows, hosts, export_dir)
            http_apis(sess, region, acct, rows, hosts)
            custom_domains(sess, region, hosts)

    if a.hostnames_only:
        pathlib.Path(a.out).write_text("\n".join(sorted(hosts)) + "\n")
        print(f"{len(hosts)} hostnames -> {a.out}")
        return 0

    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["api"])
        w.writeheader()
        w.writerows(rows)

    total = len(rows)
    no_auth = [r for r in rows if r["auth"] in ("NONE", "") ]
    no_waf = [r for r in rows if r["type"] == "REST" and not r["waf"]]
    covered = total - len({id(r) for r in no_auth + no_waf})
    pct = 100.0 * covered / total if total else 100.0
    print(json.dumps({"routes": total, "no_authorizer": len(no_auth), "rest_without_waf": len(no_waf),
                      "coverage_pct": round(pct, 1)}))
    return 1 if a.coverage and pct < 100 else 0


if __name__ == "__main__":
    sys.exit(main())
