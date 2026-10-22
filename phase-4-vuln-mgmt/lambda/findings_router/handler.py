"""
findings-router — EventBridge target in the Security Tooling account (Phase 4, P4.5).

Event: "Security Hub Findings - Imported" (CRITICAL/HIGH, Workflow NEW, ACTIVE) or a
resolved finding (RecordState ARCHIVED / Compliance PASSED / Workflow RESOLVED).

For NEW findings:
  1. Enrich: CVE -> EPSS (FIRST API) + CISA KEV (cached catalogue in /tmp)
  2. Resource tags (owner, team, exposure, data-classification, criticality, environment)
     from the finding, else via cross-account tagging API
  3. Risk score + SLA due date (risk.py)
  4. Create (or reuse) Jira issue in SECVULN, idempotent on finding id
  5. BatchUpdateFindings: Workflow=NOTIFIED, Note=<JIRA-KEY due YYYY-MM-DD>, UserDefinedFields
  6. P1 -> also publish to the pager SNS topic
For resolved findings:
  transition the Jira issue to "Verified" (verify-by-rescan).

Env:
  JIRA_BASE_URL, JIRA_PROJECT=SECVULN, JIRA_SECRET_ARN (json {"email","api_token"})
  PAGER_TOPIC_ARN, TAG_LOOKUP_ROLE=SecurityReadOnlyAutomation, DRY_RUN=false
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

import boto3

from risk import Context, assess

log = logging.getLogger()
log.setLevel(os.getenv("LOG_LEVEL", "INFO"))

SECURITYHUB = boto3.client("securityhub")
SNS = boto3.client("sns")
STS = boto3.client("sts")
SECRETS = boto3.client("secretsmanager")

JIRA_BASE = os.getenv("JIRA_BASE_URL", "").rstrip("/")
JIRA_PROJECT = os.getenv("JIRA_PROJECT", "SECVULN")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SENSITIVE = {"confidential", "restricted"}
KEV_CACHE = "/tmp/kev.json"
KEV_TTL = 6 * 3600


# ---------------------------------------------------------------- HTTP helpers
def _http_json(url: str, method: str = "GET", body: dict | None = None, headers: dict | None = None,
               timeout: int = 10) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json", **({"Content-Type": "application/json"} if data else {}), **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed https endpoints
        raw = r.read()
        return json.loads(raw) if raw else {}


# ---------------------------------------------------------------- enrichment
def kev_catalog() -> set[str]:
    try:
        if os.path.exists(KEV_CACHE) and time.time() - os.path.getmtime(KEV_CACHE) < KEV_TTL:
            with open(KEV_CACHE) as fh:
                return set(json.load(fh))
        data = _http_json(KEV_URL, timeout=15)
        ids = [v["cveID"] for v in data.get("vulnerabilities", [])]
        with open(KEV_CACHE, "w") as fh:
            json.dump(ids, fh)
        return set(ids)
    except Exception as exc:  # enrichment must never block ticketing
        log.warning("KEV fetch failed: %s", exc)
        return set()


def epss(cves: list[str]) -> float:
    if not cves:
        return 0.0
    try:
        data = _http_json(EPSS_URL + ",".join(cves[:50]))
        return max((float(d.get("epss", 0)) for d in data.get("data", [])), default=0.0)
    except Exception as exc:
        log.warning("EPSS fetch failed: %s", exc)
        return 0.0


def cves_of(f: dict) -> list[str]:
    ids = {v.get("Id") for v in f.get("Vulnerabilities", []) if v.get("Id", "").startswith("CVE-")}
    ids |= set(CVE_RE.findall(f.get("Title", "") + " " + f.get("Description", "")))
    return sorted(i for i in ids if i)


def cvss_of(f: dict) -> float | None:
    scores = [c.get("BaseScore") for v in f.get("Vulnerabilities", []) for c in v.get("Cvss", []) if c.get("BaseScore")]
    return max(scores) if scores else None


@lru_cache(maxsize=64)
def _tagging_client(account_id: str, region: str):
    role = os.getenv("TAG_LOOKUP_ROLE", "SecurityReadOnlyAutomation")
    c = STS.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{role}", RoleSessionName="findings-router")["Credentials"]
    return boto3.client("resourcegroupstaggingapi", region_name=region, aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])


def resource_tags(f: dict) -> dict[str, str]:
    res = (f.get("Resources") or [{}])[0]
    tags = dict(res.get("Tags") or {})
    if tags.get("owner"):
        return tags
    arn = res.get("Id", "")
    if not arn.startswith("arn:"):
        return tags
    try:
        client = _tagging_client(f["AwsAccountId"], res.get("Region") or f.get("Region") or "ap-south-1")
        out = client.get_resources(ResourceARNList=[arn]).get("ResourceTagMappingList", [])
        if out:
            tags.update({t["Key"]: t["Value"] for t in out[0].get("Tags", [])})
    except Exception as exc:
        log.warning("tag lookup failed for %s: %s", arn, exc)
    return tags


# ---------------------------------------------------------------- Jira
@lru_cache(maxsize=1)
def jira_auth() -> str:
    secret = json.loads(SECRETS.get_secret_value(SecretId=os.environ["JIRA_SECRET_ARN"])["SecretString"])
    return "Basic " + base64.b64encode(f"{secret['email']}:{secret['api_token']}".encode()).decode()


def jira_find(finding_id: str) -> str | None:
    jql = f'project = {JIRA_PROJECT} AND "Finding ID[Short text]" ~ "{finding_id[-64:]}"'
    q = urllib.parse.urlencode({"jql": jql, "maxResults": 1, "fields": "key"})
    data = _http_json(f"{JIRA_BASE}/rest/api/3/search/jql?{q}", headers={"Authorization": jira_auth()})
    issues = data.get("issues", [])
    return issues[0]["key"] if issues else None


def jira_create(f: dict, tags: dict, a, cves: list[str], epss_v: float, kev: bool) -> str:
    res = (f.get("Resources") or [{}])[0]
    summary = f"[{a.effective_severity}] {f.get('Title', '')[:180]}"
    desc_lines = [
        f"*Account:* {f.get('AwsAccountId')}  *Region:* {res.get('Region', f.get('Region'))}",
        f"*Resource:* {res.get('Type')} {res.get('Id')}",
        f"*Product:* {f.get('ProductName', f.get('ProductFields', {}).get('aws/securityhub/ProductName', ''))}",
        f"*CVE:* {', '.join(cves) or 'n/a'}  *EPSS:* {epss_v:.3f}  *KEV:* {kev}",
        f"*Risk score:* {a.score} ({a.priority})  *SLA:* {a.sla_days} days → due {a.due_date}",
        "",
        (f.get("Description") or "")[:3000],
        "",
        f"*Remediation:* {f.get('Remediation', {}).get('Recommendation', {}).get('Text', '')}",
        f"{f.get('Remediation', {}).get('Recommendation', {}).get('Url', '')}",
        "",
        "Closure is automatic when the scanner stops reporting this finding (verify-by-rescan).",
    ]
    body = {
        "fields": {
            "project": {"key": JIRA_PROJECT},
            "issuetype": {"name": "Vulnerability"},
            "summary": summary,
            "priority": {"name": {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}[a.priority]},
            "duedate": a.due_date.isoformat(),
            "labels": ["securityhub", tags.get("team", "unassigned"), tags.get("environment", "unknown")] + (["kev"] if kev else []),
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": line or " "}]} for line in desc_lines],
            },
            # custom fields — ids configured per Jira instance (see jira/fields.md)
            os.getenv("JF_FINDING_ID", "customfield_10101"): f["Id"][-255:],
            os.getenv("JF_CVE", "customfield_10102"): ",".join(cves)[:255],
            os.getenv("JF_EPSS", "customfield_10103"): round(epss_v, 4),
            os.getenv("JF_RISK", "customfield_10104"): a.score,
            os.getenv("JF_TEAM", "customfield_10105"): tags.get("team", "unassigned"),
        }
    }
    data = _http_json(f"{JIRA_BASE}/rest/api/3/issue", "POST", body, {"Authorization": jira_auth()})
    return data["key"]


def jira_transition(key: str, name: str = "Verified") -> None:
    hdr = {"Authorization": jira_auth()}
    trs = _http_json(f"{JIRA_BASE}/rest/api/3/issue/{key}/transitions", headers=hdr).get("transitions", [])
    tid = next((t["id"] for t in trs if t["name"].lower() == name.lower()), None)
    if tid:
        _http_json(f"{JIRA_BASE}/rest/api/3/issue/{key}/transitions", "POST", {"transition": {"id": tid}}, hdr)


# ---------------------------------------------------------------- Security Hub
def update_finding(f: dict, note: str, status: str, udf: dict) -> None:
    if DRY_RUN:
        log.info("DRY_RUN update %s -> %s", f["Id"], status)
        return
    SECURITYHUB.batch_update_findings(
        FindingIdentifiers=[{"Id": f["Id"], "ProductArn": f["ProductArn"]}],
        Workflow={"Status": status},
        Note={"Text": note[:512], "UpdatedBy": "findings-router"},
        UserDefinedFields={k: str(v)[:1024] for k, v in udf.items()},
    )


def is_resolved(f: dict) -> bool:
    return (f.get("RecordState") == "ARCHIVED"
            or f.get("Compliance", {}).get("Status") == "PASSED"
            or f.get("Workflow", {}).get("Status") == "RESOLVED")


# ---------------------------------------------------------------- main
def handle_new(f: dict, kev_set: set[str]) -> dict:
    cves = cves_of(f)
    kev = any(c in kev_set for c in cves)
    epss_v = epss(cves)
    tags = resource_tags(f)
    ctx = Context(
        severity=f.get("Severity", {}).get("Label", "MEDIUM"),
        cvss=cvss_of(f),
        epss=epss_v,
        kev=kev,
        internet_facing=tags.get("exposure") == "internet",
        sensitive_data=tags.get("data-classification") in SENSITIVE,
        tier1=tags.get("criticality") == "tier-1",
        prod=tags.get("environment") == "prod",
    )
    a = assess(ctx)

    key = None if DRY_RUN or not JIRA_BASE else (jira_find(f["Id"]) or jira_create(f, tags, a, cves, epss_v, kev))
    note = f"{key or 'NO-JIRA'} · {a.priority} · risk {a.score} · due {a.due_date}"
    update_finding(f, note, "NOTIFIED", {
        "jira": key or "", "risk_score": a.score, "priority": a.priority,
        "sla_due": a.due_date.isoformat(), "epss": round(epss_v, 4), "kev": kev, "team": tags.get("team", "unassigned"),
    })
    if a.priority == "P1" and os.getenv("PAGER_TOPIC_ARN") and not DRY_RUN:
        SNS.publish(TopicArn=os.environ["PAGER_TOPIC_ARN"], Subject=f"P1 security finding {key}"[:100],
                    Message=json.dumps({"jira": key, "title": f.get("Title"), "account": f.get("AwsAccountId"),
                                        "resource": (f.get("Resources") or [{}])[0].get("Id"), "risk": a.score}))
    return {"id": f["Id"], "jira": key, "priority": a.priority, "score": a.score}


def handle_resolved(f: dict) -> dict:
    key = (f.get("UserDefinedFields") or {}).get("jira")
    if key and JIRA_BASE and not DRY_RUN:
        jira_transition(key, "Verified")
    return {"id": f["Id"], "jira": key, "resolved": True}


def handler(event, _context):
    findings = event.get("detail", {}).get("findings", [])
    kev_set = kev_catalog() if findings else set()
    results = []
    for f in findings:
        try:
            results.append(handle_resolved(f) if is_resolved(f) else handle_new(f, kev_set))
        except urllib.error.HTTPError as exc:
            log.error("HTTP %s for %s: %s", exc.code, f.get("Id"), exc.read()[:500])
            raise  # let EventBridge retry → DLQ
    log.info(json.dumps({"processed": len(results), "results": results}, default=str))
    return {"processed": len(results)}
