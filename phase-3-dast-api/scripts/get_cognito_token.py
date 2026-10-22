#!/usr/bin/env python3
"""Get a short-lived Cognito access token for the DAST test user (USER_PASSWORD_AUTH or client_credentials).

Secret JSON (Secrets Manager, stage account):
  {"region":"ap-south-1","user_pool_id":"...","client_id":"...","client_secret":"...",
   "username":"dast-bot@example.com","password":"...","flow":"password"|"client_credentials",
   "token_url":"https://<domain>.auth.ap-south-1.amazoncognito.com/oauth2/token","scope":"omni-api/orders.read"}
Prints the token only (pipeline masks it via issecret=true).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse
import urllib.request

import boto3


def secret_hash(username: str, client_id: str, client_secret: str) -> str:
    dig = hmac.new(client_secret.encode(), (username + client_id).encode(), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret-id", required=True)
    ap.add_argument("--region", default="ap-south-1")
    a = ap.parse_args()

    cfg = json.loads(boto3.client("secretsmanager", region_name=a.region).get_secret_value(SecretId=a.secret_id)["SecretString"])

    if cfg.get("flow", "password") == "client_credentials":
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": cfg.get("scope", "")}).encode()
        basic = base64.b64encode(f"{cfg['client_id']}:{cfg['client_secret']}".encode()).decode()
        req = urllib.request.Request(cfg["token_url"], data=body, headers={
            "Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310 - fixed https token URL from secret
            print(json.loads(r.read())["access_token"])
        return 0

    idp = boto3.client("cognito-idp", region_name=cfg.get("region", a.region))
    params = {"USERNAME": cfg["username"], "PASSWORD": cfg["password"]}
    if cfg.get("client_secret"):
        params["SECRET_HASH"] = secret_hash(cfg["username"], cfg["client_id"], cfg["client_secret"])
    res = idp.initiate_auth(ClientId=cfg["client_id"], AuthFlow="USER_PASSWORD_AUTH", AuthParameters=params)
    print(res["AuthenticationResult"]["AccessToken"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
