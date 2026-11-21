"""Authenticated YC HTTP invocation; never trust headers supplied by the caller."""

import ipaddress
import json
import re


def handler(event, context):
    nonce = (event.get("queryStringParameters") or {}).get("nonce", "")
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        return {"statusCode": 400, "body": "Invalid nonce"}
    try:
        address = ipaddress.ip_address(event["requestContext"]["identity"]["sourceIp"])
        if address.version != 4 or not address.is_global:
            raise ValueError
    except (KeyError, ValueError):
        return {"statusCode": 422, "body": "Public IPv4 required"}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps({"nonce": nonce, "ip": str(address)}),
    }
