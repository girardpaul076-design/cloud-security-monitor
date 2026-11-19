import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

import boto3
from boto3.dynamodb.conditions import Attr

_DYNAMODB = boto3.resource("dynamodb")

VISITOR_TABLE_NAME = os.environ.get("VISITOR_TABLE", "VisitorTable")
METRICS_TABLE_NAME = os.environ.get("METRICS_TABLE", "MetricsTable")
IP_HASH_SALT = os.environ.get("IP_HASH_SALT", "fallback-dev-salt-12345")
VISITOR_COUNTER_ID = os.environ.get("VISITOR_COUNTER_ID", "resume-visitor-count")

VISITOR_TABLE = _DYNAMODB.Table(VISITOR_TABLE_NAME)
METRICS_TABLE = _DYNAMODB.Table(METRICS_TABLE_NAME)

MALICIOUS_AGENTS: tuple[str, ...] = (
    "sqlmap",
    "nikto",
    "gobuster",
    "nmap",
    "masscan",
    "curl",
    "python-requests",
)

CORS_HEADERS: dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "OPTIONS,GET,POST",
}


def _response(status_code: int, body: str | dict[str, Any]) -> dict[str, Any]:
    encoded = body if isinstance(body, str) else json.dumps(body, default=str)
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": encoded,
    }


def _normalize_headers(raw_headers: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(raw_headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in raw_headers.items() if v is not None}


def _get_method(event: dict[str, Any]) -> str:
    http_info = event.get("requestContext", {}).get("http", {})
    return str(http_info.get("method") or event.get("httpMethod") or "").upper()


def _get_client_ip(headers: dict[str, str], event: dict[str, Any]) -> str:
    forwarded = headers.get("x-forwarded-for", "")
    if forwarded:
        first_ip = forwarded.split(",")[0].strip()
        if first_ip:
            return first_ip
    source_ip = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    return str(source_ip) if source_ip else "0.0.0.0"


def _hash_ip(client_ip: str) -> str:
    return hashlib.sha256(f"{client_ip}{IP_HASH_SALT}".encode("utf-8")).hexdigest()


def _detect_suspicious_agent(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    return any(agent in ua_lower for agent in MALICIOUS_AGENTS)


def _is_siem_read(method: str, event: dict[str, Any]) -> bool:
    if method != "GET":
        return False
    raw_path = unquote(str(event.get("rawPath") or event.get("path") or ""))
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        query_params = {}
    return (
        raw_path.rstrip("/").endswith("/siem")
        or query_params.get("view") == "siem"
        or query_params.get("mode") == "siem"
    )


def _write_threat_event(hashed_ip: str, user_agent: str, request_id: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    print(
        f"SECURITY ALERT: Suspicious request detected from Hashed IP: {hashed_ip} "
        f"using User-Agent: {user_agent}"
    )
    METRICS_TABLE.put_item(
        Item={
            "id": f"threat-{hashed_ip}-{request_id}",
            "timestamp": timestamp,
            "hashed_ip": hashed_ip,
            "user_agent": user_agent,
            "severity": "MEDIUM",
            "request_id": request_id,
        }
    )


def _sync_visitor_count(increment: bool) -> int:
    if increment:
        resp = VISITOR_TABLE.update_item(
            Key={"id": VISITOR_COUNTER_ID},
            UpdateExpression="ADD visitor_count :inc",
            ExpressionAttributeValues={":inc": 1},
            ReturnValues="UPDATED_NEW",
        )
        return int(resp.get("Attributes", {}).get("visitor_count", 1))

    item = VISITOR_TABLE.get_item(Key={"id": VISITOR_COUNTER_ID}).get("Item", {})
    return int(item.get("visitor_count", 0))


def _fetch_recent_threats(limit: int = 50) -> list[dict[str, Any]]:
    resp = METRICS_TABLE.scan(FilterExpression=Attr("hashed_ip").exists())
    items = resp.get("Items", [])
    items.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
    return items[:limit]


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    print("Received event:", json.dumps(event, default=str))

    method = _get_method(event)
    if method == "OPTIONS":
        return _response(200, "")

    try:
        headers = _normalize_headers(event.get("headers"))
        siem_read = _is_siem_read(method, event)

        client_ip = _get_client_ip(headers, event)
        user_agent = headers.get("user-agent", "unknown")
        hashed_ip = _hash_ip(client_ip)
        is_suspicious = _detect_suspicious_agent(user_agent)

        if is_suspicious and not siem_read:
            request_id = str(getattr(context, "aws_request_id", "local-invocation"))
            _write_threat_event(hashed_ip, user_agent, request_id)

        current_count = _sync_visitor_count(increment=not siem_read)

        payload: dict[str, Any] = {
            "message": "Telemetry processed successfully",
            "visitor_count": current_count,
            "security_flagged": is_suspicious,
        }

        if siem_read:
            threats = _fetch_recent_threats()
            payload["threats"] = threats
            payload["threat_count"] = len(threats)

        return _response(200, payload)

    except Exception as exc:
        print(f"Error processing request: {exc}")
        return _response(500, {"error": str(exc)})