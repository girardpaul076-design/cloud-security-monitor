import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_REGION = os.environ.get("AWS_REGION", "us-east-2")
BOTO_CONFIG = Config(
    region_name=DEFAULT_REGION,
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2, "mode": "standard"},
)

SCANNER_AGENTS = (
    "sqlmap/1.8",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "gobuster/3.6",
    "python-requests/2.32.0",
)


def resolve_target_bucket(region: str, bucket_override: str | None = None) -> str:
    if bucket_override:
        return bucket_override.strip()
    sts = boto3.client("sts", config=BOTO_CONFIG)
    account_id = sts.get_caller_identity()["Account"]
    return f"siem-simulation-victim-{account_id}-{region}"


def set_bucket_acl(bucket_name: str, acl: str, dry_run: bool) -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)

    if dry_run:
        print(f"[DRY-RUN] Would call put_bucket_acl(Bucket='{bucket_name}', ACL='{acl}')")
        return

    s3.put_bucket_acl(Bucket=bucket_name, ACL=acl)
    grants = s3.get_bucket_acl(Bucket=bucket_name).get("Grants", [])
    print(f"ACL updated to '{acl}' on '{bucket_name}' (grants count: {len(grants)}).")


def probe_siem_api(api_url: str, send_scanners: bool) -> None:
    base_url = api_url.rstrip("/")
    agents = ["Mozilla/5.0 LegitimateBrowserTest"]
    if send_scanners:
        agents.extend(SCANNER_AGENTS)

    for ua in agents:
        req = urllib.request.Request(
            base_url,
            method="GET",
            headers={"User-Agent": ua},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed: dict[str, Any] = json.loads(raw) if raw else {}
                print(
                    f"[API {resp.status}] UA='{ua}' -> "
                    f"flagged={parsed.get('security_flagged')} visitors={parsed.get('visitor_count')}"
                )
        except urllib.error.URLError as exc:
            print(f"[API ERROR] UA='{ua}' -> {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate S3 ACL exposure and/or SIEM HTTP telemetry traffic."
    )
    parser.add_argument(
        "--region",
        default=DEFAULT_REGION,
        help=f"AWS region (default: {DEFAULT_REGION})",
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="Optional explicit target S3 bucket name override",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply ACL='public-read' to the target bucket (default is dry-run)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Restore bucket ACL to 'private' after testing",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("SIEM_API_URL", ""),
        help="Optional HTTP API base URL to send test requests",
    )
    parser.add_argument(
        "--scanners",
        action="store_true",
        help="Include simulated scanner user-agents when --api-url is provided",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        target_bucket = resolve_target_bucket(args.region, args.bucket)
        print(f"Target bucket: {target_bucket} ({args.region})")

        if args.reset:
            set_bucket_acl(target_bucket, "private", dry_run=not args.apply)
        else:
            set_bucket_acl(target_bucket, "public-read", dry_run=not args.apply)
            if args.apply:
                print("Awaiting AWS EventBridge threat capture / remediation loop...")

        if args.api_url:
            probe_siem_api(args.api_url, send_scanners=args.scanners)

        return 0
    except (ClientError, BotoCoreError) as exc:
        print(f"AWS error during simulation: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error during simulation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())