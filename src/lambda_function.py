import hashlib
import json
import os
import time
from datetime import datetime, timezone
import boto3

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

visitor_table = dynamodb.Table('cloud-resume-stats')
metrics_table = dynamodb.Table('SiemMetricsTable')

SUSPICIOUS_AGENTS = (
    'curl',
    'python-requests',
    'nikto',
    'sqlmap',
    'gobuster',
    'nmap',
    'masscan',
)


def hash_ip(ip_address: str) -> str:
    salt = os.environ.get('IP_HASH_SALT', 'fallback-dev-salt')
    salted = f'{salt}:{ip_address}'.encode('utf-8')
    return hashlib.sha256(salted).hexdigest()[:16]


def record_siem_incident(target: str, event_type: str, status: str) -> str:
    incident_id = f'ALERT-{int(time.time() * 1000)}'
    metrics_table.put_item(
        Item={
            'id': incident_id,
            'timestamp': datetime.now(timezone.utc).strftime(
                '%Y-%m-%d %H:%M:%S UTC'
            ),
            'target': target,
            'event_type': event_type,
            'status': status,
        }
    )
    return incident_id


def lambda_handler(event, context):
    # --- TRIGGER 1: EventBridge / CloudTrail S3 Public Breach Remediation ---
    if 'detail' in event:
        detail = event['detail']
        bucket_name = detail.get('requestParameters', {}).get('bucketName')
        if bucket_name:
            try:
                s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
                status_msg = 'REMEDIATED'
            except Exception as e:
                status_msg = f'ERROR: {str(e)}'

            incident_id = record_siem_incident(
                target=bucket_name,
                event_type='PutBucketAcl (Public Exposure Event)',
                status=status_msg,
            )
            return {'status': 'complete', 'incident_id': incident_id}

    # --- TRIGGER 2: HTTP API Routes for Resume & SIEM Dashboard ---
    path = event.get('rawPath', '') or event.get('requestContext', {}).get(
        'http', {}
    ).get('path', '')
    raw_headers = event.get('headers') or {}
    req_headers = {k.lower(): v for k, v in raw_headers.items()}

    cors_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'OPTIONS,GET',
    }

    # ROUTE A: Privacy-Safe Unique Visitor Counter + Web Recon Detection
    if 'visitor' in path:
        raw_ip = req_headers.get('x-forwarded-for', '').split(',')[0].strip() or event.get(
            'requestContext', {}
        ).get('http', {}).get('sourceIp', 'unknown')
        user_agent = req_headers.get('user-agent', 'unknown')
        visitor_hash = hash_ip(raw_ip)
        visitor_key = f'VISITOR-{visitor_hash}'
        now_epoch = int(time.time())

        existing = visitor_table.get_item(Key={'id': visitor_key}).get('Item')
        is_new_visitor = not existing or int(existing.get('ttl', 0)) < now_epoch

        if is_new_visitor:
            visitor_table.put_item(
                Item={'id': visitor_key, 'hits': 1, 'ttl': now_epoch + 86400}
            )
            response = visitor_table.update_item(
                Key={'id': 'visitors'},
                UpdateExpression='ADD #c :val',
                ExpressionAttributeNames={'#c': 'count'},
                ExpressionAttributeValues={':val': 1},
                ReturnValues='UPDATED_NEW',
            )
            unique_views = int(response['Attributes']['count'])
            hit_count = 1
        else:
            hit_res = visitor_table.update_item(
                Key={'id': visitor_key},
                UpdateExpression='ADD hits :val',
                ExpressionAttributeValues={':val': 1},
                ReturnValues='UPDATED_NEW',
            )
            hit_count = int(hit_res['Attributes']['hits'])
            stats = visitor_table.get_item(Key={'id': 'visitors'}).get('Item', {})
            unique_views = int(stats.get('count', 1))

        if hit_count == 15:
            record_siem_incident(
                target=f'Resume Endpoint (Hash: {visitor_hash})',
                event_type='Anomalous Traffic Burst (>15 Hits / 24h)',
                status='DETECTED',
            )

        if is_new_visitor and any(
            tool in user_agent.lower() for tool in SUSPICIOUS_AGENTS
        ):
            record_siem_incident(
                target=f'Resume Endpoint (Hash: {visitor_hash})',
                event_type=f'Recon Tool Detected ({user_agent[:40]})',
                status='LOGGED',
            )

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'count': unique_views,
                'visitor_hash': visitor_hash,
                'is_new_visitor': is_new_visitor,
            }),
        }

    # ROUTE B: SIEM Attack & Alert Metrics Counter
    elif 'metrics' in path:
        response = metrics_table.scan(Select='COUNT')
        attack_count = response.get('Count', 0)
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({'total_attacks': attack_count}),
        }

    return {
        'statusCode': 404,
        'headers': cors_headers,
        'body': json.dumps({'message': 'Endpoint not found'}),
    }
