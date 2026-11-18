import json
import os
import hashlib
import boto3

dynamodb = boto3.resource('dynamodb')

VISITOR_TABLE = os.environ.get('VISITOR_TABLE', 'VisitorTable')
METRICS_TABLE = os.environ.get('METRICS_TABLE', 'MetricsTable')
IP_SALT = os.environ.get('IP_HASH_SALT', 'fallback-dev-salt-12345')

MALICIOUS_AGENTS = ['sqlmap', 'nikto', 'gobuster', 'nmap', 'masscan', 'curl', 'python-requests']

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
    }

    request_context = event.get('requestContext', {})
    http_info = request_context.get('http', {})
    if http_info.get('method') == 'OPTIONS':
        return {"statusCode": 200, "headers": headers, "body": ""}

    try:
        headers_in = event.get('headers', {})
        client_ip = headers_in.get('x-forwarded-for', '0.0.0.0').split(',')[0].strip()
        user_agent = headers_in.get('user-agent', 'unknown')

        hasher = hashlib.sha256()
        hasher.update((client_ip + IP_SALT).encode('utf-8'))
        hashed_ip = hasher.hexdigest()

        is_suspicious = any(agent in user_agent.lower() for agent in MALICIOUS_AGENTS)
        
        if is_suspicious:
            print(f"SECURITY ALERT: Suspicious request detected from Hashed IP: {hashed_ip} using User-Agent: {user_agent}")
            metrics_table = dynamodb.Table(METRICS_TABLE)
            metrics_table.put_item(
                Item={
                    'id': f"threat-{hashed_ip}-{context.aws_request_id}",
                    'hashed_ip': hashed_ip,
                    'user_agent': user_agent,
                    'severity': 'MEDIUM'
                }
            )

        visitor_table = dynamodb.Table(VISITOR_TABLE)
        response = visitor_table.update_item(
            Key={'id': 'resume-visitor-count'},
            UpdateExpression="ADD visitor_count :inc",
            ExpressionAttributeValues={':inc': 1},
            ReturnValues="UPDATED_NEW"
        )
        
        current_count = int(response.get('Attributes', {}).get('visitor_count', 1))

        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({
                "message": "Telemetry processed successfully",
                "visitor_count": current_count,
                "security_flagged": is_suspicious
            })
        }

    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({"error": str(e)})
        }
