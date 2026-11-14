import json
import boto3
import uuid
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

# Connect to both tables in your architecture
visitor_table = dynamodb.Table('cloud-resume-stats')
metrics_table = dynamodb.Table('SiemMetricsTable')

def lambda_handler(event, context):
    # --- ROUTE 0: EventBridge S3 Security Breach Handler ---
    if event.get('source') == 'aws.s3' or 'detail' in event:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        request_params = detail.get('requestParameters', {})
        bucket_name = request_params.get('bucketName')
        
        if event_name in ['PutBucketAcl', 'PutBucketPolicy'] and bucket_name:
            print(f"🚨 Security Alert: Unauthorized public modification ({event_name}) detected on bucket: {bucket_name}")
            
            # Remediate: Force bucket ACL back to private
            try:
                s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
                print(f"🛡️ Successfully remediated: Reverted bucket {bucket_name} ACL to private.")
            except Exception as e:
                print(f"❌ Failed to remediate bucket ACL: {e}")
            
            # Log incident to SiemMetricsTable so /metrics can track it
            try:
                incident_id = str(uuid.uuid4())
                metrics_table.put_item(
                    Item={
                        'id': incident_id,
                        'timestamp': str(datetime.utcnow()),
                        'eventName': event_name,
                        'bucketName': bucket_name,
                        'status': 'Remediated'
                    }
                )
            except Exception as e:
                print(f"❌ Failed to log metric to DynamoDB: {e}")
                
            return {'status': 'Remediated'}

    # --- ROUTE 1 & 2: HTTP API Gateway Requests ---
    path = event.get('rawPath', '') or event.get('requestContext', {}).get('http', {}).get('path', '')
    
    headers = {
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'OPTIONS,GET'
    }
    
    # --- ROUTE 1: Visitor Counter ---
    if 'visitor' in path:
        response = visitor_table.update_item(
            Key={'id': 'visitors'},
            UpdateExpression='ADD #c :val',
            ExpressionAttributeNames={'#c': 'count'},
            ExpressionAttributeValues={':val': 1},
            ReturnValues='UPDATED_NEW'
        )
        views = int(response['Attributes']['count'])
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'count': views})
        }
        
    # --- ROUTE 2: SIEM Attack Metrics Tracker ---
    elif 'metrics' in path:
        response = metrics_table.scan(Select='COUNT')
        attack_count = response.get('Count', 0)
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'total_attacks': attack_count})
        }
        
    return {
        'statusCode': 404,
        'headers': headers,
        'body': json.dumps({'message': 'Endpoint not found'})
    }
    }

```
