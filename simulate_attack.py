This script is syntactically correct and uses an **atomic counter pattern** (`ADD attack_count :val`), which is much faster and more cost-effective than scanning the whole table!

Just like the previous snippet, it contains non-breaking spaces in the indentation that will cause a Python `IndentationError` if copy-pasted directly.

Here is the cleaned-up version with standard spacing ready to use:

```python
import json
import boto3
import os

# Initialize the DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('SiemMetricsTable')

def lambda_handler(event, context):
    # 1. Catch the attack simulation event from EventBridge
    if event.get("detail-type") == "AWS API Call via CloudTrail":
        try:
            table.update_item(
                Key={'metric_id': 'total_attacks'},
                UpdateExpression="ADD attack_count :val",
                ExpressionAttributeValues={':val': 1}
            )
            print("Security remediation triggered! Counter incremented.")
        except Exception as e:
            print(f"Database error tracking attack: {str(e)}")
        return {"statusCode": 200, "body": "Security Alert Processed"}

    # 2. Handle the frontend resume webpage request (API Gateway call)
    try:
        db_query = table.get_item(Key={'metric_id': 'total_attacks'})
        attack_count = db_query.get('Item', {}).get('attack_count', 0)
    except Exception as e:
        print(f"Database error reading metrics: {str(e)}")
        attack_count = 0

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "Content-Type"
        },
        "body": json.dumps({
            "total_attacks": int(attack_count)
        })
    }

```
