import json
import os

def lambda_handler(event, context):
    print("Security Monitor Event Received:", json.dumps(event))
    ip_hash_salt = os.environ.get("IP_HASH_SALT", "default-salt")
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Security monitor processed successfully",
            "status": "active"
        })
    }
    
