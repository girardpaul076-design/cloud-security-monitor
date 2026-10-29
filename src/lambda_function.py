import json
import boto3
import os

s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    bucket_name = event['detail']['requestParameters']['bucketName']
    print(f"ALERT: Public S3 bucket configuration detected on bucket: {bucket_name}")

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(f"REMEDIATION: Bucket {bucket_name} has been secured and locked down to Private.")

    sns_arn = os.environ['SNS_TOPIC_ARN']
    sns.publish(
        TopicArn=sns_arn,
        Message=f"SECURITY ALERT: Public access configuration was detected on bucket '{bucket_name}'. The automated compliance engine has forcefully locked the bucket down to Private successfully.",
        Subject="CRITICAL: S3 Security Remediation Triggered"
    )
    return {'statusCode': 200, 'body': json.dumps('Security Remediation Complete')}
