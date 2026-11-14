import boto3

# Initialize clients
sts = boto3.client('sts')
s3 = boto3.client('s3')

# Dynamically fetch current Account ID and Region
account_id = sts.get_caller_identity()['Account']
region = s3.meta.region_name or 'us-east-2'

# Construct the exact TargetVictimBucket name matching your CloudFormation template
TARGET_BUCKET = f'siem-simulation-victim-{account_id}-{region}'

print(f'🚀 Initializing Intrusion Simulation on target: {TARGET_BUCKET}...')

try:
    s3.put_bucket_acl(Bucket=TARGET_BUCKET, ACL='public-read')
    print('🔥 Vulnerability Exploited! ACL changed to public-read.')
    print('⏳ Awaiting AWS EventBridge threat capture loop to trigger remediation...')
except Exception as e:
    print(f'❌ Attack simulation canceled: {e}')
