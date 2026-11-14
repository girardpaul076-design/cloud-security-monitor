import boto3

s3 = boto3.client('s3', region_name='us-east-2')

# Replace with your TargetVictimBucket from CloudFormation / SAM outputs
TARGET_BUCKET = 'siem-simulation-victim-YOUR-ACCOUNT-ID-us-east-2'

print(f'🚀 Initializing Intrusion Simulation on target: {TARGET_BUCKET}...')

try:
  s3.put_bucket_acl(Bucket=TARGET_BUCKET, ACL='public-read')
  print('🔥 Vulnerability Exploited! ACL changed to public-read.')
  print(
      '⏳ Awaiting AWS EventBridge threat capture loop to trigger'
      ' remediation...'
  )
except Exception as e:
  print(f'❌ Attack simulation canceled: {e}')
