import boto3

# Initialize the S3 client
s3 = boto3.client('s3', region_name='us-east-2')

# Replace this string with your actual fresh target victim bucket name from your SAM deploy output
TARGET_BUCKET = "siem-simulation-victim-YOUR-ACCOUNT-ID-us-east-2"

print(f"🚀 Initializing Intrusion Simulation on target: {TARGET_BUCKET}...")

try:
    # Intentionally flipping ACL to public exposure to activate the monitoring loops
    s3.put_bucket_acl(
        Bucket= "siem-test-bucket-paul",
        ACL='public-read'
    )
    print("🔥 Vulnerability Exploited! ACL changed to public-read.")
    print("⏳ Awaiting AWS EventBridge threat capture loop to trigger remediation...")
except Exception as e:
    print(f"❌ Attack simulation canceled: {e}")
