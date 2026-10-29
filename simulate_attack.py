import boto3
import time
import uuid

s3 = boto3.client('s3')
unique_id = str(uuid.uuid4())[:8]
test_bucket_name = f"security-test-bucket-{unique_id}"

print(f"[*] Starting Cloud Security Simulation...")
print(f"[*] Creating target test bucket: {test_bucket_name}")
s3.create_bucket(Bucket=test_bucket_name)

print(f"[!] ATTACK STAGE: Deliberately turning off Public Access Blocks...")
s3.put_public_access_block(
    Bucket=test_bucket_name,
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False
    }
)
print(f"[!] Exposure API called successfully. Waiting 15 seconds for remediation...")
time.sleep(15)

print(f"[*] VERIFICATION STAGE: Checking current Public Access Block status...")
try:
    response = s3.get_public_access_block(Bucket=test_bucket_name)
    config = response['PublicAccessBlockConfiguration']
    
    print("\n================ LIVE STATUS ================")
    print(f"BlockPublicAcls:       {config['BlockPublicAcls']}")
    print(f"IgnorePublicAcls:      {config['IgnorePublicAcls']}")
    print(f"BlockPublicPolicy:     {config['BlockPublicPolicy']}")
    print(f"RestrictPublicBuckets: {config['RestrictPublicBuckets']}")
    print("=============================================")

    if config['BlockPublicAcls'] == True:
        print("\n[+] SUCCESS: Engine intercepted the change and locked down the bucket!")
    else:
        print("\n[-] FAILURE: Bucket is still public. Check CloudWatch Logs.")
except Exception as e:
    print(f"[-] Error: {e}")

print(f"\n[*] Cleaning up test bucket...")
s3.delete_bucket(Bucket=test_bucket_name)
print("[*] Simulation complete.")
