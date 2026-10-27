# cloud-security-monitor
 Type: Automated cloud security compliance engine that detects public S3 buckets via CloudTrail and remediates security vulnerabilities using serverless Python Lambda functions.
[Vulnerability Event] 
An S3 bucket is changed to Public -> Triggers AWS CloudTrail
      │
      ▼
[Detection Layer]
Amazon EventBridge matches the specific "PutBucketAcl" security event
      │
      ▼
[Remediation Engine]
AWS Lambda runs a Python script -> Changes the bucket back to 100% Private
      │
      ▼
[Alerting System]
Amazon SNS fires a text/email alert -> Notifies you of the threat layout
