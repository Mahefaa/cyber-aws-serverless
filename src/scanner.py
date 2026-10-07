import boto3
import json
import gzip

s3_client = boto3.client('s3')
ses_client = boto3.client('ses', region_name='us-east-1')

def handler(event, context):
    print("SecOps Scanner: Parsing newly delivered CloudTrail log...")
    
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        # Fetch and parse log
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = gzip.decompress(response['Body'].read())
        logs = json.loads(content)
        
        for event in logs.get('Records', []):
            # Detect IAM Policy Changes (Privilege Escalation attempt)
            if event['eventName'] == 'PutUserPolicy':
                alert_admin(event['userIdentity']['arn'], event['requestParameters'])

    return {"status": "success"}

def alert_admin(user, details):
    print(f"CRITICAL: IAM Policy altered by {user}. Sending SES Alert.")
    # ses_client.send_email(...) implementation here
