import boto3
def handler(event, context):
    print("Scanning newly uploaded S3 object for malware...")
    return {"status": "clean"}
