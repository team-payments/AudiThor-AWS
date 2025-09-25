# collectors/utils.py
import boto3
from botocore.exceptions import ClientError

def get_session(data):
    try:
        access_key = data.get('access_key')
        secret_key = data.get('secret_key')
        session_token = data.get('session_token')
        if not access_key or not secret_key:
            return None, "Access Key or Secret Key not provided."
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        sts = session.client("sts")
        sts.get_caller_identity()
        return session, None
    except Exception as e:
        return None, f"Error validating AWS credentials: {str(e)}"
    
def get_all_aws_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [region['RegionName'] for region in ec2.describe_regions()['Regions']]