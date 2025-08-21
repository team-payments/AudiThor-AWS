# collectors/cloudtrail.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import pytz
from .utils import get_all_aws_regions # Importación relativa


def collect_cloudtrail_data(session):
    regions = get_all_aws_regions(session)
    result_trails, result_events, processed_trail_arns = [], [], set()
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for trail in client.describe_trails().get('trailList', []):
                trail_arn = trail.get("TrailARN")
                if trail_arn not in processed_trail_arns:
                    try:
                        trail_status = client.get_trail_status(Name=trail_arn)
                        result_trails.append({ "Name": trail.get("Name"), "HomeRegion": trail.get("HomeRegion"), "S3BucketName": trail.get("S3BucketName"), "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False), "IsOrganizationTrail": trail.get("IsOrganizationTrail", False), "IsLogging": trail_status.get("IsLogging", False), "KmsKeyId": trail.get("KmsKeyId"), "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False), "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"), "TrailARN": trail_arn })
                        processed_trail_arns.add(trail_arn)
                    except ClientError: continue 
        except ClientError: continue
    eventos_a_buscar = [ "ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging", "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "StartInstances", "StopInstances", "TerminateInstances", "DisableKey", "ScheduleKeyDeletion" ]
    end_time, start_time = datetime.now(pytz.utc), datetime.now(pytz.utc) - timedelta(days=7)
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for event_name in eventos_a_buscar:
                paginator = client.get_paginator('lookup_events')
                for page in paginator.paginate(LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}], StartTime=start_time, EndTime=end_time):
                    for event in page.get('Events', []):
                        cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        result_events.append({ "EventName": event.get("EventName"), "EventTime": str(event.get("EventTime")), "Username": event.get("Username", "N/A"), "EventRegion": cloudtrail_event_data.get("awsRegion", region), "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"), "RequestParameters": cloudtrail_event_data.get("requestParameters", {}) })
        except ClientError: continue
    result_events.sort(key=lambda x: x['EventTime'], reverse=True)
    return {"trails": result_trails, "events": result_events}

def lookup_cloudtrail_events(session, region, event_name, start_time, end_time):
    found_events = []
    try:
        client = session.client("cloudtrail", region_name=region)
        paginator = client.get_paginator('lookup_events')
        
        lookup_attributes = []
        if event_name:
            lookup_attributes.append({'AttributeKey': 'EventName', 'AttributeValue': event_name})

        pages = paginator.paginate(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time
        )

        for page in pages:
            for event in page.get('Events', []):
                cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                found_events.append({
                    "EventId": event.get("EventId"),
                    "CloudTrailEvent": event.get('CloudTrailEvent', '{}'),
                    "EventName": event.get("EventName"),
                    "EventTime": str(event.get("EventTime")),
                    "Username": event.get("Username", "N/A"),
                    "EventRegion": cloudtrail_event_data.get("awsRegion", region),
                    "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"),
                    "RequestParameters": cloudtrail_event_data.get("requestParameters", {})
                })
    except ClientError as e:
        # Lanza una excepción para que el endpoint la capture y devuelva un error claro.
        raise Exception(f"Error searching for CloudTrail events in the region {region}: {str(e)}")

    found_events.sort(key=lambda x: x['EventTime'], reverse=True)
    return {"events": found_events}

