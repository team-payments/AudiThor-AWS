# collectors/cloudtrail.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import pytz
from .utils import get_all_aws_regions # Importación relativa
from .cloudwatch import get_log_group_destinations


def collect_cloudtrail_data(session: boto3.Session):
    """
    Collects CloudTrail data, including trail configurations and recent events.

    This function performs three main tasks:
    1. Describes all CloudTrail trails in the account, correctly handling
       multi-region trails to avoid duplicates.
    2. Searches for a specific list of security-sensitive API calls across all
       regions from the last 7 days.
    3. Runs a separate analysis function ('run_trailguard_analysis') on the
       collected trail configurations to check for potential issues.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing 'trails', 'events', and 'trailguard_findings'.

    Example:
        >>> import boto3
        >>>
        >>> # Assumes helper functions are available
        >>> aws_session = boto3.Session()
        >>> trail_data = collect_cloudtrail_data(aws_session)
        >>> print(f"Found {len(trail_data['trails'])} CloudTrail trails.")
    """
    regions = get_all_aws_regions(session)
    result_trails = []
    result_events = []
    processed_trail_arns = set()

    # --- 1. Collect Trail Configurations ---
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            # describe_trails in any region can return multi-region trails
            for trail in client.describe_trails().get('trailList', []):
                trail_arn = trail.get("TrailARN")
                if trail_arn not in processed_trail_arns:
                    try:
                        status = client.get_trail_status(Name=trail_arn)
                        result_trails.append({
                            "Name": trail.get("Name"),
                            "HomeRegion": trail.get("HomeRegion"),
                            "S3BucketName": trail.get("S3BucketName"),
                            "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                            "IsOrganizationTrail": trail.get("IsOrganizationTrail", False),
                            "IsLogging": status.get("IsLogging", False),
                            "KmsKeyId": trail.get("KmsKeyId"),
                            "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
                            "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"),
                            "TrailARN": trail_arn
                        })
                        processed_trail_arns.add(trail_arn)
                    except ClientError:
                        continue # Failed to get status, but continue processing other trails
        except ClientError:
            continue # Failed to describe trails in region, continue to next region

    # --- 2. Search for Notable Events (Last 7 Days) ---
    events_to_search = [
        "ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging",
        "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
        "StartInstances", "StopInstances", "TerminateInstances",
        "DisableKey", "ScheduleKeyDeletion"
    ]
    
    end_time = datetime.now(pytz.utc)
    start_time = end_time - timedelta(days=7)

    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for event_name in events_to_search:
                paginator = client.get_paginator('lookup_events')
                page_iterator = paginator.paginate(
                    LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                    StartTime=start_time,
                    EndTime=end_time
                )
                for page in page_iterator:
                    for event in page.get('Events', []):
                        event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        result_events.append({
                            "EventName": event.get("EventName"),
                            "EventTime": str(event.get("EventTime")),
                            "Username": event.get("Username", "N/A"),
                            "EventRegion": event_data.get("awsRegion", region),
                            "SourceIPAddress": event_data.get("sourceIPAddress", "N/A"),
                            "RequestParameters": event_data.get("requestParameters", {})
                        })
        except ClientError:
            continue # Failed to look up events in this region

    # Sort events from most recent to oldest
    result_events.sort(key=lambda x: x['EventTime'], reverse=True)
    
    # --- 3. Run Configuration Analysis ---
    trailguard_findings = run_trailguard_analysis(session, result_trails)
    
    return {
        "trails": result_trails,
        "events": result_events,
        "trailguard_findings": trailguard_findings
    }

def lookup_cloudtrail_events(session, region, event_name, start_time, end_time):
    """
    Searches AWS CloudTrail for specific events within a given time frame and region.

    This function uses a paginator to efficiently retrieve all matching events,
    parses the relevant data from each event, and returns them in a structured format,
    sorted from most recent to oldest.

    Args:
        session (boto3.Session): The Boto3 session object for AWS credentials.
        region (str): The AWS region to perform the search in.
        event_name (str): The name of the event to look for (e.g., 'ConsoleLogin').
        start_time (datetime): The start of the time window for the search.
        end_time (datetime): The end of the time window for the search.

    Returns:
        dict: A dictionary containing a list of found CloudTrail events, sorted
              by time in descending order. Returns {"events": []} if none are found.

    Raises:
        Exception: If there is an API error when communicating with the CloudTrail service.

    Example:
        >>> import boto3
        >>> from datetime import datetime, timedelta
        >>>
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> end_timestamp = datetime.utcnow()
        >>> start_timestamp = end_timestamp - timedelta(days=1)
        >>>
        >>> found_events = lookup_cloudtrail_events(
        ...     session=aws_session,
        ...     region='us-east-1',
        ...     event_name='ConsoleLogin',
        ...     start_time=start_timestamp,
        ...     end_time=end_timestamp
        ... )
    """
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
        # Raise a generic exception so the calling endpoint can catch it and return a clear error.
        raise Exception(f"Error searching for CloudTrail events in region {region}: {str(e)}")

    # Sort events from most recent to oldest before returning
    found_events.sort(key=lambda x: x['EventTime'], reverse=True)
    
    return {"events": found_events}

def run_trailguard_analysis(session, trails_list):
    all_trails_flow = []
    for trail in trails_list:
        region = trail.get("HomeRegion")
        if not region:
            continue

        flow_data = {
            "TrailName": trail.get("Name"),
            "TrailArn": trail.get("TrailARN"),
            "Region": region,
            "S3Destination": None,
            "CloudWatchDestination": None
        }

        if trail.get("S3BucketName"):
            bucket_name = trail["S3BucketName"]
            s3_dest = {"BucketName": bucket_name, "Notifications": []}
            try:
                s3_client = session.client("s3", region_name=region)
                notif_config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                for config in notif_config.get('LambdaFunctionConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "Lambda", "Target": config.get('LambdaFunctionArn')})
                for config in notif_config.get('QueueConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "SQS", "Target": config.get('QueueArn')})
                for config in notif_config.get('TopicConfigurations', []):
                    s3_dest["Notifications"].append({"Type": "SNS", "Target": config.get('TopicArn')})
            except ClientError:
                pass
            flow_data["S3Destination"] = s3_dest

        if trail.get("CloudWatchLogsLogGroupArn"):
            log_group_arn = trail["CloudWatchLogsLogGroupArn"]
            log_group_name = log_group_arn.split(':')[6]
            
            # --- LÓGICA MODIFICADA ---
            # Llamamos a la nueva función centralizada para obtener TODOS los destinos
            destinations = get_log_group_destinations(session, log_group_arn)
            
            cw_dest = {
                "LogGroupName": log_group_name,
                "Subscriptions": destinations.get("subscriptions", []),
                "MetricFilters": destinations.get("metric_filters", []) # Añadimos los filtros de métricas
            }
            flow_data["CloudWatchDestination"] = cw_dest
        
        all_trails_flow.append(flow_data)
            
    return all_trails_flow