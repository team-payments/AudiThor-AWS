# collectors/cloudtrail.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import pytz
from .utils import get_all_aws_regions # Importación relativa


def collect_cloudtrail_data(session: boto3.Session):
    """
    Collects AWS CloudTrail configurations and recent sensitive events.

    This function operates in two stages. First, it discovers all unique
    CloudTrail trails across all regions and gathers their configuration details.
    Second, it searches for a predefined list of sensitive API events
    (e.g., ConsoleLogin, CreateUser) that occurred within the last 7 days.

    Args:
        session: A Boto3 session instance used to create AWS clients.

    Returns:
        A dictionary with two keys:
        - 'trails': A list of dictionaries, each detailing a CloudTrail configuration.
        - 'events': A list of dictionaries, each representing a sensitive event,
                    sorted from most to least recent.

    Example:
        >>> import boto3
        >>> aws_session = boto3.Session()
        >>> cloudtrail_data = collect_cloudtrail_data(aws_session)
    """
    regions = get_all_aws_regions(session)
    result_trails = []
    result_events = []
    processed_trail_arns = set()

    # Part 1: Collect details for all unique CloudTrail trails.
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for trail in client.describe_trails().get('trailList', []):
                trail_arn = trail.get("TrailARN")
                
                # Use a set to ensure multi-region trails are processed only once.
                if trail_arn not in processed_trail_arns:
                    try:
                        trail_status = client.get_trail_status(Name=trail_arn)
                        result_trails.append({
                            "Name": trail.get("Name"),
                            "HomeRegion": trail.get("HomeRegion"),
                            "S3BucketName": trail.get("S3BucketName"),
                            "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                            "IsOrganizationTrail": trail.get("IsOrganizationTrail", False),
                            "IsLogging": trail_status.get("IsLogging", False),
                            "KmsKeyId": trail.get("KmsKeyId"),
                            "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
                            "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"),
                            "TrailARN": trail_arn
                        })
                        processed_trail_arns.add(trail_arn)
                    except ClientError:
                        # Could not get trail status, but continue processing others.
                        continue
        except ClientError:
            # Could not connect to the region, so skip it.
            continue

    # Part 2: Look up recent, sensitive events across all regions.
    eventos_a_buscar = [
        "ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging",
        "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
        "StartInstances", "StopInstances", "TerminateInstances",
        "DisableKey", "ScheduleKeyDeletion"
    ]
    
    # Define the time window for the event search (last 7 days).
    end_time = datetime.now(pytz.utc)
    start_time = end_time - timedelta(days=7)

    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for event_name in eventos_a_buscar:
                paginator = client.get_paginator('lookup_events')
                page_iterator = paginator.paginate(
                    LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                    StartTime=start_time,
                    EndTime=end_time
                )
                for page in page_iterator:
                    for event in page.get('Events', []):
                        # The 'CloudTrailEvent' field is a JSON string that needs parsing.
                        cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        result_events.append({
                            "EventName": event.get("EventName"),
                            "EventTime": str(event.get("EventTime")),
                            "Username": event.get("Username", "N/A"),
                            "EventRegion": cloudtrail_event_data.get("awsRegion", region),
                            "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"),
                            "RequestParameters": cloudtrail_event_data.get("requestParameters", {})
                        })
        except ClientError:
            # Could not look up events in this region, so skip it.
            continue

    # Sort all found events from most to least recent.
    result_events.sort(key=lambda x: x['EventTime'], reverse=True)
    
    return {"trails": result_trails, "events": result_events}


def lookup_cloudtrail_events(session, region, event_name, start_time, end_time):
    """
    Searches AWS CloudTrail for specific events within a given time frame and region.

    This function uses a paginator to efficiently retrieve all matching events, 
    parses the relevant data from each event, and returns them in a structured format.

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
        >>> print(found_events)
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


def run_trailguard_analysis(session, region):
    """
    Searches for suspicious activities in CloudTrail based on TrailGuard's rules.

    Args:
        session (boto3.Session): The Boto3 session for AWS credentials.
        region (str): The specific AWS region to scan.

    Returns:
        dict: A dictionary where keys are the names of the TrailGuard rules
              and values are lists of the events found for each rule.
    """
    client = session.client("cloudtrail", region_name=region)
    end_time = datetime.now(pytz.utc)
    start_time = end_time - timedelta(days=7)
    
    # Definimos las reglas de búsqueda inspiradas en TrailGuard
    trailguard_rules = {
        "IAM User/Role/Group Created": ["CreateUser", "CreateRole", "CreateGroup"],
        "IAM User/Role/Group Deleted": ["DeleteUser", "DeleteRole", "DeleteGroup"],
        "IAM Policy Changed": ["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "DetachUserPolicy", "DetachRolePolicy", "DetachGroupPolicy"],
        "CloudTrail Disabled or Tampered": ["StopLogging", "DeleteTrail", "UpdateTrail"],
        "Security Group Tampered": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress"],
        "Network ACL Tampered": ["CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry"],
        "VPC Changes": ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute"],
        "Root Login": ["ConsoleLogin"], # Se filtrará por usuario "root" más adelante
    }

    findings = {}

    for rule_name, event_names in trailguard_rules.items():
        found_events_for_rule = []
        for event_name in event_names:
            try:
                paginator = client.get_paginator('lookup_events')
                page_iterator = paginator.paginate(
                    LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                    StartTime=start_time,
                    EndTime=end_time
                )
                for page in page_iterator:
                    for event in page.get('Events', []):
                        # Caso especial para el login de root
                        if event_name == "ConsoleLogin":
                            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                            if event_data.get("userIdentity", {}).get("type") != "Root":
                                continue # Ignoramos logins que no sean de root
                        
                        found_events_for_rule.append({
                            "EventName": event.get("EventName"),
                            "EventTime": str(event.get("EventTime")),
                            "Username": event.get("Username", "N/A"),
                            "SourceIPAddress": json.loads(event.get('CloudTrailEvent', '{}')).get("sourceIPAddress", "N/A"),
                            "CloudTrailEvent": event.get('CloudTrailEvent', '{}') # Guardamos el evento completo para detalles
                        })
            except ClientError as e:
                print(f"Skipping event {event_name} in {region} due to error: {e}")
                continue
        
        if found_events_for_rule:
            # Ordenamos los eventos por fecha, del más reciente al más antiguo
            found_events_for_rule.sort(key=lambda x: x['EventTime'], reverse=True)
            findings[rule_name] = found_events_for_rule
            
    return findings