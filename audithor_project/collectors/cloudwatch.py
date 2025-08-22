# collectors/cloudwatch.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_cloudwatch_data(session):
    """
    Collects CloudWatch alarms and SNS topics from all available AWS regions.

    This function iterates through every AWS region accessible by the provided
    credentials. For each region, it retrieves all CloudWatch metric alarms and
    all SNS topics that have confirmed email subscriptions. It gracefully skips
    regions that are not enabled for the account.

    Args:
        session (boto3.Session): The main Boto3 session object used to
                                 derive credentials and discover regions.

    Returns:
        dict: A dictionary with two keys:
              - 'alarms': A list of CloudWatch alarm configuration dictionaries.
              - 'topics': A list of SNS topics that have email subscriptions.

    Example:
        >>> import boto3
        >>>
        >>> # This assumes 'get_all_aws_regions' is an available function
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> all_data = collect_cloudwatch_data(aws_session)
        >>> print(f"Found {len(all_data['alarms'])} alarms across all regions.")
        >>> print(f"Found {len(all_data['topics'])} topics with email subs.")
    """
    all_regions = get_all_aws_regions(session)
    result_alarms = []
    result_topics = []

    for region in all_regions:
        try:
            # Create a new session for each specific region
            session_regional = boto3.Session(
                aws_access_key_id=session.get_credentials().access_key,
                aws_secret_access_key=session.get_credentials().secret_key,
                aws_session_token=session.get_credentials().token,
                region_name=region
            )
            cw_client = session_regional.client("cloudwatch")
            sns_client = session_regional.client("sns")

            # 1. Collect CloudWatch Alarms
            try:
                paginator_alarms = cw_client.get_paginator('describe_alarms')
                for page in paginator_alarms.paginate():
                    for alarm in page.get('MetricAlarms', []):
                        alarm['Region'] = region
                        result_alarms.append(alarm)
            except ClientError as e:
                if "OptInRequired" in str(e):
                    continue # Skip regions that are not enabled

            # 2. Collect SNS Topics and their email subscriptions
            try:
                paginator_topics = sns_client.get_paginator('list_topics')
                all_topics_in_region = []
                for page in paginator_topics.paginate():
                    all_topics_in_region.extend(page.get("Topics", []))

                for topic in all_topics_in_region:
                    topic_arn = topic['TopicArn']
                    subscriptions = []
                    try:
                        paginator_subs = sns_client.get_paginator('list_subscriptions_by_topic')
                        for page in paginator_subs.paginate(TopicArn=topic_arn):
                            for sub in page.get("Subscriptions", []):
                                is_email = sub.get("Protocol") in ["email", "email-json"]
                                is_confirmed = sub.get("SubscriptionArn") != "PendingConfirmation"
                                if is_email and is_confirmed:
                                    subscriptions.append({
                                        "Endpoint": sub.get("Endpoint"),
                                        "Protocol": sub.get("Protocol")
                                    })
                    except ClientError:
                        # Ignore errors for specific topics (e.g., permissions) and continue
                        pass
                    
                    if subscriptions:
                        result_topics.append({
                            "TopicArn": topic_arn,
                            "Region": region,
                            "Subscriptions": subscriptions
                        })
            except ClientError as e:
                if "OptInRequired" in str(e):
                    continue # Skip regions that are not enabled

        except ClientError as e:
            # Catch broader errors for regions that cannot be accessed
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e):
                continue

    return {"alarms": result_alarms, "topics": result_topics}

def get_log_group_destinations(session, log_group_arn):
    """
    Inspects a CloudWatch Log Group and finds all its destinations, including
    Subscription Filters and Metric Filters with their associated Alarms.
    """
    destinations = {
        "subscriptions": [],
        "metric_filters": []
    }
    try:
        log_region = log_group_arn.split(':')[3]
        log_group_name = log_group_arn.split(':')[6]
        logs_client = session.client("logs", region_name=log_region)
        cw_client = session.client("cloudwatch", region_name=log_region)

        # 1. Get Subscription Filters (existing logic)
        subs = logs_client.describe_subscription_filters(logGroupName=log_group_name)
        for sub in subs.get('subscriptionFilters', []):
            dest_arn = sub.get('destinationArn', '')
            service_type = "Unknown"
            if "lambda" in dest_arn: service_type = "Lambda"
            elif "kinesis" in dest_arn: service_type = "Kinesis"
            elif "firehose" in dest_arn: service_type = "Firehose"
            elif "opensearch" in dest_arn: service_type = "OpenSearch"
            destinations["subscriptions"].append({"Type": service_type, "Target": dest_arn})

        # 2. Get Metric Filters and their Alarms
        metric_filters = logs_client.describe_metric_filters(logGroupName=log_group_name)
        for mf in metric_filters.get('metricFilters', []):
            mf_data = {
                "FilterName": mf.get('filterName'),
                "MetricName": mf.get('metricTransformations', [{}])[0].get('metricName'),
                "Namespace": mf.get('metricTransformations', [{}])[0].get('metricNamespace'),
                "Alarms": []
            }
            # Check for alarms associated with this metric
            if mf_data["MetricName"] and mf_data["Namespace"]:
                alarms = cw_client.describe_alarms_for_metric(
                    MetricName=mf_data["MetricName"],
                    Namespace=mf_data["Namespace"]
                )
                for alarm in alarms.get('MetricAlarms', []):
                    mf_data["Alarms"].append(alarm.get('AlarmName'))
            
            destinations["metric_filters"].append(mf_data)

    except (ClientError, IndexError):
        # If anything fails (permissions, parsing), return what we have
        pass
        
    return destinations