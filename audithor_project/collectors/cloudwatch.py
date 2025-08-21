# collectors/cloudwatch.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_cloudwatch_data(session):
    all_regions = get_all_aws_regions(session)
    result_alarms, result_topics = [], []
    for region in all_regions:
        try:
            session_regional = boto3.Session(aws_access_key_id=session.get_credentials().access_key, aws_secret_access_key=session.get_credentials().secret_key, aws_session_token=session.get_credentials().token, region_name=region)
            cw_client, sns_client = session_regional.client("cloudwatch"), session_regional.client("sns")
            try:
                paginator_alarms = cw_client.get_paginator('describe_alarms')
                for page in paginator_alarms.paginate():
                    for alarm in page['MetricAlarms']: alarm['Region'] = region; result_alarms.append(alarm)
            except ClientError as e:
                if "OptInRequired" in str(e): continue
            try:
                paginator_topics, all_topics_in_region = sns_client.get_paginator('list_topics'), []
                for page in paginator_topics.paginate(): all_topics_in_region.extend(page.get("Topics", []))
                for topic in all_topics_in_region:
                    topic_arn, subscriptions = topic['TopicArn'], []
                    try:
                        paginator_subs = sns_client.get_paginator('list_subscriptions_by_topic')
                        for page in paginator_subs.paginate(TopicArn=topic_arn):
                            for sub in page.get("Subscriptions", []):
                                if sub.get("Protocol") in ["email", "email-json"] and sub.get("SubscriptionArn") != "PendingConfirmation":
                                    subscriptions.append({"Endpoint": sub.get("Endpoint"), "Protocol": sub.get("Protocol")})
                    except ClientError: pass
                    if subscriptions: result_topics.append({"TopicArn": topic_arn, "Region": region, "Subscriptions": subscriptions})
            except ClientError as e:
                if "OptInRequired" in str(e): continue
        except ClientError as e:
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e): continue
    return {"alarms": result_alarms, "topics": result_topics}

