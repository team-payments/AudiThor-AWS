# collectors/waf.py
import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from .utils import get_all_aws_regions # Importación relativa


def parse_resource_arn(arn):
    """
    Parses an AWS ARN string to extract a simplified, human-readable resource identifier.

    This function is designed to handle different ARN formats, with special logic
    for complex ones like Elastic Load Balancers and API Gateway REST APIs to 
    provide more context than just the final ID. For all other ARNs, it defaults
    to returning the last component of the resource path.

    Args:
        arn (str): The full AWS ARN string to be parsed.

    Returns:
        str: The simplified resource name/ID, or the original ARN string if
             parsing fails due to an unexpected format.
    """
    try:
        parts = arn.split(':')
        resource_part = parts[5]
        if 'loadbalancer' in resource_part:
            lb_parts = resource_part.split('/')
            if len(lb_parts) > 2:
                return f"{lb_parts[0]}/{lb_parts[1]}/{lb_parts[2]}"
        if 'restapis' in resource_part:
            api_parts = resource_part.split('/')
            if len(api_parts) > 2:
                return f"{api_parts[1]}/{api_parts[2]}"
        return resource_part.split('/')[-1]
    except Exception:
        return arn


def collect_waf_data(session):
    """
    Collects data on AWS WAFv2 Web ACLs and IP Sets, including CloudWatch metrics for top rules.

    This function handles the dual-scope nature of WAFv2 by first querying for
    global resources (Scope='CLOUDFRONT') in us-east-1, and then iterating
    through all other regions for regional resources (Scope='REGIONAL').
    It gathers details for Web ACLs (logging, visibility) and IP Sets.
    
    For each Web ACL, it also queries CloudWatch for the 'BlockedRequests' metric
    over the last 3 days to identify the most triggered rules.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing two keys:
              - 'acls': A list of all Web ACLs, each including a 'TopRules' key 
                        with metric data if available.
              - 'ip_sets': A list of all IP Sets, global and regional.
    """
    all_acls = []
    all_ip_sets = []
    regions = get_all_aws_regions(session)

    # --- 1. Collect CloudFront (Global) Web ACLs ---
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_web_acls(Scope="CLOUDFRONT")
        for acl_summary in response.get("WebACLs", []):
            acl_details = client_global.get_web_acl(
                Name=acl_summary["Name"],
                Scope="CLOUDFRONT",
                Id=acl_summary["Id"]
            ).get("WebACL", {})

            resources_raw = client_global.list_resources_for_web_acl(
                WebACLArn=acl_summary["ARN"]
            ).get("ResourceArns", [])
            
            # --- NEW: Collect CloudWatch metrics for the ACL ---
            top_rules = []
            try:
                cloudwatch_client = session.client('cloudwatch', region_name="us-east-1")
                metric_response = cloudwatch_client.get_metric_data(
                    MetricDataQueries=[{
                        'Id': 'blocked_requests_by_rule',
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/WAFV2',
                                'MetricName': 'BlockedRequests',
                                'Dimensions': [
                                    {'Name': 'WebACL', 'Value': acl_summary["Name"]},
                                    {'Name': 'Rule', 'Value': 'ALL'}
                                ]
                            },
                            'Period': 2592000,  # 3 days in seconds
                            'Stat': 'Sum',
                        },
                        'ReturnData': True,
                    }],
                    StartTime=datetime.utcnow() - timedelta(days=30),
                    EndTime=datetime.utcnow()
                )
                if metric_response.get('MetricDataResults'):
                    for result in metric_response['MetricDataResults']:
                        rule_name = result['Label']
                        total_blocked = sum(result['Values'])
                        if total_blocked > 0:
                            top_rules.append({"RuleName": rule_name, "BlockedRequests": int(total_blocked)})
            except ClientError:
                pass # Fails silently if metrics are not available
            # --- END of new metric collection ---

            all_acls.append({
                "Name": acl_summary["Name"],
                "ARN": acl_summary["ARN"],
                "Id": acl_summary["Id"],
                "Scope": "CLOUDFRONT",
                "Region": "Global",
                "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw],
                "LoggingConfiguration": acl_details.get("LoggingConfiguration", {}),
                "VisibilityConfig": acl_details.get("VisibilityConfig", {}),
                "TopRules": sorted(top_rules, key=lambda x: x['BlockedRequests'], reverse=True)
            })
    except ClientError:
        pass

    # --- 2. Collect Regional Web ACLs ---
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_web_acls(Scope="REGIONAL")
            for acl_summary in response.get("WebACLs", []):
                acl_details = client_regional.get_web_acl(
                    Name=acl_summary["Name"],
                    Scope="REGIONAL",
                    Id=acl_summary["Id"]
                ).get("WebACL", {})

                resources_raw = client_regional.list_resources_for_web_acl(
                    WebACLArn=acl_summary["ARN"]
                ).get("ResourceArns", [])

                # --- NEW: Collect CloudWatch metrics for the ACL ---
                top_rules = []
                try:
                    cloudwatch_client = session.client('cloudwatch', region_name=region)
                    metric_response = cloudwatch_client.get_metric_data(
                        MetricDataQueries=[{
                            'Id': 'blocked_requests_by_rule',
                            'MetricStat': {
                                'Metric': {
                                    'Namespace': 'AWS/WAFV2',
                                    'MetricName': 'BlockedRequests',
                                    'Dimensions': [
                                        {'Name': 'WebACL', 'Value': acl_summary["Name"]},
                                        {'Name': 'Rule', 'Value': 'ALL'}
                                    ]
                                },
                                'Period': 259200, # 3 days in seconds
                                'Stat': 'Sum',
                            },
                            'ReturnData': True,
                        }],
                        StartTime=datetime.utcnow() - timedelta(days=3),
                        EndTime=datetime.utcnow()
                    )
                    if metric_response.get('MetricDataResults'):
                        for result in metric_response['MetricDataResults']:
                            rule_name = result['Label']
                            total_blocked = sum(result['Values'])
                            if total_blocked > 0:
                                top_rules.append({"RuleName": rule_name, "BlockedRequests": int(total_blocked)})
                except ClientError:
                    pass # Fails silently if metrics are not available
                # --- END of new metric collection ---

                all_acls.append({
                    "Name": acl_summary["Name"],
                    "ARN": acl_summary["ARN"],
                    "Id": acl_summary["Id"],
                    "Scope": "REGIONAL",
                    "Region": region,
                    "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw],
                    "LoggingConfiguration": acl_details.get("LoggingConfiguration", {}),
                    "VisibilityConfig": acl_details.get("VisibilityConfig", {}),
                    "TopRules": sorted(top_rules, key=lambda x: x['BlockedRequests'], reverse=True)
                })
        except ClientError:
            pass

    # --- 3. Collect CloudFront (Global) IP Sets ---
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_ip_sets(Scope="CLOUDFRONT")
        for ip_set_summary in response.get("IPSets", []):
            details = client_global.get_ip_set(
                Name=ip_set_summary["Name"],
                Scope="CLOUDFRONT",
                Id=ip_set_summary["Id"]
            )
            ip_set = details["IPSet"]
            all_ip_sets.append({
                "Name": ip_set["Name"],
                "ARN": ip_set["ARN"],
                "Scope": "CLOUDFRONT",
                "Region": "Global",
                "IPAddressVersion": ip_set["IPAddressVersion"],
                "AddressCount": len(ip_set["Addresses"])
            })
    except ClientError:
        pass

    # --- 4. Collect Regional IP Sets ---
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_ip_sets(Scope="REGIONAL")
            for ip_set_summary in response.get("IPSets", []):
                details = client_regional.get_ip_set(
                    Name=ip_set_summary["Name"],
                    Scope="REGIONAL",
                    Id=ip_set_summary["Id"]
                )
                ip_set = details["IPSet"]
                all_ip_sets.append({
                    "Name": ip_set["Name"],
                    "ARN": ip_set["ARN"],
                    "Scope": "REGIONAL",
                    "Region": region,
                    "IPAddressVersion": ip_set["IPAddressVersion"],
                    "AddressCount": len(ip_set["Addresses"])
                })
        except ClientError:
            pass
            
    return {"acls": all_acls, "ip_sets": all_ip_sets}