# collectors/waf.py
import json
import boto3
from botocore.exceptions import ClientError
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

    Example:
        >>> ec2_arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-01a2b3c4d5e6f7g8h"
        >>> print(parse_resource_arn(ec2_arn))
        i-01a2b3c4d5e6f7g8h

        >>> lb_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188"
        >>> print(parse_resource_arn(lb_arn))
        loadbalancer/app/my-lb
    """
    try:
        parts = arn.split(':')
        resource_part = parts[5]

        # Special handling for Load Balancer ARNs to include type and name
        if 'loadbalancer' in resource_part:
            lb_parts = resource_part.split('/')
            if len(lb_parts) > 2:
                return f"{lb_parts[0]}/{lb_parts[1]}/{lb_parts[2]}"
        
        # Special handling for API Gateway REST API ARNs
        if 'restapis' in resource_part:
            api_parts = resource_part.split('/')
            if len(api_parts) > 2:
                return f"{api_parts[1]}/{api_parts[2]}"
        
        # Default case: return the last part of the resource identifier
        return resource_part.split('/')[-1]

    except Exception:
        # If parsing fails for any reason, return the original ARN
        return arn

def collect_waf_data(session):
    """
    Collects data on AWS WAFv2 Web ACLs and IP Sets from all scopes and regions.

    This function handles the dual-scope nature of WAFv2 by first querying for
    global resources (Scope='CLOUDFRONT') in us-east-1, and then iterating
    through all other regions to find regional resources (Scope='REGIONAL').
    It gathers details for both Web ACLs and IP Sets.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing two keys:
              - 'acls': A list of all Web ACLs, global and regional.
              - 'ip_sets': A list of all IP Sets, global and regional.

    Example:
        >>> import boto3
        >>>
        >>> # Assumes helper functions are available
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> waf_inventory = collect_waf_data(aws_session)
        >>> print(f"Found {len(waf_inventory['acls'])} total Web ACLs.")
    """
    all_acls = []
    all_ip_sets = []
    regions = get_all_aws_regions(session)

    # --- 1. Collect CloudFront (Global) Web ACLs ---
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_web_acls(Scope="CLOUDFRONT")
        for acl in response.get("WebACLs", []):
            resources_raw = client_global.list_resources_for_web_acl(
                WebACLArn=acl["ARN"]
            ).get("ResourceArns", [])
            
            all_acls.append({
                "Name": acl["Name"],
                "ARN": acl["ARN"],
                "Scope": "CLOUDFRONT",
                "Region": "Global",
                "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw]
            })
    except ClientError:
        pass # Ignore if WAF is not available or permissions are missing

    # --- 2. Collect Regional Web ACLs ---
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_web_acls(Scope="REGIONAL")
            for acl in response.get("WebACLs", []):
                resources_raw = client_regional.list_resources_for_web_acl(
                    WebACLArn=acl["ARN"]
                ).get("ResourceArns", [])

                all_acls.append({
                    "Name": acl["Name"],
                    "ARN": acl["ARN"],
                    "Scope": "REGIONAL",
                    "Region": region,
                    "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw]
                })
        except ClientError:
            pass # Continue to the next region on error

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
