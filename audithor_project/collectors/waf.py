# collectors/waf.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def parse_resource_arn(arn):
    try:
        parts = arn.split(':')
        resource_part = parts[5]
        if 'loadbalancer' in resource_part:
            lb_parts = resource_part.split('/')
            if len(lb_parts) > 2: return f"{lb_parts[0]}/{lb_parts[1]}/{lb_parts[2]}"
        if 'restapis' in resource_part:
            api_parts = resource_part.split('/')
            if len(api_parts) > 2: return f"{api_parts[1]}/{api_parts[2]}"
        return resource_part.split('/')[-1]
    except Exception: return arn

def collect_waf_data(session):
    all_acls, all_ip_sets = [], []
    regions = get_all_aws_regions(session)
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_web_acls(Scope="CLOUDFRONT")
        for acl in response.get("WebACLs", []):
            # --- LÍNEA CORREGIDA ---
            resources_raw = client_global.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
            all_acls.append({ "Name": acl["Name"], "ARN": acl["ARN"], "Scope": "CLOUDFRONT", "Region": "Global", "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw] })
    except ClientError: pass
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_web_acls(Scope="REGIONAL")
            for acl in response.get("WebACLs", []):
                resources_raw = client_regional.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
                all_acls.append({ "Name": acl["Name"], "ARN": acl["ARN"], "Scope": "REGIONAL", "Region": region, "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw] })
        except ClientError: pass
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_ip_sets(Scope="CLOUDFRONT")
        for ip_set_summary in response.get("IPSets", []):
            details = client_global.get_ip_set(Name=ip_set_summary["Name"], Scope="CLOUDFRONT", Id=ip_set_summary["Id"])
            all_ip_sets.append({ "Name": details["IPSet"]["Name"], "ARN": details["IPSet"]["ARN"], "Scope": "CLOUDFRONT", "Region": "Global", "IPAddressVersion": details["IPSet"]["IPAddressVersion"], "AddressCount": len(details["IPSet"]["Addresses"]) })
    except ClientError: pass
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_ip_sets(Scope="REGIONAL")
            for ip_set_summary in response.get("IPSets", []):
                details = client_regional.get_ip_set(Name=ip_set_summary["Name"], Scope="REGIONAL", Id=ip_set_summary["Id"])
                all_ip_sets.append({ "Name": details["IPSet"]["Name"], "ARN": details["IPSet"]["ARN"], "Scope": "REGIONAL", "Region": region, "IPAddressVersion": details["IPSet"]["IPAddressVersion"], "AddressCount": len(details["IPSet"]["Addresses"]) })
        except ClientError: pass
    return {"acls": all_acls, "ip_sets": all_ip_sets}
