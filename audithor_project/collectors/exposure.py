import json
import boto3
import threading
from botocore.exceptions import ClientError
from collections import defaultdict
from .utils import get_all_aws_regions # Relative import

EXPOSURE_SERVICES = {
    "S3 Public Buckets": "s3",
    "EC2 Public Instances": "ec2",
    "Security Groups Open": "ec2",
    "ALB/NLB Public": "elbv2",
    "Lambda URLs": "lambda",
    "API Gateway Public": "apigateway",
    "Assumable Roles": "iam",
}

EXPOSURE_GLOBAL_SERVICES = {"S3 Public Buckets", "Assumable Roles"}


def is_bucket_public(s3, bucket):
    """
    Checks if an S3 bucket is public via ACL or bucket policy.

    Args:
        s3 (boto3.client): The S3 client object.
        bucket (dict): A dictionary containing the bucket's name.

    Returns:
        bool: True if the bucket is public, False otherwise.

    Example:
        >>> s3_client = boto3.client('s3')
        >>> bucket_info = {'Name': 'my-test-bucket'}
        >>> is_public = is_bucket_public(s3_client, bucket_info)
    """
    try:
        acl = s3.get_bucket_acl(Bucket=bucket["Name"])
        for grant in acl.get("Grants", []):
            if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                return True
    except ClientError:
        pass  # Ignore errors like AccessDenied

    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket["Name"])
        if policy_status.get("PolicyStatus", {}).get("IsPublic"):
            return True
    except ClientError:
        pass  # Ignore errors if no policy exists or access is denied

    return False


def lambda_has_url(client, fn_name):
    """
    Determines if a Lambda function has a public Function URL.

    A function URL is considered public if its authentication type is 'NONE'.

    Args:
        client (boto3.client): The Lambda client object.
        fn_name (str): The name of the Lambda function.

    Returns:
        bool: True if the function has a public URL, False otherwise.

    Example:
        >>> lambda_client = boto3.client('lambda')
        >>> has_public_url = lambda_has_url(lambda_client, 'my-function')
    """
    try:
        configs = client.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
        return any(c.get("AuthType") == "NONE" for c in configs)
    except ClientError:
        return False


def role_is_assumable_by_anyone(role):
    """
    Checks if an IAM role's trust policy allows it to be assumed by anyone.

    It inspects the 'Principal' in the assume role policy document.

    Args:
        role (dict): A dictionary representing the IAM role details.

    Returns:
        bool: True if the role is assumable by a wildcard principal, False otherwise.

    Example:
        >>> role_details = iam_client.get_role(RoleName='my-role')['Role']
        >>> is_assumable = role_is_assumable_by_anyone(role_details)
    """
    try:
        pol = role.get("AssumeRolePolicyDocument", {})
        for stmt in pol.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal.get("AWS") == "*":
                return True
    except Exception:
        pass
    return False


def collect_network_ports_data(session, regions):
    """
    Scans Security Groups and Network ACLs across regions for rules allowing inbound traffic from 0.0.0.0/0.

    Args:
        session (boto3.Session): The boto3 session to use for creating clients.
        regions (list): A list of AWS region names to scan.

    Returns:
        list: A list of dictionaries, each detailing an exposed port or range.

    Example:
        >>> current_session = boto3.Session()
        >>> regions_to_scan = ['us-east-1', 'eu-west-1']
        >>> ports = collect_network_ports_data(current_session, regions_to_scan)
    """
    exposed_ports = []

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            from_port = perm.get("FromPort", "All")
                            to_port = perm.get("ToPort", "All")
                            exposed_ports.append({
                                "Region": region, "ResourceId": sg.get("GroupId"), "ResourceType": "SecurityGroup",
                                "Direction": "Inbound", "Protocol": perm.get("IpProtocol"),
                                "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                "Source": ip_range.get("CidrIp"), "Description": f"SG: {sg.get('GroupName')}"
                            })

            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                for entry in acl.get("Entries", []):
                    if entry.get("RuleAction") == "allow" and not entry.get("Egress") and entry.get("CidrBlock") == "0.0.0.0/0":
                        port_range = entry.get("PortRange", {})
                        from_port = port_range.get("From", "All")
                        to_port = port_range.get("To", "All")
                        exposed_ports.append({
                            "Region": region, "ResourceId": acl.get("NetworkAclId"), "ResourceType": "NetworkAcl",
                            "Direction": "Inbound", "Protocol": "All" if entry.get("Protocol") == -1 else entry.get("Protocol"),
                            "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                            "Source": entry.get("CidrBlock"), "Description": f"NACL Rule Number: {entry.get('RuleNumber')}"
                        })
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
    return exposed_ports


def collect_exposure_data(session):
    """
    Collects public exposure data across multiple AWS services using multi-threading.

    This function scans for public S3 buckets, EC2 instances, open security groups,
    internet-facing load balancers, Lambda URLs, public API Gateways, and
    publicly assumable IAM roles. It also collects open network port data.

    Args:
        session (boto3.Session): The boto3 session for creating service clients.

    Returns:
        dict: A dictionary containing a summary, detailed findings, and network port analysis.

    Example:
        >>> current_session = boto3.Session()
        >>> exposure_report = collect_exposure_data(current_session)
    """
    regions = get_all_aws_regions(session)
    result_summary = defaultdict(dict)
    result_details = defaultdict(lambda: defaultdict(list))
    lock = threading.Lock()
    threads = []
    network_ports_results = collect_network_ports_data(session, regions)

    def worker(service, region, current_session):
        try:
            exposed = []
            if service == "S3 Public Buckets":
                client = current_session.client("s3", region_name=region if region != "Global" else "us-east-1")
                for b in client.list_buckets()["Buckets"]:
                    if is_bucket_public(client, b):
                        exposed.append(b["Name"])

            elif service == "EC2 Public Instances":
                client = current_session.client("ec2", region_name=region)
                for r in client.describe_instances()["Reservations"]:
                    for inst in r["Instances"]:
                        if inst.get("PublicIpAddress"):
                            exposed.append({"Id": inst['InstanceId'], "State": inst.get("State", {}).get("Name", "unknown"), "PublicIp": inst.get("PublicIpAddress")})

            elif service == "Security Groups Open":
                client = current_session.client("ec2", region_name=region)
                for sg in client.describe_security_groups()["SecurityGroups"]:
                    if any(ip.get("CidrIp") == "0.0.0.0/0" for rule in sg.get("IpPermissions", []) for ip in rule.get("IpRanges", [])):
                        exposed.append(f"{sg['GroupId']} ({sg['GroupName']})")

            elif service == "ALB/NLB Public":
                client = current_session.client("elbv2", region_name=region)
                ssl_policies_details = {p['Name']: p for p in client.describe_ssl_policies().get('SslPolicies', [])}
                for lb in client.describe_load_balancers()["LoadBalancers"]:
                    if lb.get("Scheme") == "internet-facing":
                        lb_arn = lb["LoadBalancerArn"]
                        listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                        listener_details = []
                        for listener in listeners:
                            if listener.get("Protocol") in ["HTTPS", "TLS"]:
                                policy_name = listener.get("SslPolicy")
                                policy_details = ssl_policies_details.get(policy_name, {})
                                tls_versions = policy_details.get('SslProtocols', [])
                                ciphers = [c['Name'] for c in policy_details.get('Ciphers', [])]
                                is_outdated = any(v in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for v in tls_versions)
                                listener_details.append({
                                    "port": listener.get("Port"), "protocol": listener.get("Protocol"),
                                    "policyName": policy_name, "isOutdated": is_outdated,
                                    "tlsVersions": tls_versions, "ciphers": ciphers
                                })
                        exposed.append({
                            "name": lb["LoadBalancerName"], "arn": lb_arn,
                            "region": region, "listeners": listener_details
                        })

            elif service == "Lambda URLs":
                client = current_session.client("lambda", region_name=region)
                for fn in client.list_functions()["Functions"]:
                    if lambda_has_url(client, fn["FunctionName"]):
                        exposed.append(fn["FunctionName"])

            elif service == "API Gateway Public":
                client = current_session.client("apigateway", region_name=region)
                for api in client.get_rest_apis()["items"]:
                    if "REGIONAL" in api.get("endpointConfiguration", {}).get("types", []):
                        exposed.append(f"{api['name']} (Regional)")

            elif service == "Assumable Roles":
                client = current_session.client("iam", region_name="us-east-1")
                for role in client.list_roles()["Roles"]:
                    if role_is_assumable_by_anyone(role):
                        exposed.append(role["RoleName"])

            with lock:
                if exposed:
                    result_summary[service][region] = len(exposed)
                    result_details[service][region] = exposed
        except ClientError:
            pass

    tasks = [(s, "Global") if s in EXPOSURE_GLOBAL_SERVICES else (s, r) for s in EXPOSURE_SERVICES for r in (["Global"] if s in EXPOSURE_GLOBAL_SERVICES else regions)]
    for service, region in tasks:
        t = threading.Thread(target=worker, args=(service, region, session))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return {
        "summary": dict(result_summary),
        "details": dict(result_details),
        "network_ports": network_ports_results
    }