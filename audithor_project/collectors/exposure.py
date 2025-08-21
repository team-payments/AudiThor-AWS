# collectors/exposure.py
import json
import boto3
from botocore.exceptions import ClientError
import threading
from .utils import get_all_aws_regions # Importación relativa
from collections import defaultdict


EXPOSURE_SERVICES = { "S3 Public Buckets": "s3", "EC2 Public Instances": "ec2", "Security Groups Open": "ec2", "ALB/NLB Public": "elbv2", "Lambda URLs": "lambda", "API Gateway Public": "apigateway", "Assumable Roles": "iam", }
EXPOSURE_GLOBAL_SERVICES = {"S3 Public Buckets", "Assumable Roles"}
def is_bucket_public(s3, bucket):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket["Name"])
        for grant in acl.get("Grants", []):
            if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"): return True
    except ClientError: pass
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket["Name"])
        if policy_status.get("PolicyStatus", {}).get("IsPublic"): return True
    except ClientError: pass
    return False

def lambda_has_url(client, fn_name):
    try:
        configs = client.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
        return any(c.get("AuthType") == "NONE" for c in configs)
    except ClientError: return False

def role_is_assumable_by_anyone(role):
    try:
        pol = role.get("AssumeRolePolicyDocument", {})
        for stmt in pol.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal.get("AWS") == "*": return True
    except Exception: pass
    return False
    
def collect_network_ports_data(session, regions):
    exposed_ports = []
    
    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                for perm in sg.get("IpPermissions", []):
                    ip_protocol = perm.get("IpProtocol")
                    from_port = perm.get("FromPort", "All")
                    to_port = perm.get("ToPort", "All")
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            exposed_ports.append({
                                "Region": region, "ResourceId": sg_id, "ResourceType": "SecurityGroup",
                                "Direction": "Inbound", "Protocol": ip_protocol,
                                "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                "Source": ip_range.get("CidrIp"), "Description": f"SG: {sg_name}"
                            })
            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                acl_id = acl.get("NetworkAclId")
                for entry in acl.get("Entries", []):
                    if entry.get("RuleAction") == "allow" and not entry.get("Egress") and entry.get("CidrBlock") == "0.0.0.0/0":
                        ip_protocol = entry.get("Protocol")
                        port_range = entry.get("PortRange", {})
                        from_port = port_range.get("From", "All")
                        to_port = port_range.get("To", "All")
                        protocol = "All" if ip_protocol == -1 else ip_protocol
                        exposed_ports.append({
                            "Region": region, "ResourceId": acl_id, "ResourceType": "NetworkAcl",
                            "Direction": "Inbound", "Protocol": protocol,
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
    regions = get_all_aws_regions(session)
    result_summary, result_details = defaultdict(dict), defaultdict(lambda: defaultdict(list))
    lock, threads = threading.Lock(), []
    network_ports_results = collect_network_ports_data(session, regions)
    
    def worker(service, region, current_session):
        try:
            exposed = []
            if service == "S3 Public Buckets":
                client = current_session.client("s3", region_name=region if region != "Global" else "us-east-1")
                for b in client.list_buckets()["Buckets"]:
                    if is_bucket_public(client, b): exposed.append(b["Name"])
            
            elif service == "EC2 Public Instances":
                client = current_session.client("ec2", region_name=region)
                for r in client.describe_instances()["Reservations"]:
                    for inst in r["Instances"]:
                        if inst.get("PublicIpAddress"): exposed.append({ "Id": inst['InstanceId'], "State": inst.get("State", {}).get("Name", "unknown"), "PublicIp": inst.get("PublicIpAddress") })
            
            elif service == "Security Groups Open":
                client = current_session.client("ec2", region_name=region)
                for sg in client.describe_security_groups()["SecurityGroups"]:
                    if any(ip.get("CidrIp") == "0.0.0.0/0" for rule in sg.get("IpPermissions", []) for ip in rule.get("IpRanges", [])): exposed.append(f"{sg['GroupId']} ({sg['GroupName']})");
            
            elif service == "ALB/NLB Public":
                client = current_session.client("elbv2", region_name=region)
                
                try:
                    # --- LÍNEA CORREGIDA ---
                    # Se ha cambiado p['SslPolicyName'] por p['Name'] que es la clave correcta.
                    ssl_policies_details = {p['Name']: p for p in client.describe_ssl_policies().get('SslPolicies', [])}
                except ClientError:
                    ssl_policies_details = {}

                for lb in client.describe_load_balancers()["LoadBalancers"]:
                    if lb.get("Scheme") == "internet-facing":
                        lb_arn = lb["LoadBalancerArn"]
                        lb_data = {
                            "name": lb["LoadBalancerName"],
                            "arn": lb_arn,
                            "region": region,
                            "listeners": []
                        }
                        
                        listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                        for listener in listeners:
                            if listener.get("Protocol") in ["HTTPS", "TLS"]:
                                policy_name = listener.get("SslPolicy")
                                policy_details = ssl_policies_details.get(policy_name, {})
                                tls_versions = policy_details.get('SslProtocols', [])
                                ciphers = [c['Name'] for c in policy_details.get('Ciphers', [])]
                                is_outdated = any(v in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for v in tls_versions)
                                lb_data["listeners"].append({
                                    "port": listener.get("Port"), "protocol": listener.get("Protocol"),
                                    "policyName": policy_name, "isOutdated": is_outdated,
                                    "tlsVersions": tls_versions, "ciphers": ciphers
                                })
                        exposed.append(lb_data)

            elif service == "Lambda URLs":
                client = current_session.client("lambda", region_name=region)
                for fn in client.list_functions()["Functions"]:
                    if lambda_has_url(client, fn["FunctionName"]): exposed.append(fn["FunctionName"])
            
            elif service == "API Gateway Public":
                client = current_session.client("apigateway", region_name=region)
                for api in client.get_rest_apis()["items"]:
                    if "REGIONAL" in api.get("endpointConfiguration", {}).get("types", []): exposed.append(f"{api['name']} (Regional)")
            
            elif service == "Assumable Roles":
                client = current_session.client("iam", region_name="us-east-1")
                for role in client.list_roles()["Roles"]:
                    if role_is_assumable_by_anyone(role): exposed.append(role["RoleName"])
            
            with lock:
                if exposed:
                    result_summary[service][region], result_details[service][region] = len(exposed), exposed
        except ClientError: pass

    tasks = [(s, "Global") if s in EXPOSURE_GLOBAL_SERVICES else (s, r) for s in EXPOSURE_SERVICES for r in (["Global"] if s in EXPOSURE_GLOBAL_SERVICES else regions)]
    for service, region in tasks:
        t = threading.Thread(target=worker, args=(service, region, session)); threads.append(t); t.start()
    for t in threads: t.join()
    
    return {
        "summary": dict(result_summary), 
        "details": dict(result_details),
        "network_ports": network_ports_results
    }
