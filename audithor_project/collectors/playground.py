# collectors/playground.py
import json
import boto3
import ipaddress
import socket
import threading
import subprocess
import shutil
from collections import defaultdict
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

# --- Constantes del módulo ---
PROTOCOLS = {'-1': 'ALL', '6': 'TCP', '17': 'UDP', '1': 'ICMP'}

def pg_format_sg_rules(ec2_client, sg_id):
    """Obtiene y formatea las reglas de un Security Group en una tabla de texto."""
    sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
    rows = []
    
    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        port_range = f"{from_port}-{to_port}" if from_port != 'N/A' else 'ALL'
        
        sources = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                  [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])] + \
                  [i.get('PrefixListId') for i in rule.get('PrefixListIds', [])]
        
        for source in (sources or ['-']):
            rows.append(['Ingress', proto, port_range, source or 'N/A'])

    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        port_range = f"{from_port}-{to_port}" if from_port != 'N/A' else 'ALL'

        dests = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])] + \
                [i.get('PrefixListId') for i in rule.get('PrefixListIds', [])]

        for dest in (dests or ['-']):
            rows.append(['Egress', proto, port_range, dest or 'N/A'])

    return _format_to_table(['Direction', 'Protocol', 'Port Range', 'Source/Destination'], rows, f"Details for Security Group: {sg_id}")

def pg_format_nacl_rules(ec2_client, nacl_id):
    """Obtiene y formatea las reglas de una Network ACL en una tabla de texto."""
    nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]
    rows = []
    
    sorted_entries = sorted(nacl['Entries'], key=lambda x: x['RuleNumber'])
    
    for entry in sorted_entries:
        direction = 'Egress' if entry['Egress'] else 'Ingress'
        proto = PROTOCOLS.get(entry['Protocol'], entry['Protocol'])
        port_range = 'ALL'
        if 'PortRange' in entry:
            port_range = f"{entry['PortRange']['From']}-{entry['PortRange']['To']}"
        
        cidr = entry.get('CidrBlock') or entry.get('Ipv6CidrBlock', '-')
        rows.append([entry['RuleNumber'], direction, entry['RuleAction'].upper(), proto, port_range, cidr])

    return _format_to_table(['Rule #', 'Direction', 'Action', 'Protocol', 'Port Range', 'CIDR'], rows, f"Details for Network ACL: {nacl_id}")

def pg_format_route_table(ec2_client, rtb_id):
    """Obtiene y formatea las rutas de una Route Table en una tabla de texto."""
    rt = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])['RouteTables'][0]
    rows = []

    for route in rt['Routes']:
        target = next((v for k, v in route.items() if k != 'DestinationCidrBlock' and (k.endswith('Id') or k.endswith('id'))), 'local')
        rows.append([route['DestinationCidrBlock'], target, route['State']])
        
    return _format_to_table(['Destination', 'Target', 'State'], rows, f"Details for Route Table: {rtb_id}")

def pg_get_ec2_details(ec2_client, instance_id):
    """Obtiene detalles de red de una instancia EC2."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        if not instance.get('PrivateIpAddress'):
            raise ValueError(f"The EC2 instance '{instance_id}' does not have a private IP assigned (it may be stopped).")
        return {
            "id": instance['InstanceId'], "service": "EC2",
            "private_ip": instance.get('PrivateIpAddress'),
            "subnet_id": instance['SubnetId'], "vpc_id": instance['VpcId'],
            "security_group_ids": [sg['GroupId'] for sg in instance['SecurityGroups']]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            raise ValueError(f"EC2 instance with ID not found '{instance_id}'.")
        raise

def pg_get_rds_details(session, region, db_identifier, ec2_client):
    """Obtiene detalles de red de una instancia RDS."""
    rds_client = session.client('rds', region_name=region)
    try:
        db = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)['DBInstances'][0]
        # Primero, verificamos si la instancia es públicamente accesible.
        if db.get('PubliclyAccessible', False):
            public_ip = "No resuelta"
            try:
                # Intentamos resolver la IP solo para mostrarla en el mensaje de error.
                endpoint_address = db.get('Endpoint', {}).get('Address')
                if endpoint_address:
                    public_ip = socket.gethostbyname(endpoint_address)
            except Exception:
                pass # Si no se puede resolver, no es crítico.
            
            # Creamos un mensaje de error claro y explicativo.
            error_message = (f"Unsupported analysis: The RDS instance '{db_identifier}' is publicly accessible (IP: {public_ip}). "
                           "This tool can only analyze private network routes within a VPC. "
                           "To perform the analysis, the database must have Public access set to No in the AWS console.")
            raise ValueError(error_message)

        endpoint = db.get('Endpoint', {}).get('Address')
        if not endpoint:
            raise ValueError(f"The RDS instance '{db_identifier}' does not have an endpoint (it may be being created or in an unavailable state).")
        
        try:
            private_ip = socket.gethostbyname(endpoint)
        except socket.gaierror:
            raise ValueError(f"Could not resolve the private IP for the RDS endpoint: {endpoint}")

        all_subnets_in_vpc = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [db['DBSubnetGroup']['VpcId']]}])['Subnets']
        current_subnet_id = None
        for subnet in all_subnets_in_vpc:
            if ipaddress.ip_address(private_ip) in ipaddress.ip_network(subnet['CidrBlock']):
                current_subnet_id = subnet['SubnetId']
                break
        
        if not current_subnet_id:
            # Este error ahora solo saltará en casos muy extraños de configuración de red.
            raise ValueError(f"Could not determine the current subnet for the RDS instance IP {private_ip}.")

        return {
            "id": db['DBInstanceIdentifier'], "service": "RDS",
            "private_ip": private_ip,
            "subnet_id": current_subnet_id, "vpc_id": db['DBSubnetGroup']['VpcId'],
            "security_group_ids": [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            raise ValueError(f"RDS instance with identifier not found '{db_identifier}'.")
        raise

def pg_get_lambda_details(session, region, function_name, ec2_client):
    lambda_client = session.client('lambda', region_name=region)
    try:
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        vpc_config = config.get('VpcConfig')
        if not (vpc_config and vpc_config.get('VpcId')): raise ValueError(f"The Lambda function '{function_name}' is not connected to a VPC.")
        paginator = ec2_client.get_paginator('describe_network_interfaces')
        pages = paginator.paginate(Filters=[ {'Name': 'group-id', 'Values': vpc_config['SecurityGroupIds']}, {'Name': 'description', 'Values': [f'AWS Lambda VPC ENI-{function_name}-*']} ])
        eni = next((eni for page in pages for eni in page['NetworkInterfaces']), None)
        if not (eni and eni.get('PrivateIpAddress')): raise ValueError(f"Could not find a network interface (ENI) with a private IP for the Lambda function '{function_name}'.")
        return {
            "id": config['FunctionName'],
            "service": "Lambda",
            "private_ip": eni['PrivateIpAddress'],
            "subnet_id": eni['SubnetId'],
            "vpc_id": eni['VpcId'],
            "security_group_ids": [sg['GroupId'] for sg in eni['Groups']]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException': raise ValueError(f"Lambda function with the name not found '{function_name}'.")
        raise

def pg_get_resource_network_details(session, arn):
    """Función 'dispatcher' que obtiene detalles de red para cualquier recurso soportado."""
    try:
        parts = arn.split(':')
        service = parts[2]
        region = parts[3]
        resource_full = ":".join(parts[5:])
        
        ec2_client = session.client('ec2', region_name=region)

        if service == 'ec2' and resource_full.startswith('instance/'):
            instance_id = resource_full.split('/')[1]
            return pg_get_ec2_details(ec2_client, instance_id)
        elif service == 'rds' and resource_full.startswith('db:'):
            db_identifier = resource_full[3:]
            return pg_get_rds_details(session, region, db_identifier, ec2_client)
        elif service == 'lambda' and resource_full.startswith('function:'):
            function_name = resource_full[9:]
            return pg_get_lambda_details(session, region, function_name, ec2_client)
        else:
            raise ValueError(f"Unsupported ARN type: '{arn}'. Only EC2 instances, RDS instances, and Lambda functions (in VPC) are supported.")
    except (IndexError, AttributeError):
        raise ValueError(f"The ARN format '{arn}' is invalid.")

def pg_check_nacl_fully(ec2_client, subnet_id, direction, remote_ip, protocol, port):
    try:
        response = ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        acl = response['NetworkAcls'][0]
    except (IndexError, ClientError):
        vpc_id_res = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]['VpcId']
        response = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id_res]}, {'Name': 'default', 'Values': ['true']}])
        acl = response['NetworkAcls'][0]

    protocol_str = str(protocol)
    rules = sorted([e for e in acl['Entries'] if e['Egress'] == (direction == 'outbound')], key=lambda x: x['RuleNumber'])

    for rule in rules:
        if rule['RuleNumber'] == 32767: continue
        cidr = rule.get('CidrBlock')
        if not (cidr and ipaddress.ip_address(remote_ip) in ipaddress.ip_network(cidr)): continue
        rule_protocol = rule.get('Protocol')
        if rule_protocol != '-1' and rule_protocol != protocol_str: continue
        port_range = rule.get('PortRange', {})
        rule_from_port = port_range.get('From')
        if rule_from_port is not None:
            rule_to_port = port_range.get('To')
            if port != -1 and not (port >= rule_from_port and port <= rule_to_port): continue
        
        matched_rule = {**rule, 'AclId': acl['NetworkAclId']}
        if rule['RuleAction'] == 'deny': return False, matched_rule
        return True, matched_rule
    
    implicit_deny_rule = {'RuleNumber': '*', 'RuleAction': 'deny', 'AclId': acl['NetworkAclId'], 'CidrBlock': '0.0.0.0/0'}
    return False, implicit_deny_rule

def pg_check_route_table(ec2_client, source_subnet_id, dest_ip):
    try:
        response = ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [source_subnet_id]}])
        if not response['RouteTables']:
            subnet_info = ec2_client.describe_subnets(SubnetIds=[source_subnet_id])
            vpc_id = subnet_info['Subnets'][0]['VpcId']
            response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'association.main', 'Values': ['true']}])

        rt = response['RouteTables'][0]
        best_route = None
        longest_prefix = -1

        for route in rt['Routes']:
            cidr = ipaddress.ip_network(route['DestinationCidrBlock'])
            if ipaddress.ip_address(dest_ip) in cidr:
                if cidr.prefixlen > longest_prefix:
                    longest_prefix = cidr.prefixlen
                    best_route = route
        
        if best_route:
            target = next((v for k, v in best_route.items() if k.endswith('GatewayId') or k.endswith('InstanceId') or k.endswith('InterfaceId') or k.endswith('PeeringConnectionId')), 'local')
            return True, {'RouteTableId': rt['RouteTableId'], 'Destination': best_route['DestinationCidrBlock'], 'Target': target}
    except (ClientError, IndexError):
        pass
    return False, {'RouteTableId': 'N/A', 'Destination': 'N/A', 'Target': 'No Route Found'}

def pg_build_decision_table(path_info, consolidated_ports):
    rows_data = []
    def get_sg_source_dest(rule):
        key_order = ['IpRanges', 'UserIdGroupPairs', 'PrefixListIds']
        key_extract = {'IpRanges': 'CidrIp', 'UserIdGroupPairs': 'GroupId', 'PrefixListIds': 'PrefixListId'}
        for key in key_order:
            items = rule.get(key)
            if items: return items[0].get(key_extract[key], 'N/A')
        return 'N/A'

    sg_out = path_info['source_sg_rule']
    rows_data.append(["SG Origen", path_info['source_sg_id'], "Egress", "N/A", "allow", str(sg_out.get('IpProtocol','-1')), f"{sg_out.get('FromPort', 'All')}-{sg_out.get('ToPort', 'All')}".replace('-1','All'), get_sg_source_dest(sg_out)])
    nacl_out = path_info['source_nacl_rule']
    rows_data.append(["NACL Origen", nacl_out.get('AclId'), "Egress", str(nacl_out.get('RuleNumber')), nacl_out.get('RuleAction'), str(nacl_out.get('Protocol','-1')), f"{nacl_out.get('PortRange',{}).get('From','All')}-{nacl_out.get('PortRange',{}).get('To','All')}", nacl_out.get('CidrBlock')])
    route_info = path_info['route_rule']
    rows_data.append(["Route Table", route_info.get('RouteTableId'), "Forwarding", route_info.get('Destination'), "N/A", "N/A", "N/A", route_info.get('Target')])
    nacl_in = path_info['target_nacl_rule']
    rows_data.append(["NACL Destino", nacl_in.get('AclId'), "Ingress", str(nacl_in.get('RuleNumber')), nacl_in.get('RuleAction'), str(nacl_in.get('Protocol','-1')), f"{nacl_in.get('PortRange',{}).get('From','All')}-{nacl_in.get('PortRange',{}).get('To','All')}", nacl_in.get('CidrBlock')])
    sg_in = path_info['target_sg_rule']
    rows_data.append(["SG Destino", path_info['target_sg_id'], "Ingress", "N/A", "allow", str(sg_in.get('IpProtocol','-1')), consolidated_ports, get_sg_source_dest(sg_in)])
    
    title = f"Decision Path for {consolidated_ports}:"
    headers = ["Capa", "ID Recurso", "Dirección", "Destino/Regla", "Acción", "Protocolo", "Puerto(s)", "Origen/Target"]
    return _format_to_table(headers, rows_data, title)

def pg_consolidate_ports(port_tuples):
    if not port_tuples: return ""
    ports_by_proto = defaultdict(set)
    for proto, from_port, to_port in port_tuples:
        proto_str = PROTOCOLS.get(str(proto), str(proto))
        if from_port == -1: ports_by_proto[proto_str] = {"All"}; continue
        ports_by_proto[proto_str].add(f"{from_port}-{to_port}" if from_port != to_port else str(from_port))
    
    output_parts = []
    for proto, ports in sorted(ports_by_proto.items()):
        if "All" in ports: output_parts.append(f"All ports {proto}"); continue
        sorted_ports = sorted(list(ports), key=lambda x: tuple(map(int, x.split('-'))) if '-' in x else (int(x),))
        output_parts.append(f"Port(s) {', '.join(sorted_ports)} ({proto})")
    return " | ".join(output_parts)

def analyze_network_path_data(session, source_arn, target_arn):
    """Función principal que ahora usa el dispatcher para analizar la ruta."""
    source = pg_get_resource_network_details(session, source_arn)
    target = pg_get_resource_network_details(session, target_arn)

    if source['vpc_id'] != target['vpc_id']:
        return {'status': 'UNREACHABLE', 'reason': f"The resources are in different VPCs ({source['vpc_id']} and {target['vpc_id']}) and this analysis does not cover Peering/Transit Gateway.", 'tables': [], 'detail_tables': {}}
    
    region = source_arn.split(':')[3]
    ec2 = session.client('ec2', region_name=region)
    
    route_ok, route_rule = pg_check_route_table(ec2, source['subnet_id'], target['private_ip'])
    if not route_ok:
        return {'status': 'UNREACHABLE', 'reason': f"No route was found in the table '{route_rule.get('RouteTableId')}' from the source subnet to the destination IP '{target['private_ip']}'.", 'tables': [], 'detail_tables': {}}

    result = {
        'status': 'UNREACHABLE', 'reason': 'There are no rules in the source/destination SG that allow the connection.',
        'perms': [], 'tables': [], 'detail_tables': {}
    }
    
    source_sgs_rules = ec2.describe_security_groups(GroupIds=source['security_group_ids'])['SecurityGroups']
    target_sgs_rules = ec2.describe_security_groups(GroupIds=target['security_group_ids'])['SecurityGroups']
    path_found_for_target = False

    for sg_out_details in source_sgs_rules:
        for egress_rule in sg_out_details.get('IpPermissionsEgress', []):
            target_matches_egress_rule = any(ipaddress.ip_address(target['private_ip']) in ipaddress.ip_network(ip_range.get('CidrIp', '0.0.0.0/32')) for ip_range in egress_rule.get('IpRanges', [])) or \
                                         any(sg_ref.get('GroupId') in target['security_group_ids'] for sg_ref in egress_rule.get('UserIdGroupPairs', []))
            if not target_matches_egress_rule: continue

            for target_sg_details in target_sgs_rules:
                for ingress_rule in target_sg_details.get('IpPermissions', []):
                    egress_proto = egress_rule.get('IpProtocol', '-1')
                    ingress_proto = ingress_rule.get('IpProtocol', '-1')
                    if not (egress_proto == ingress_proto or egress_proto == '-1' or ingress_proto == '-1'): continue
                    
                    egress_from, egress_to = egress_rule.get('FromPort', -1), egress_rule.get('ToPort', -1)
                    ingress_from, ingress_to = ingress_rule.get('FromPort', -1), ingress_rule.get('ToPort', -1)
                    if not (egress_from == -1 or ingress_from == -1 or max(egress_from, ingress_from) <= min(egress_to, ingress_to)): continue

                    source_allowed = any(ipaddress.ip_address(source['private_ip']) in ipaddress.ip_network(in_cidr.get('CidrIp', '0.0.0.0/32')) for in_cidr in ingress_rule.get('IpRanges',[])) or \
                                     any(in_sg_ref.get('GroupId') in source['security_group_ids'] for in_sg_ref in ingress_rule.get('UserIdGroupPairs',[]))
                    if not source_allowed: continue
                    
                    report_proto = ingress_proto if egress_proto == '-1' and ingress_proto != '-1' else egress_proto
                    report_from = ingress_from if egress_from == -1 and ingress_from != -1 else egress_from
                    
                    nacl_out_allowed, nacl_out_rule = pg_check_nacl_fully(ec2, source['subnet_id'], 'outbound', target['private_ip'], report_proto, report_from if report_from != -1 else 0)
                    if not nacl_out_allowed:
                        result['reason'] = f"Blocked by outbound NACL: Rule #{nacl_out_rule.get('RuleNumber')} ({nacl_out_rule.get('RuleAction')} in {nacl_out_rule.get('AclId')})"; continue
                    
                    nacl_in_allowed, nacl_in_rule = pg_check_nacl_fully(ec2, target['subnet_id'], 'inbound', source['private_ip'], report_proto, report_from if report_from != -1 else 0)
                    if not nacl_in_allowed:
                        result['reason'] = f"Blocked by inbound NACL: Rule #{nacl_in_rule.get('RuleNumber')} ({nacl_in_rule.get('RuleAction')} in {nacl_in_rule.get('AclId')})"; continue
                    
                    path_found_for_target = True
                    result['status'] = 'REACHABLE'
                    result['perms'].append({
                        'perm_tuple': (ingress_proto, ingress_from, ingress_rule.get('ToPort', -1)),
                        'source_sg_rule': egress_rule, 'source_sg_id': sg_out_details['GroupId'],
                        'target_sg_rule': ingress_rule, 'target_sg_id': target_sg_details['GroupId'],
                        'source_nacl_rule': nacl_out_rule, 'target_nacl_rule': nacl_in_rule,
                        'route_rule': route_rule
                    })
    
    if path_found_for_target:
        result['reason'] = ''
        grouped_paths = defaultdict(list)
        involved_ids = set()

        for perm_path in result['perms']:
            path_signature = (perm_path['source_sg_id'], perm_path['target_sg_id'], perm_path['source_nacl_rule']['AclId'], perm_path['source_nacl_rule']['RuleNumber'], perm_path['target_nacl_rule']['AclId'], perm_path['target_nacl_rule']['RuleNumber'], str(perm_path['source_sg_rule']), str(perm_path['target_sg_rule']), str(perm_path['route_rule']))
            grouped_paths[path_signature].append(perm_path['perm_tuple'])
        
        for perms in grouped_paths.values():
            representative_path = next(p for p in result['perms'] if p['perm_tuple'] in perms)
            consolidated_ports_str = pg_consolidate_ports(perms)
            result['tables'].append(pg_build_decision_table(representative_path, consolidated_ports_str))
            
            involved_ids.add(("sg", representative_path['source_sg_id']))
            involved_ids.add(("sg", representative_path['target_sg_id']))
            involved_ids.add(("nacl", representative_path['source_nacl_rule']['AclId']))
            involved_ids.add(("nacl", representative_path['target_nacl_rule']['AclId']))
            involved_ids.add(("rtb", representative_path['route_rule']['RouteTableId']))

        for type, res_id in sorted(list(involved_ids)):
            if res_id not in result['detail_tables']:
                if type == "sg": result['detail_tables'][res_id] = pg_format_sg_rules(ec2, res_id)
                elif type == "nacl": result['detail_tables'][res_id] = pg_format_nacl_rules(ec2, res_id)
                elif type == "rtb": result['detail_tables'][res_id] = pg_format_route_table(ec2, res_id)

    del result['perms']
    return result

def run_sslscan_on_targets(targets_str):
    """
    Ejecuta sslscan en una lista de objetivos y devuelve los resultados.
    """
    targets = [t.strip() for t in targets_str.split(',')]
    results = []
    
    if not shutil.which("sslscan"):
        return [{"target": ", ".join(targets), "error": "The sslscan command was not found in your system PATH."}]

    threads = []
    def scan_target(target):
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
        if not all(char in safe_chars for char in target) or not target:
            results.append({"target": target, "error": "The target contains invalid characters or is empty."})
            return
        try:
            command = ['sslscan', '--no-colour', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            if not result.stdout and not result.stderr:
                results.append({"target": target, "error": "The command executed but returned no output."})
            else:
                results.append({"target": target, "output": result.stdout + result.stderr})
        except subprocess.TimeoutExpired:
            results.append({"target": target, "error": "The scan has exceeded the timeout (120 seconds)."})
        except Exception as e:
            results.append({"target": target, "error": f"An unexpected error has occurred: {str(e)}"})

    for target in targets:
        thread = threading.Thread(target=scan_target, args=(target,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results

def _format_to_table(headers, rows, title):
    """Función de utilidad para crear una tabla de texto."""
    if not rows:
        return f"{title}\nNo rules or entries found."
    
    # Calcular anchos de columna
    col_widths = {header: len(header) for header in headers}
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[headers[i]] = max(col_widths[headers[i]], len(str(cell)))
    
    # Crear líneas de la tabla
    header_line = " | ".join(header.ljust(col_widths[header]) for header in headers)
    separator = "-+-".join("-" * col_widths[header] for header in headers)
    body_lines = "\n".join(" | ".join(str(cell).ljust(col_widths[headers[i]]) for i, cell in enumerate(row)) for row in rows)
    
    return (f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n"
            f"| {title.center(len(header_line))} |\n"
            f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n"
            f"| {header_line} |\n"
            f"+={separator}=+\n"
            f"| " + body_lines.replace("\n", " |\n| ") + " |\n"
            f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+")