# collectors/network_policies.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_network_policies_data(session):
    regions = get_all_aws_regions(session) # Se obtiene la lista completa de regiones aquí
    result_vpcs = []
    result_acls = []
    result_sgs = []
    result_subnets = [] # <-- AÑADIDO

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            
            # Recopilar VPCs
            vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                tags_dict = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                result_vpcs.append({
                    "Region": region, "VpcId": vpc.get("VpcId"), "CidrBlock": vpc.get("CidrBlock"),
                    "IsDefault": vpc.get("IsDefault"), "Tags": tags_dict
                })

            # Recopilar Network ACLs
            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                tags_dict = {tag['Key']: tag['Value'] for tag in acl.get('Tags', [])}
                result_acls.append({
                    "Region": region, "AclId": acl.get("NetworkAclId"), "VpcId": acl.get("VpcId"),
                    "IsDefault": acl.get("IsDefault"), "Tags": tags_dict
                })

            # Recopilar Security Groups
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                tags_dict = {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                result_sgs.append({
                    "Region": region, "GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"), "Description": sg.get("Description"), "Tags": tags_dict
                })
            # Recopilar Subredes
            subnets = ec2_client.describe_subnets().get("Subnets", [])
            for subnet in subnets:
                tags_dict = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                result_subnets.append({
                    "Region": region,
                    "SubnetId": subnet.get("SubnetId"),
                    "VpcId": subnet.get("VpcId"),
                    "CidrBlock": subnet.get("CidrBlock"),
                    "AvailabilityZone": subnet.get("AvailabilityZone"),
                    "Tags": tags_dict
                })
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
            
    # El return ahora incluye la lista de subredes
    return { 
        "vpcs": result_vpcs, 
        "acls": result_acls, 
        "security_groups": result_sgs,
        "subnets": result_subnets, # <-- AÑADIDO
        "all_regions": regions 
    }

PROTOCOLS = {'-1': 'ALL', '6': 'TCP', '17': 'UDP', '1': 'ICMP'}

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
    
    return f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n" \
           f"| {title.center(len(header_line))} |\n" \
           f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n" \
           f"| {header_line} |\n" \
           f"+={separator}=+\n" \
           f"| " + body_lines.replace("\n", " |\n| ") + " |\n" \
           f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+"

def format_sg_details_table(sg_details):
    sg = sg_details['SecurityGroups'][0]
    title = f"Security Group details: {sg['GroupId']} ({sg['GroupName']})"
    headers = ['Dirección', 'Protocolo', 'Puerto', 'Origen/Destino', 'Descripción']
    rows = []

    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Ingress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Ingress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])
    
    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Egress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Egress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])

    return _format_to_table(headers, rows, title)

def format_nacl_details_table(nacl_details):
    nacl = nacl_details['NetworkAcls'][0]
    title = f"Network ACL details: {nacl['NetworkAclId']}"
    headers = ['# Regla', 'Dirección', 'Acción', 'Protocolo', 'Puerto', 'CIDR', 'Tags']
    rows = []
    
    tags_str = ", ".join([f"{t['Key']}={t['Value']}" for t in nacl.get('Tags', [])]) or "-"

    for entry in sorted(nacl['Entries'], key=lambda x: x['RuleNumber']):
        direction = 'Egress' if entry.get('Egress') else 'Ingress'
        action = entry.get('RuleAction', 'N/A').upper()
        proto = PROTOCOLS.get(str(entry.get('Protocol', '-1')), entry.get('Protocol', 'N/A'))
        port_range = entry.get('PortRange', {})
        port = f"{port_range.get('From', 'All')}-{port_range.get('To', 'All')}".replace('-1-All', 'All')
        cidr = entry.get('CidrBlock', '-')
        rows.append([entry.get('RuleNumber'), direction, action, proto, port, cidr, tags_str])
        
    return _format_to_table(headers, rows, title)

def _format_rules_as_table(headers, rows):
    """Función de ayuda para formatear datos en una tabla de texto plano."""
    # Encontrar el ancho máximo para cada columna
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    
    # Crear la línea de cabecera
    header_line = " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    separator = "-+-".join("-" * w for w in widths)
    
    # Crear las filas de datos
    data_lines = []
    for row in rows:
        data_lines.append(" | ".join(str(row[i]).ljust(widths[i]) for i in range(len(row))))
        
    return "\n".join([header_line, separator] + data_lines)

def get_network_details_table(session, resource_id, region):
    """
    Gets the rules for a Security Group or Network ACL and returns them
    as a formatted text table.
    """
    resource_id = resource_id.strip()

    try:
        ec2_client = session.client("ec2", region_name=region)

        if resource_id.startswith("sg-"):
            response = ec2_client.describe_security_groups(GroupIds=[resource_id])
            sg = response['SecurityGroups'][0]
            
            headers = ["Direction", "Protocol", "Port Range", "Source/Dest", "Description"]
            rows = []

            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', '-1')
                port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                for ip_range in rule.get('IpRanges', []):
                    rows.append(["Inbound", protocol, port_range, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
                for sg_source in rule.get('UserIdGroupPairs', []):
                    rows.append(["Inbound", protocol, port_range, sg_source.get('GroupId'), sg_source.get('Description', '-')])

            for rule in sg.get('IpPermissionsEgress', []):
                protocol = rule.get('IpProtocol', '-1')
                port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                for ip_range in rule.get('IpRanges', []):
                    rows.append(["Outbound", protocol, port_range, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
                for sg_dest in rule.get('UserIdGroupPairs', []):
                    rows.append(["Outbound", protocol, port_range, sg_dest.get('GroupId'), sg_dest.get('Description', '-')])
            
            title = f"--- Security Group Details: {sg.get('GroupName')} ({resource_id}) ---\n"
            return title + _format_rules_as_table(headers, rows)

        elif resource_id.startswith("acl-"):
            response = ec2_client.describe_network_acls(NetworkAclIds=[resource_id])
            nacl = response['NetworkAcls'][0]

            headers = ["Direction", "Rule #", "Protocol", "Port Range", "Source/Dest", "Action"]
            rows = []

            for entry in sorted(nacl.get('Entries', []), key=lambda x: x['RuleNumber']):
                direction = "Outbound" if entry.get('Egress') else "Inbound"
                protocol = entry.get('Protocol', '-1')
                port_range = f"{entry.get('PortRange', {}).get('From', 'All')}-{entry.get('PortRange', {}).get('To', 'All')}"
                action = entry.get('RuleAction').capitalize()
                source_dest = entry.get('CidrBlock')

                rows.append([direction, entry.get('RuleNumber'), protocol, port_range, source_dest, action])
            
            title = f"--- Network ACL Details: {resource_id} ---\n"
            return title + _format_rules_as_table(headers, rows)

        else:
            return "Error: The provided ID does not appear to be a Security Group (sg-...) or a Network ACL (acl-...)."

    except ClientError as e:
        return f"Error connecting to AWS: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"