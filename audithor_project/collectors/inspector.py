# collectors/inspector.py
import json
import boto3
from botocore.exceptions import ClientError
from collections import defaultdict
from .utils import get_all_aws_regions # Importación relativa


def collect_inspector_status(session):
    """
    FUNCIÓN RÁPIDA: Obtiene solo el estado de activación de Inspector por región.
    """
    result_scan_status = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []
    
    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            account_state = status_response.get('accounts', [{}])[0]

            if account_state.get('state', {}).get('status') in ['ENABLED', 'ENABLING']:
                resource_state = account_state.get('resourceState', {})
                status = {
                    "Region": region,
                    "InspectorStatus": account_state.get('state', {}).get('status'),
                    "ScanEC2": resource_state.get('ec2', {}).get('status'),
                    "ScanECR": resource_state.get('ecr', {}).get('status'),
                    "ScanLambda": resource_state.get('lambda', {}).get('status', 'NOT_AVAILABLE')
                }
                result_scan_status.append(status)
        except ClientError:
            continue
    return {"scan_status": result_scan_status}

def collect_inspector_findings(session):
    """
    FUNCIÓN LENTA: Obtiene todos los hallazgos (findings) de Inspector.
    MODIFICADA: Ahora también obtiene el tag "Name" de las instancias EC2.
    """
    result_findings = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            if status_response.get('accounts', [{}])[0].get('state', {}).get('status') != 'ENABLED':
                continue

            paginator = inspector_client.get_paginator('list_findings')
            pages = paginator.paginate(filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]})
            for page in pages:
                for finding in page.get('findings', []):
                    finding['Region'] = region
                    result_findings.append(finding)
        except ClientError:
            continue
    # Agrupar IDs de instancias EC2 por región para una consulta eficiente
    ec2_findings_by_region = defaultdict(list)
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            region = f['Region']
            instance_id = f['resources'][0]['id']
            ec2_findings_by_region[region].append(instance_id)

    # Mapa para guardar los nombres de las instancias: { "i-12345": "WebServer01" }
    instance_name_map = {}

    # Consultar los nombres de las instancias en bloque por cada región
    for region, instance_ids in ec2_findings_by_region.items():
        if not instance_ids: continue
        try:
            ec2_client = session.client('ec2', region_name=region)
            paginator = ec2_client.get_paginator('describe_instances')
            pages = paginator.paginate(InstanceIds=list(set(instance_ids)))
            for page in pages:
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        name_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None)
                        if name_tag:
                            instance_name_map[instance['InstanceId']] = name_tag
        except ClientError:
            continue

    # Añadir el nombre resuelto de vuelta al objeto del finding
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            instance_id = f['resources'][0]['id']
            # Añadimos un nuevo campo 'resourceName' al finding
            f['resourceName'] = instance_name_map.get(instance_id, '')
    # --- FIN DE LA LÓGICA AÑADIDA ---

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNDEFINED': 5}
    result_findings.sort(key=lambda f: severity_order.get(f.get('severity'), 99))
    return {"findings": result_findings}

def collect_inspector_findings(session):
    """
    FUNCIÓN LENTA: Obtiene todos los hallazgos (findings) de Inspector.
    """
    result_findings = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            # Solo continuamos si Inspector está realmente activo en la región
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            if status_response.get('accounts', [{}])[0].get('state', {}).get('status') != 'ENABLED':
                continue

            paginator = inspector_client.get_paginator('list_findings')
            pages = paginator.paginate(filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]})
            for page in pages:
                for finding in page.get('findings', []):
                    finding['Region'] = region
                    result_findings.append(finding)
        except ClientError:
            continue
            
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNDEFINED': 5}
    result_findings.sort(key=lambda f: severity_order.get(f.get('severity'), 99))
    return {"findings": result_findings}

