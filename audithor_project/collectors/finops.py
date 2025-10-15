# collectors/finops.py
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

# --- ESTIMACIONES DE COSTE (Basadas en us-east-1, para dar una idea de magnitud) ---
# Es importante aclarar al cliente que son estimaciones.
COST_EBS_GP3_PER_GB_MONTH = 0.08  # $ por GB/mes
COST_EIP_PER_HOUR = 0.005         # $ por hora para EIP no asociada
COST_ALB_PER_HOUR = 0.0225        # $ por hora para un Application Load Balancer

def _estimate_monthly_cost(resource_type, details):
    """Estima el coste mensual de un recurso basado en precios aproximados."""
    hours_in_month = 730
    if resource_type == 'ebs':
        return details.get('Size', 0) * COST_EBS_GP3_PER_GB_MONTH
    elif resource_type == 'eip':
        return COST_EIP_PER_HOUR * hours_in_month
    elif resource_type == 'lb':
        return COST_ALB_PER_HOUR * hours_in_month
    return 0

def collect_finops_data(session):
    """
    Colecta datos de recursos potencialmente desperdiciados para análisis FinOps.
    """
    all_regions = get_all_aws_regions(session)
    unattached_volumes = []
    unassociated_eips = []
    idle_load_balancers = []

    for region in all_regions:
        try:
            print(f"[FinOps Collector] Analizando región: {region}")
            ec2_client = session.client('ec2', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)

            # 1. Buscar Volúmenes EBS sin adjuntar (estado 'available')
            paginator_vol = ec2_client.get_paginator('describe_volumes')
            for page in paginator_vol.paginate(Filters=[{'Name': 'status', 'Values': ['available']}]):
                for vol in page.get('Volumes', []):
                    details = {
                        'VolumeId': vol['VolumeId'],
                        'Region': region,
                        'Size': vol['Size'],
                        'VolumeType': vol['VolumeType'],
                        'CreateTime': vol['CreateTime'].isoformat()
                    }
                    details['EstimatedMonthlyCost'] = _estimate_monthly_cost('ebs', details)
                    unattached_volumes.append(details)

            # 2. Buscar IPs Elásticas no asociadas
            addresses = ec2_client.describe_addresses()
            for addr in addresses.get('Addresses', []):
                if 'AssociationId' not in addr:
                    details = {
                        'PublicIp': addr['PublicIp'],
                        'AllocationId': addr['AllocationId'],
                        'Region': region,
                        'Domain': addr['Domain']
                    }
                    details['EstimatedMonthlyCost'] = _estimate_monthly_cost('eip', details)
                    unassociated_eips.append(details)

            # 3. Buscar Load Balancers (v2) inactivos
            paginator_lb = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator_lb.paginate():
                for lb in page.get('LoadBalancers', []):
                    target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                    is_idle = True
                    if not target_groups.get('TargetGroups', []):
                        # Si no tiene Target Groups, está inactivo
                        is_idle = True
                    else:
                        # Si tiene Target Groups, verificar si alguno tiene instancias
                        is_idle = True # Asumimos inactivo hasta que encontremos un target
                        for tg in target_groups['TargetGroups']:
                            health = elbv2_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                            if health.get('TargetHealthDescriptions', []):
                                is_idle = False
                                break # Encontramos un target, el LB no está inactivo
                    
                    if is_idle:
                        details = {
                            'LoadBalancerName': lb['LoadBalancerName'],
                            'LoadBalancerArn': lb['LoadBalancerArn'],
                            'Region': region,
                            'Type': lb['Type'],
                            'State': lb['State']['Code']
                        }
                        details['EstimatedMonthlyCost'] = _estimate_monthly_cost('lb', details)
                        idle_load_balancers.append(details)

        except ClientError as e:
            if "OptInRequired" in str(e):
                print(f"[FinOps Collector] Saltando región no habilitada: {region}")
            else:
                print(f"[FinOps Collector] Error en la región {region}: {e}")
            continue

    return {
        "unattached_volumes": unattached_volumes,
        "unassociated_eips": unassociated_eips,
        "idle_load_balancers": idle_load_balancers
    }