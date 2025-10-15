# collectors/finops.py
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

# --- ESTIMACIONES DE COSTE (Basadas en us-east-1, para dar una idea de magnitud) ---
# Es importante aclarar al cliente que son estimaciones.
COST_EBS_GP3_PER_GB_MONTH = 0.08  # $ por GB/mes
COST_EIP_PER_HOUR = 0.005         # $ por hora para EIP no asociada
COST_ALB_PER_HOUR = 0.0225        # $ por hora para un Application Load Balancer
COST_EBS_GP2_PER_GB_MONTH = 0.10
OUTDATED_INSTANCE_FAMILIES = ['t2', 'm4', 'c4', 'r4', 't1', 'm3', 'c3', 'r3']

def _estimate_monthly_cost(resource_type, details):
    """Estima el coste mensual de un recurso basado en precios aproximados."""
    hours_in_month = 730
    if resource_type == 'ebs':
        return details.get('Size', 0) * COST_EBS_GP3_PER_GB_MONTH
    elif resource_type == 'ebs_gp2_saving':
        # Calcula el ahorro al pasar de gp2 a gp3
        cost_gp2 = details.get('Size', 0) * COST_EBS_GP2_PER_GB_MONTH
        cost_gp3 = details.get('Size', 0) * COST_EBS_GP3_PER_GB_MONTH
        return cost_gp2 - cost_gp3
    elif resource_type == 'eip':
        return COST_EIP_PER_HOUR * hours_in_month
    elif resource_type == 'lb':
        return COST_ALB_PER_HOUR * hours_in_month
    return 0

# --- NUEVA FUNCIÓN: Encontrar instancias EC2 obsoletas ---
def find_outdated_ec2_instances(ec2_client, region):
    outdated_instances = []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]):
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_type = instance.get('InstanceType', '')
                    instance_family = instance_type.split('.')[0]
                    if instance_family in OUTDATED_INSTANCE_FAMILIES:
                        recommendation = "N/A"
                        if instance_family == 't2': recommendation = "Upgrade to t3/t4g"
                        elif instance_family in ['m4', 'm3']: recommendation = "Upgrade to m6i/m6g"
                        elif instance_family in ['c4', 'c3']: recommendation = "Upgrade to c6i/c6g"
                        elif instance_family in ['r4', 'r3']: recommendation = "Upgrade to r6i/r6g"
                        
                        outdated_instances.append({
                            'InstanceId': instance.get('InstanceId'),
                            'Region': region,
                            'InstanceType': instance_type,
                            'Recommendation': recommendation,
                            'EstimatedSavings': "Up to 20% savings with better performance"
                        })
    except ClientError as e:
        print(f"[FinOps Collector] Error buscando instancias EC2 en {region}: {e}")
    return outdated_instances

# --- NUEVA FUNCIÓN: Encontrar volúmenes EBS gp2 ---
def find_gp2_ebs_volumes(ec2_client, region):
    gp2_volumes = []
    try:
        paginator = ec2_client.get_paginator('describe_volumes')
        for page in paginator.paginate(Filters=[{'Name': 'volume-type', 'Values': ['gp2']}]):
            for vol in page.get('Volumes', []):
                details = {
                    'VolumeId': vol['VolumeId'],
                    'Region': region,
                    'Size': vol['Size'],
                    'Recommendation': "Migrate to gp3 for ~20% lower cost and better performance",
                }
                details['EstimatedMonthlySavings'] = _estimate_monthly_cost('ebs_gp2_saving', details)
                gp2_volumes.append(details)
    except ClientError as e:
        print(f"[FinOps Collector] Error buscando volúmenes gp2 en {region}: {e}")
    return gp2_volumes

# --- NUEVA FUNCIÓN: Encontrar oportunidades en S3 ---
def find_s3_optimization_opportunities(s3_client):
    s3_opportunities = []
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            try:
                # Si no tiene reglas de ciclo de vida, es un candidato
                s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    s3_opportunities.append({
                        'BucketName': bucket_name,
                        'Recommendation': "Enable S3 Intelligent-Tiering via a lifecycle policy for automatic savings on objects with changing access patterns.",
                        'EstimatedSavings': "Varies"
                    })
    except ClientError as e:
        print(f"[FinOps Collector] Error listando buckets de S3: {e}")
    return s3_opportunities

def collect_finops_data(session):
    """
    Colecta datos de recursos potencialmente desperdiciados y oportunidades
    de modernización para el análisis FinOps.
    """
    all_regions = get_all_aws_regions(session)
    
    # Listas para "Identificación de Desperdicio"
    unattached_volumes = []
    unassociated_eips = []
    idle_load_balancers = []
    
    # Listas para "Modernización y Eficiencia"
    outdated_instances = []
    gp2_volumes = []

    for region in all_regions:
        try:
            print(f"[FinOps Collector] Analizando región: {region}")
            ec2_client = session.client('ec2', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)

            # --- 1. Búsquedas de "Identificación de Desperdicio" ---

            # 1a. Buscar Volúmenes EBS sin adjuntar (estado 'available')
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

            # 1b. Buscar IPs Elásticas no asociadas
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

            # 1c. Buscar Load Balancers (v2) inactivos
            paginator_lb = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator_lb.paginate():
                for lb in page.get('LoadBalancers', []):
                    target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                    is_idle = True
                    if not target_groups.get('TargetGroups', []):
                        is_idle = True
                    else:
                        is_idle = True
                        for tg in target_groups['TargetGroups']:
                            health = elbv2_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                            if health.get('TargetHealthDescriptions', []):
                                is_idle = False
                                break
                    
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
            
            # --- 2. Búsquedas de "Modernización y Eficiencia" ---

            outdated_instances.extend(find_outdated_ec2_instances(ec2_client, region))
            gp2_volumes.extend(find_gp2_ebs_volumes(ec2_client, region))

        except ClientError as e:
            if "OptInRequired" in str(e):
                print(f"[FinOps Collector] Saltando región no habilitada: {region}")
            else:
                print(f"[FinOps Collector] Error en la región {region}: {e}")
            continue

    # --- 3. Búsqueda de S3 (es global, se hace fuera del bucle de regiones) ---
    s3_client = session.client('s3')
    s3_opportunities = find_s3_optimization_opportunities(s3_client)

    return {
        # Resultados de "Desperdicio"
        "unattached_volumes": unattached_volumes,
        "unassociated_eips": unassociated_eips,
        "idle_load_balancers": idle_load_balancers,
        # Resultados de "Modernización"
        "outdated_instances": outdated_instances,
        "gp2_volumes": gp2_volumes,
        "s3_opportunities": s3_opportunities
    }