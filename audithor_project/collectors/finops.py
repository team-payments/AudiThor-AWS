# collectors/finops.py
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions
import json
import os
from datetime import datetime, timedelta

# --- CONSTANTES DE CONFIGURACIÓN ---
CACHE_FILE = 'pricing_cache.json'
CACHE_EXPIRATION_DAYS = 30
OUTDATED_INSTANCE_FAMILIES = ['t2', 'm4', 'c4', 'r4', 't1', 'm3', 'c3', 'r3']

# --- LÓGICA DE PRECIOS DINÁMICOS Y CACHÉ ---

def get_aws_prices(session):
    """
    Se conecta a la API de Precios de AWS para obtener los costes actualizados.
    Utiliza valores por defecto si la API falla para no romper la aplicación.
    """
    pricing_client = session.client('pricing', region_name='us-east-1')
    # Precios por defecto en caso de que la API falle
    prices = {
        "ebs_gp2": 0.10, "ebs_gp3": 0.08,
        "eip_hourly": 0.005, "alb_hourly": 0.0225
    }

    def get_price_from_response(response):
        """Función anidada para extraer el precio de una respuesta de la API."""
        price_data = json.loads(response['PriceList'][0])
        ondemand_terms = list(price_data['terms']['OnDemand'].values())[0]
        price_dimension = list(ondemand_terms['priceDimensions'].values())[0]
        return float(price_dimension['pricePerUnit']['USD'])

    try:
        # 1. Precio de EBS gp3
        response_gp3 = pricing_client.get_products(
            ServiceCode='AmazonEC2',
            Filters=[
                {'Type': 'TERM_MATCH', 'Field': 'volumeApiName', 'Value': 'gp3'},
                {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': 'US East (N. Virginia)'}
            ]
        )
        if response_gp3['PriceList']:
            prices['ebs_gp3'] = get_price_from_response(response_gp3)
            print(f"[FinOps Price API] OK: EBS gp3 price = ${prices['ebs_gp3']}")

        # 2. Precio de EBS gp2
        response_gp2 = pricing_client.get_products(ServiceCode='AmazonEC2', Filters=[{'Type': 'TERM_MATCH', 'Field': 'volumeApiName', 'Value': 'gp2'},{'Type': 'TERM_MATCH', 'Field': 'location', 'Value': 'US East (N. Virginia)'}])
        if response_gp2['PriceList']:
            prices['ebs_gp2'] = get_price_from_response(response_gp2)
            print(f"[FinOps Price API] OK: EBS gp2 price = ${prices['ebs_gp2']}")
        
        # 3. Precio de EIP no asociada
        response_eip = pricing_client.get_products(ServiceCode='AmazonEC2', Filters=[{'Type': 'TERM_MATCH', 'Field': 'group', 'Value': 'Elastic IP - Idle'}, {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': 'US East (N. Virginia)'}])
        if response_eip['PriceList']:
            prices['eip_hourly'] = get_price_from_response(response_eip)
            print(f"[FinOps Price API] OK: EIP Hourly price = ${prices['eip_hourly']}")

        # 4. Precio de ALB
        response_alb = pricing_client.get_products(ServiceCode='AWSElasticLoadBalancing', Filters=[{'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Load Balancer-Application'}, {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': 'US East (N. Virginia)'}])
        if response_alb['PriceList']:
            prices['alb_hourly'] = get_price_from_response(response_alb)
            print(f"[FinOps Price API] OK: ALB Hourly price = ${prices['alb_hourly']}")

    except Exception as e:
        print(f"[FinOps Price API] WARNING: Could not fetch real-time prices from AWS API: {e}. Using default values.")

    return prices

def load_or_refresh_prices(session):
    """
    Carga los precios desde un fichero de caché local. Si la caché no existe
    o ha expirado, obtiene los precios nuevos desde la API de AWS.
    """
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                cache_data = json.load(f)
            last_updated = datetime.fromisoformat(cache_data['last_updated'])
            if datetime.now() - last_updated < timedelta(days=CACHE_EXPIRATION_DAYS):
                print("[FinOps Collector] Using prices from local cache.")
                return cache_data['prices']
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
             print(f"[FinOps Collector] WARNING: {CACHE_FILE} is corrupted or invalid. Refetching prices.")

    print(f"[FinOps Collector] Price cache not found or expired. Fetching from AWS Price List API...")
    prices = get_aws_prices(session)
    
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump({'last_updated': datetime.now().isoformat(), 'prices': prices}, f)
    except IOError as e:
        print(f"[FinOps Collector] ERROR: Could not write to cache file {CACHE_FILE}: {e}")
        
    return prices

def _estimate_monthly_cost(resource_type, details, prices):
    """Estima el coste mensual de un recurso usando los precios cargados dinámicamente."""
    hours_in_month = 730
    if resource_type == 'ebs':
        return details.get('Size', 0) * prices.get('ebs_gp3', 0.08)
    elif resource_type == 'ebs_gp2_saving':
        cost_gp2 = details.get('Size', 0) * prices.get('ebs_gp2', 0.10)
        cost_gp3 = details.get('Size', 0) * prices.get('ebs_gp3', 0.08)
        return cost_gp2 - cost_gp3
    elif resource_type == 'eip':
        return prices.get('eip_hourly', 0.005) * hours_in_month
    elif resource_type == 'lb':
        return prices.get('alb_hourly', 0.0225) * hours_in_month
    return 0

# --- FUNCIONES DE BÚSQUEDA DE RECURSOS ---

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
                            'InstanceId': instance.get('InstanceId'), 'Region': region,
                            'InstanceType': instance_type, 'Recommendation': recommendation,
                            'EstimatedSavings': "Up to 20% savings with better performance"
                        })
    except ClientError as e:
        print(f"[FinOps Collector] Error searching for EC2 instances in {region}: {e}")
    return outdated_instances

def find_gp2_ebs_volumes(ec2_client, region, prices):
    gp2_volumes = []
    try:
        paginator = ec2_client.get_paginator('describe_volumes')
        for page in paginator.paginate(Filters=[{'Name': 'volume-type', 'Values': ['gp2']}]):
            for vol in page.get('Volumes', []):
                details = {
                    'VolumeId': vol['VolumeId'], 'Region': region, 'Size': vol['Size'],
                    'Recommendation': "Migrate to gp3 for ~20% lower cost and better performance",
                }
                details['EstimatedMonthlySavings'] = _estimate_monthly_cost('ebs_gp2_saving', details, prices)
                gp2_volumes.append(details)
    except ClientError as e:
        print(f"[FinOps Collector] Error searching for gp2 volumes in {region}: {e}")
    return gp2_volumes

def find_s3_optimization_opportunities(s3_client):
    s3_opportunities = []
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets.get('Buckets', []):
            bucket_name = bucket['Name']
            try:
                s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    s3_opportunities.append({
                        'BucketName': bucket_name,
                        'Recommendation': "Enable S3 Intelligent-Tiering via a lifecycle policy for automatic savings on objects with changing access patterns.",
                        'EstimatedSavings': "Varies"
                    })
    except ClientError as e:
        print(f"[FinOps Collector] Error listing S3 buckets: {e}")
    return s3_opportunities

# --- FUNCIÓN PRINCIPAL ORQUESTADORA ---

def collect_finops_data(session):
    prices = load_or_refresh_prices(session)
    all_regions = get_all_aws_regions(session)
    
    unattached_volumes, unassociated_eips, idle_load_balancers = [], [], []
    outdated_instances, gp2_volumes = [], []

    for region in all_regions:
        try:
            print(f"[FinOps Collector] Analyzing region: {region}")
            ec2_client = session.client('ec2', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)

            # --- "Waste Identification" Scans ---
            paginator_vol = ec2_client.get_paginator('describe_volumes')
            for page in paginator_vol.paginate(Filters=[{'Name': 'status', 'Values': ['available']}]):
                for vol in page.get('Volumes', []):
                    details = {
                        'VolumeId': vol['VolumeId'], 'Region': region, 'Size': vol['Size'],
                        'VolumeType': vol['VolumeType'], 'CreateTime': vol['CreateTime'].isoformat()
                    }
                    details['EstimatedMonthlyCost'] = _estimate_monthly_cost('ebs', details, prices)
                    unattached_volumes.append(details)

            addresses = ec2_client.describe_addresses()
            for addr in addresses.get('Addresses', []):
                if 'AssociationId' not in addr:
                    details = {
                        'PublicIp': addr['PublicIp'], 'AllocationId': addr['AllocationId'],
                        'Region': region, 'Domain': addr['Domain']
                    }
                    details['EstimatedMonthlyCost'] = _estimate_monthly_cost('eip', details, prices)
                    unassociated_eips.append(details)

            paginator_lb = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator_lb.paginate():
                for lb in page.get('LoadBalancers', []):
                    target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                    is_idle = not any(
                        elbv2_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn']).get('TargetHealthDescriptions')
                        for tg in target_groups.get('TargetGroups', [])
                    )
                    if is_idle:
                        details = {
                            'LoadBalancerName': lb['LoadBalancerName'], 'LoadBalancerArn': lb['LoadBalancerArn'],
                            'Region': region, 'Type': lb['Type'], 'State': lb['State']['Code']
                        }
                        details['EstimatedMonthlyCost'] = _estimate_monthly_cost('lb', details, prices)
                        idle_load_balancers.append(details)
            
            # --- "Modernization & Efficiency" Scans ---
            outdated_instances.extend(find_outdated_ec2_instances(ec2_client, region))
            gp2_volumes.extend(find_gp2_ebs_volumes(ec2_client, region, prices))

        except ClientError as e:
            if "OptInRequired" in str(e):
                print(f"[FinOps Collector] Skipping non-enabled region: {region}")
            else:
                print(f"[FinOps Collector] Error in region {region}: {e}")
            continue

    s3_client = session.client('s3')
    s3_opportunities = find_s3_optimization_opportunities(s3_client)

    return {
        "unattached_volumes": unattached_volumes,
        "unassociated_eips": unassociated_eips,
        "idle_load_balancers": idle_load_balancers,
        "outdated_instances": outdated_instances,
        "gp2_volumes": gp2_volumes,
        "s3_opportunities": s3_opportunities
    }