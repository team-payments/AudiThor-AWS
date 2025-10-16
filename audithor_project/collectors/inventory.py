# collectors/inventory.py
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions
from concurrent.futures import ThreadPoolExecutor

def count_resources_in_region(session, region):
    """Cuenta recursos principales en una sola región."""
    counts = {
        'ec2_instances': 0, 'rds_instances': 0,
        'load_balancers': 0, 'lambda_functions': 0,
    }
    try:
        print(f"[Inventory] Counting resources in {region}...")
        # EC2
        ec2 = session.client('ec2', region_name=region)
        paginator_ec2 = ec2.get_paginator('describe_instances')
        for page in paginator_ec2.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}]):
            counts['ec2_instances'] += sum(len(r.get('Instances', [])) for r in page.get('Reservations', []))

        # RDS
        rds = session.client('rds', region_name=region)
        paginator_rds = rds.get_paginator('describe_db_instances')
        for page in paginator_rds.paginate():
            counts['rds_instances'] += len(page.get('DBInstances', []))

        # Load Balancers (v2)
        elbv2 = session.client('elbv2', region_name=region)
        paginator_lb = elbv2.get_paginator('describe_load_balancers')
        for page in paginator_lb.paginate():
            counts['load_balancers'] += len(page.get('LoadBalancers', []))

        # Lambda
        lambda_client = session.client('lambda', region_name=region)
        paginator_lambda = lambda_client.get_paginator('list_functions')
        for page in paginator_lambda.paginate():
            counts['lambda_functions'] += len(page.get('Functions', []))
            
    except ClientError as e:
        if "OptInRequired" not in str(e):
            print(f"[Inventory] Error in region {region}: {e}")
    return counts

def collect_inventory_summary(session):
    """
    Realiza un recuento de alto nivel de los recursos de AWS en todas las regiones.
    """
    summary = {
        'ec2_instances': 0, 'rds_instances': 0,
        's3_buckets': 0, 'load_balancers': 0,
        'lambda_functions': 0, 'iam_users': 0,
        'iam_roles': 0, 'iam_policies': 0,
    }

    # Recursos Globales (IAM y S3)
    try:
        print("[Inventory] Counting global resources...")
        # S3
        s3 = session.client('s3')
        summary['s3_buckets'] = len(s3.list_buckets().get('Buckets', []))

        # IAM
        iam = session.client('iam')
        summary['iam_users'] = len(iam.list_users().get('Users', []))
        summary['iam_roles'] = len(iam.list_roles().get('Roles', []))
        summary['iam_policies'] = len(iam.list_policies(Scope='Local').get('Policies', [])) # Solo políticas custom
    except ClientError as e:
        print(f"[Inventory] Error counting global resources: {e}")

    # Recursos Regionales (en paralelo para mayor velocidad)
    all_regions = get_all_aws_regions(session)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(count_resources_in_region, session, region) for region in all_regions]
        for future in futures:
            regional_counts = future.result()
            for key, value in regional_counts.items():
                summary[key] += value
    
    # Convertir el diccionario a un formato de lista para la tabla del frontend
    table_data = [
        {"Resource": "EC2 Instances", "Count": summary['ec2_instances']},
        {"Resource": "RDS Instances", "Count": summary['rds_instances']},
        {"Resource": "S3 Buckets", "Count": summary['s3_buckets']},
        {"Resource": "Load Balancers (ALB/NLB)", "Count": summary['load_balancers']},
        {"Resource": "Lambda Functions", "Count": summary['lambda_functions']},
        {"Resource": "IAM Users", "Count": summary['iam_users']},
        {"Resource": "IAM Roles", "Count": summary['iam_roles']},
        {"Resource": "IAM Customer-Managed Policies", "Count": summary['iam_policies']},
    ]

    return {"summary_table": table_data}