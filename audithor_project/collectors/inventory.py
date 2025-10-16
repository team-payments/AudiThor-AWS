# collectors/inventory.py
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions
from concurrent.futures import ThreadPoolExecutor

def count_resources_in_region(session, region):
    """Cuenta recursos principales en una sola región."""
    # CORRECCIÓN: Se añaden los contadores para vpcs y dynamodb_tables
    counts = {
        'ec2_instances': 0, 'rds_instances': 0,
        'load_balancers': 0, 'lambda_functions': 0,
        'vpcs': 0, 'dynamodb_tables': 0,
    }
    try:
        print(f"[Inventory] Counting resources in {region}...")
        ec2 = session.client('ec2', region_name=region)
        
        # EC2
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
        
        # VPCs
        paginator_vpc = ec2.get_paginator('describe_vpcs')
        for page in paginator_vpc.paginate():
            counts['vpcs'] += len(page.get('Vpcs', []))

        # DynamoDB Tables
        dynamodb = session.client('dynamodb', region_name=region)
        paginator_dynamo = dynamodb.get_paginator('list_tables')
        for page in paginator_dynamo.paginate():
            counts['dynamodb_tables'] += len(page.get('TableNames', []))
            
    except ClientError as e:
        if "OptInRequired" not in str(e) and "AccessDenied" not in str(e):
            print(f"[Inventory] Error in region {region}: {e}")
    return (region, counts)

def collect_inventory_summary(session):
    """
    Realiza un recuento de alto nivel de los recursos de AWS, agrupados por región.
    """
    # Nueva estructura para almacenar totales y desglose por región
    summary = {
        'ec2_instances': {'total': 0, 'by_region': {}},
        'rds_instances': {'total': 0, 'by_region': {}},
        's3_buckets': {'total': 0, 'by_region': {}}, # S3 es global, pero mantenemos la estructura
        'load_balancers': {'total': 0, 'by_region': {}},
        'lambda_functions': {'total': 0, 'by_region': {}},
        'iam_users': {'total': 0, 'by_region': {}},
        'iam_roles': {'total': 0, 'by_region': {}},
        'iam_policies': {'total': 0, 'by_region': {}},
        'vpcs': {'total': 0, 'by_region': {}},
        'dynamodb_tables': {'total': 0, 'by_region': {}},
        'route53_hosted_zones': {'total': 0, 'by_region': {}}, # Es global
    }

    # Recursos Globales (IAM y S3)
    try:
        print("[Inventory] Counting global resources...")
        s3 = session.client('s3')
        s3_count = len(s3.list_buckets().get('Buckets', []))
        summary['s3_buckets']['total'] = s3_count
        summary['s3_buckets']['by_region']['Global'] = s3_count

        iam = session.client('iam')
        iam_users_count = len(iam.list_users().get('Users', []))
        iam_roles_count = len(iam.list_roles().get('Roles', []))
        iam_policies_count = len(iam.list_policies(Scope='Local').get('Policies', []))
        
        summary['iam_users']['total'] = iam_users_count
        summary['iam_users']['by_region']['Global'] = iam_users_count
        summary['iam_roles']['total'] = iam_roles_count
        summary['iam_roles']['by_region']['Global'] = iam_roles_count
        summary['iam_policies']['total'] = iam_policies_count
        summary['iam_policies']['by_region']['Global'] = iam_policies_count

        route53 = session.client('route53')
        paginator_r53 = route53.get_paginator('list_hosted_zones')
        r53_count = 0
        for page in paginator_r53.paginate():
            r53_count += len(page.get('HostedZones', []))
        summary['route53_hosted_zones']['total'] = r53_count
        summary['route53_hosted_zones']['by_region']['Global'] = r53_count

    except ClientError as e:
        print(f"[Inventory] Error counting global resources: {e}")

    # Recursos Regionales (en paralelo)
    all_regions = get_all_aws_regions(session)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(count_resources_in_region, session, region): region for region in all_regions}
        for future in futures:
            region_name = futures[future]
            try:
                _region, regional_counts = future.result()
                for key, value in regional_counts.items():
                    if value > 0:
                        summary[key]['total'] += value
                        summary[key]['by_region'][region_name] = value
            except Exception as exc:
                print(f'[Inventory] Region {region_name} generated an exception: {exc}')

    return summary # Devolvemos la estructura completa al frontend