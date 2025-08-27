# collectors/compute.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


# collectors/compute.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa
from . import iam # Se importa para la comprobación de permisos de roles

def collect_compute_data(session):
    """
    Gathers data on key AWS compute resources across all available regions.

    This function scans every AWS region to collect detailed information about
    EC2 instances (including their VPC ID and IAM Instance Profile), 
    Lambda functions (including their tags and execution role), EKS clusters, and ECS clusters.

    Args:
        session (boto3.Session): The Boto3 session object used for AWS 
                                 authentication and to discover all regions.

    Returns:
        dict: A dictionary containing lists of collected resources.
    """
    result_ec2_instances = []
    result_lambda_functions = []
    result_eks_clusters = []
    result_ecs_clusters = []
    
    regions = get_all_aws_regions(session)
    account_id = session.client("sts").get_caller_identity()["Account"]

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            lambda_client = session.client("lambda", region_name=region)
            eks_client = session.client("eks", region_name=region)
            ecs_client = session.client("ecs", region_name=region)

            # --- 1. Collect EC2 Instance Data ---
            ec2_paginator = ec2_client.get_paginator('describe_instances')
            instance_filters = [{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}]
            
            for page in ec2_paginator.paginate(Filters=instance_filters):
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        tags_dict = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        instance_id = instance.get("InstanceId")
                        
                        iam_profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")
                        iam_profile_name = iam_profile_arn.split('/')[-1] if iam_profile_arn else "N/A"
                        
                        os_info = "N/A"
                        image_id = instance.get("ImageId")
                        if image_id:
                            try:
                                ami_details = ec2_client.describe_images(ImageIds=[image_id])
                                if ami_details.get("Images"):
                                    os_info = ami_details["Images"][0].get("Name", "N/A")
                            except ClientError:
                                os_info = "Information not available"

                        result_ec2_instances.append({
                            "Region": region,
                            "InstanceId": instance_id,
                            "VpcId": instance.get("VpcId"),
                            "InstanceType": instance.get("InstanceType"),
                            "State": instance.get("State", {}).get("Name"),
                            "PublicIpAddress": instance.get("PublicIpAddress", "N/A"),
                            "SubnetId": instance.get("SubnetId"),
                            "SecurityGroups": [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                            "IamInstanceProfile": iam_profile_name,
                            "OperatingSystem": os_info,
                            "Tags": tags_dict,
                            "ARN": f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                        })

            # --- 2. Collect Lambda Function Data ---
            lambda_paginator = lambda_client.get_paginator("list_functions")
            for page in lambda_paginator.paginate():
                for function in page.get("Functions", []):
                    function_arn = function.get("FunctionArn")
                    
                    tags_dict = {}
                    try:
                        tags_response = lambda_client.list_tags(Resource=function_arn)
                        tags_dict = tags_response.get("Tags", {})
                    except ClientError:
                        pass
                    
                    vpc_config = function.get("VpcConfig", {})
                    result_lambda_functions.append({
                        "Region": region,
                        "FunctionName": function.get("FunctionName"),
                        "Role": function.get("Role"), # <-- CAMPO AÑADIDO
                        "Runtime": function.get("Runtime"),
                        "MemorySize": function.get("MemorySize"),
                        "Timeout": function.get("Timeout"),
                        "LastModified": str(function.get("LastModified")),
                        "VpcConfig": {
                            "VpcId": vpc_config.get("VpcId"),
                            "SubnetIds": vpc_config.get("SubnetIds", []),
                            "SecurityGroupIds": vpc_config.get("SecurityGroupIds", [])
                        },
                        "Tags": tags_dict,
                        "ARN": function_arn
                    })

            # --- 3. Collect EKS Cluster Data ---
            eks_clusters = eks_client.list_clusters().get("clusters", [])
            for cluster_name in eks_clusters:
                result_eks_clusters.append({
                    "Region": region,
                    "ClusterName": cluster_name,
                    "ARN": f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}"
                })

            # --- 4. Collect ECS Cluster Data ---
            ecs_clusters_arns = ecs_client.list_clusters().get("clusterArns", [])
            if ecs_clusters_arns:
                clusters_details = ecs_client.describe_clusters(clusters=ecs_clusters_arns).get("clusters", [])
                for cluster in clusters_details:
                    services = ecs_client.list_services(cluster=cluster.get("clusterName")).get("serviceArns", [])
                    result_ecs_clusters.append({
                        "Region": region,
                        "ClusterName": cluster.get("clusterName"),
                        "Status": cluster.get("status"),
                        "ServicesCount": len(services),
                        "ARN": cluster.get("clusterArn")
                    })

        except ClientError as e:
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException']
            if e.response['Error']['Code'] not in common_errors:
                print(f"Error processing region {region}: {e}")
            continue
    
    return {
        "ec2_instances": result_ec2_instances,
        "lambda_functions": result_lambda_functions,
        "eks_clusters": result_eks_clusters,
        "ecs_clusters": result_ecs_clusters
    }