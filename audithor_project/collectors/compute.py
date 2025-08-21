# collectors/compute.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_compute_data(session):

    regions = get_all_aws_regions(session)
    result_ec2_instances, result_lambda_functions, result_eks_clusters, result_ecs_clusters = [], [], [], []
    account_id = session.client("sts").get_caller_identity()["Account"]

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            lambda_client = session.client("lambda", region_name=region)
            eks_client = session.client("eks", region_name=region)
            ecs_client = session.client("ecs", region_name=region)

            ec2_paginator = ec2_client.get_paginator('describe_instances')
            for page in ec2_paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}]):
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        tags_dict = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        instance_id = instance.get("InstanceId")
                        
                        os_info = "N/A"
                        image_id = instance.get("ImageId")
                        if image_id:
                            try:
                                ami_details = ec2_client.describe_images(ImageIds=[image_id])
                                if ami_details.get("Images"):
                                    os_info = ami_details["Images"][0].get("Name", "N/A")
                            except ClientError:
                                os_info = "Information not available"
                        security_groups = [sg['GroupName'] for sg in instance.get('SecurityGroups', [])]
                        result_ec2_instances.append({
                            "Region": region, "InstanceId": instance_id,
                            "InstanceType": instance.get("InstanceType"), "State": instance.get("State", {}).get("Name"),
                            "PublicIpAddress": instance.get("PublicIpAddress", "N/A"), "Tags": tags_dict,
                            "OperatingSystem": os_info,
                            "ARN": f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                            "SubnetId": instance.get("SubnetId"),
                            "SecurityGroups": security_groups
                        })
            
            lambda_paginator = lambda_client.get_paginator("list_functions")
            for page in lambda_paginator.paginate():
                for function in page.get("Functions", []):
                    result_lambda_functions.append({
                        "Region": region, "FunctionName": function.get("FunctionName"),
                        "Runtime": function.get("Runtime"), "MemorySize": function.get("MemorySize"),
                        "Timeout": function.get("Timeout"), "LastModified": str(function.get("LastModified")),
                        "ARN": function.get("FunctionArn"),
                        "VpcConfig": function.get("VpcConfig", {})
                    })

            eks_clusters = eks_client.list_clusters().get("clusters", [])
            for cluster_name in eks_clusters:
                cluster_arn = f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}"
                result_eks_clusters.append({
                    "Region": region, "ClusterName": cluster_name,
                    "ARN": cluster_arn
                })

            ecs_clusters_arns = ecs_client.list_clusters().get("clusterArns", [])
            if ecs_clusters_arns:
                clusters_details = ecs_client.describe_clusters(clusters=ecs_clusters_arns).get("clusters", [])
                for cluster in clusters_details:
                    services = ecs_client.list_services(cluster=cluster.get("clusterName")).get("serviceArns", [])
                    result_ecs_clusters.append({
                        "Region": region, "ClusterName": cluster.get("clusterName"),
                        "Status": cluster.get("status"), "ServicesCount": len(services),
                        "ARN": cluster.get("clusterArn")
                    })
        except ClientError as e:
            if e.response['Error']['Code'] not in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException']:
                print(f"Error procesando la region {region}: {e}")
            continue
    
    return {
        "ec2_instances": result_ec2_instances, "lambda_functions": result_lambda_functions,
        "eks_clusters": result_eks_clusters, "ecs_clusters": result_ecs_clusters
    }

