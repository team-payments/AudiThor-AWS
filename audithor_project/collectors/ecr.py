# collectors/ecr.py
import json
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions

def collect_ecr_data(session):
    """
    Collects security-related details for all ECR repositories across all regions.

    This function iterates through each AWS region to gather information on ECR
    repositories. For each repository, it checks:
    - Image tag mutability status.
    - Image scanning configuration (scan on push).
    - Encryption settings (AES256 or KMS).
    - The repository policy, specifically checking for public access.
    - Any configured lifecycle policies.

    Args:
        session (boto3.Session): The Boto3 session object for AWS authentication.

    Returns:
        dict: A dictionary containing a single key, 'repositories', which holds a
              list of dictionaries, each representing an ECR repository with its
              security configurations.
    """
    all_repositories = []
    all_regions = get_all_aws_regions(session)

    for region in all_regions:
        try:
            ecr_client = session.client('ecr', region_name=region)
            paginator = ecr_client.get_paginator('describe_repositories')
            
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    repo_name = repo.get('repositoryName')
                    
                    # 1. Check for public access in the repository policy
                    is_public = False
                    policy_text = None
                    try:
                        policy_response = ecr_client.get_repository_policy(repositoryName=repo_name)
                        policy_text = json.loads(policy_response.get('policyText', '{}'))
                        statements = policy_text.get('Statement', [])
                        for stmt in statements:
                            if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                                is_public = True
                                break
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'RepositoryPolicyNotFoundException':
                            raise # Relaunch other errors
                    
                    # 2. Check for lifecycle policy
                    lifecycle_policy_text = None
                    try:
                        lifecycle_response = ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                        lifecycle_policy_text = json.loads(lifecycle_response.get('lifecyclePolicyText', '{}'))
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'LifecyclePolicyNotFoundException':
                            raise

                    all_repositories.append({
                        "Region": region,
                        "RepositoryName": repo_name,
                        "RepositoryArn": repo.get('repositoryArn'),
                        "ImageTagMutability": repo.get('imageTagMutability'),
                        "ScanOnPush": repo.get('imageScanningConfiguration', {}).get('scanOnPush', False),
                        "EncryptionType": repo.get('encryptionConfiguration', {}).get('encryptionType'),
                        "KmsKey": repo.get('encryptionConfiguration', {}).get('kmsKey'),
                        "IsPublic": is_public,
                        "Policy": policy_text,
                        "LifecyclePolicy": lifecycle_policy_text
                    })
        except ClientError:
            # Ignore regions where ECR might not be available or enabled
            continue
            
    return {"repositories": all_repositories}