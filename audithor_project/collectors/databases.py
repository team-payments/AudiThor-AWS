# collectors/databases.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_database_data(session):
    """
    Collects data on AWS database services, including detailed encryption info.

    This function scans all accessible AWS regions for RDS instances, Aurora
    clusters, DynamoDB tables, and DocumentDB clusters. A key feature is that
    it also queries KMS in each region to create a map of KMS Key IDs to their
    human-readable aliases. This map is then used to enrich the database
    information, showing the specific key alias used for encryption.

    Args:
        session (boto3.Session): The Boto3 session object for AWS 
                                 authentication and to discover all regions.

    Returns:
        dict: A dictionary containing lists of database resources, structured as:
              {
                  "rds_instances": [...],
                  "aurora_clusters": [...],
                  "dynamodb_tables": [...],
                  "documentdb_clusters": [...]
              }

    Example:
        >>> import boto3
        >>>
        >>> # This assumes 'get_all_aws_regions' is available
        >>> aws_session = boto3.Session(profile_name='my-aws-profile')
        >>> all_databases = collect_database_data(aws_session)
        >>> print(f"Found {len(all_databases['aurora_clusters'])} Aurora clusters.")
    """
    rds_instances = []
    aurora_clusters = []
    dynamodb_tables = []
    documentdb_clusters = []
    
    try:
        # Prefer getting regions where the service is known to be available
        regions = session.get_available_regions("rds")
    except ClientError:
        # Fallback to a general region discovery if specific lookup fails
        regions = get_all_aws_regions(session)

    for region in regions:
        try:
            rds_client = session.client("rds", region_name=region)
            dynamodb_client = session.client("dynamodb", region_name=region)
            docdb_client = session.client("docdb", region_name=region)
            kms_client = session.client("kms", region_name=region)

            # --- 1. Create a map of KMS Key IDs to Aliases for the current region ---
            alias_map = {}
            try:
                paginator = kms_client.get_paginator('list_aliases')
                for page in paginator.paginate():
                    for alias in page.get('Aliases', []):
                        # Map the target key ID to the first non-default alias found
                        alias_name = alias.get('AliasName')
                        if alias.get('TargetKeyId') and not alias_name.startswith('alias/aws/'):
                            alias_map[alias['TargetKeyId']] = alias_name
            except ClientError:
                # Ignore if KMS is not accessible (e.g., permissions, disabled region)
                pass

            # --- 2. Collect Aurora Clusters ---
            aurora_paginator = rds_client.get_paginator("describe_db_clusters")
            for page in aurora_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    if "aurora" in cluster.get("Engine", ""):
                        kms_key_id = cluster.get("KmsKeyId")
                        key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                        aurora_clusters.append({
                            "Region": region,
                            "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                            "Engine": cluster.get("Engine"),
                            "Status": cluster.get("Status"),
                            "Endpoint": cluster.get("Endpoint", "N/A"),
                            "Encrypted": cluster.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                            "ARN": cluster.get("DBClusterArn")
                        })
            
            # --- 3. Collect RDS Instances (standalone only) ---
            rds_paginator = rds_client.get_paginator("describe_db_instances")
            for page in rds_paginator.paginate():
                for instance in page.get("DBInstances", []):
                    if not instance.get("DBClusterIdentifier"): # Exclude Aurora instances
                        kms_key_id = instance.get("KmsKeyId")
                        key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                        rds_instances.append({
                            "Region": region,
                            "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                            "DBInstanceClass": instance.get("DBInstanceClass"),
                            "Engine": instance.get("Engine"),
                            "DBInstanceStatus": instance.get("DBInstanceStatus"),
                            "PubliclyAccessible": instance.get('PubliclyAccessible', False),
                            "Endpoint": instance.get("Endpoint", {}).get("Address", "N/A"),
                            "Encrypted": instance.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                            "ARN": instance.get("DBInstanceArn")
                        })

            # --- 4. Collect DynamoDB Tables ---
            dynamo_paginator = dynamodb_client.get_paginator("list_tables")
            for page in dynamo_paginator.paginate():
                for table_name in page.get("TableNames", []):
                    details = dynamodb_client.describe_table(TableName=table_name).get("Table", {})
                    sse_details = details.get("SSEDescription")
                    kms_key_arn = sse_details.get("KMSMasterKeyArn") if sse_details else None
                    key_id_for_lookup = kms_key_arn.split('/')[-1] if kms_key_arn else None
                    
                    alias = "N/A"
                    if sse_details and sse_details.get("Status") == "ENABLED":
                        alias = alias_map.get(key_id_for_lookup, kms_key_arn or "AWS Owned Key")

                    dynamodb_tables.append({
                        "Region": region,
                        "TableName": table_name,
                        "Status": details.get("TableStatus"),
                        "ItemCount": details.get("ItemCount", 0),
                        "SizeBytes": details.get("TableSizeBytes", 0),
                        "Encrypted": bool(sse_details and sse_details.get("Status") == "ENABLED"),
                        "KmsKeyId": key_id_for_lookup,
                        "KmsKeyAlias": alias,
                        "ARN": details.get("TableArn")
                    })

            # --- 5. Collect DocumentDB Clusters ---
            docdb_paginator = docdb_client.get_paginator("describe_db_clusters")
            for page in docdb_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    kms_key_id = cluster.get("KmsKeyId")
                    key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                    documentdb_clusters.append({
                        "Region": region,
                        "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                        "Engine": cluster.get("Engine"),
                        "Status": cluster.get("Status"),
                        "Endpoint": cluster.get("Endpoint", "N/A"),
                        "Encrypted": cluster.get("StorageEncrypted", False),
                        "KmsKeyId": kms_key_id,
                        "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                        "ARN": cluster.get("DBClusterArn")
                    })

        except ClientError as e:
            # Suppress common errors for disabled/inaccessible regions but log others
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] not in common_errors:
                print(f"Error processing databases in region {region}: {e}")
            continue
    
    return {
        "rds_instances": rds_instances,
        "aurora_clusters": aurora_clusters,
        "dynamodb_tables": dynamodb_tables,
        "documentdb_clusters": documentdb_clusters
    }

