# collectors/databases.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_database_data(session):
    rds_instances = []
    aurora_clusters = []
    dynamodb_tables = []
    documentdb_clusters = []
    
    try:
        regions = session.get_available_regions("rds")
    except ClientError:
        regions = get_all_aws_regions(session)

    for region in regions:
        try:
            rds_client = session.client("rds", region_name=region)
            dynamodb_client = session.client("dynamodb", region_name=region)
            docdb_client = session.client("docdb", region_name=region)
            # <-- MODIFICACIÓN: Creamos un cliente KMS para esta región
            kms_client = session.client("kms", region_name=region)

            # <-- MODIFICACIÓN: Obtenemos un mapa de Key ID -> Alias para la región actual
            alias_map = {}
            try:
                paginator = kms_client.get_paginator('list_aliases')
                for page in paginator.paginate():
                    for alias in page.get('Aliases', []):
                        if 'TargetKeyId' in alias:
                            # Un alias puede apuntar a una clave, guardamos el primero que encontremos
                            alias_name = alias['AliasName']
                            if not alias_name.startswith('alias/aws/'): # Excluimos las claves por defecto de AWS
                                alias_map[alias['TargetKeyId']] = alias_name
            except ClientError:
                pass # Ignorar si no hay permisos para KMS o el servicio no está disponible


            # 1. Clústeres Aurora
            aurora_paginator = rds_client.get_paginator("describe_db_clusters")
            for page in aurora_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    if "aurora" in cluster.get("Engine", ""):
                        kms_key_id = cluster.get("KmsKeyId")
                        aurora_clusters.append({
                            "Region": region,
                            "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                            "Engine": cluster.get("Engine"),
                            "Status": cluster.get("Status"),
                            "Endpoint": cluster.get("Endpoint", "N/A"),
                            "ARN": cluster.get("DBClusterArn"),
                            # <-- MODIFICACIÓN: Añadimos campos de cifrado
                            "Encrypted": cluster.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(kms_key_id.split('/')[-1] if kms_key_id else None, kms_key_id or "N/A")
                        })
            
            # 2. Instancias RDS (que no pertenezcan a un clúster de Aurora)
            rds_paginator = rds_client.get_paginator("describe_db_instances")
            for page in rds_paginator.paginate():
                for instance in page.get("DBInstances", []):
                    if not instance.get("DBClusterIdentifier"):
                        kms_key_id = instance.get("KmsKeyId")
                        rds_instances.append({
                            "Region": region,
                            "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                            "DBInstanceClass": instance.get("DBInstanceClass"),
                            "Engine": instance.get("Engine"),
                            "DBInstanceStatus": instance.get("DBInstanceStatus"),
                            "Endpoint": instance.get("Endpoint", {}).get("Address", "N/A"),
                            "ARN": instance.get("DBInstanceArn"),
                            "PubliclyAccessible": instance.get('PubliclyAccessible', False),
                            # <-- MODIFICACIÓN: Añadimos campos de cifrado
                            "Encrypted": instance.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(kms_key_id.split('/')[-1] if kms_key_id else None, kms_key_id or "N/A")
                        })

            # 3. Tablas de DynamoDB
            dynamo_paginator = dynamodb_client.get_paginator("list_tables")
            for page in dynamo_paginator.paginate():
                for table_name in page.get("TableNames", []):
                    table_details = dynamodb_client.describe_table(TableName=table_name).get("Table", {})
                    sse_details = table_details.get("SSEDescription")
                    kms_key_arn = sse_details.get("KMSMasterKeyArn") if sse_details else None
                    kms_key_id = kms_key_arn.split('/')[-1] if kms_key_arn else None
                    
                    dynamodb_tables.append({
                        "Region": region,
                        "TableName": table_name,
                        "Status": table_details.get("TableStatus"),
                        "ItemCount": table_details.get("ItemCount", 0),
                        "SizeBytes": table_details.get("TableSizeBytes", 0),
                        "ARN": table_details.get("TableArn"),
                        # <-- MODIFICACIÓN: Añadimos campos de cifrado
                        "Encrypted": bool(sse_details and sse_details.get("Status") == "ENABLED"),
                        "KmsKeyId": kms_key_id,
                        "KmsKeyAlias": alias_map.get(kms_key_id, kms_key_arn or "AWS Owned Key") if sse_details else "N/A"
                    })

            # 4. Clústeres de DocumentDB
            docdb_paginator = docdb_client.get_paginator("describe_db_clusters")
            for page in docdb_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    kms_key_id = cluster.get("KmsKeyId")
                    documentdb_clusters.append({
                        "Region": region,
                        "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                        "Engine": cluster.get("Engine"),
                        "Status": cluster.get("Status"),
                        "Endpoint": cluster.get("Endpoint", "N/A"),
                        "ARN": cluster.get("DBClusterArn"),
                        # <-- MODIFICACIÓN: Añadimos campos de cifrado
                        "Encrypted": cluster.get("StorageEncrypted", False),
                        "KmsKeyId": kms_key_id,
                        "KmsKeyAlias": alias_map.get(kms_key_id.split('/')[-1] if kms_key_id else None, kms_key_id or "N/A")
                    })

        except ClientError as e:
            if e.response['Error']['Code'] not in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                print(f"Error processing databases in the region {region}: {e}")
            continue
    
    return {
        "rds_instances": rds_instances,
        "aurora_clusters": aurora_clusters,
        "dynamodb_tables": dynamodb_tables,
        "documentdb_clusters": documentdb_clusters
    }

