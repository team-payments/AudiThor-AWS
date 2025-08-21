# collectors/kms.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_kms_data(session):
    """
    Busca claves de KMS en todas las regiones y recopila información relevante.
    Adaptado del script kms.py.
    """
    all_regions = get_all_aws_regions(session)
    result_kms_keys = []

    for region in all_regions:
        try:
            kms_client = session.client("kms", region_name=region)

            alias_map = {}
            aliases_paginator = kms_client.get_paginator("list_aliases")
            for page in aliases_paginator.paginate():
                for alias in page.get("Aliases", []):
                    if 'TargetKeyId' in alias:
                        key_id = alias['TargetKeyId']
                        if key_id not in alias_map:
                            alias_map[key_id] = []
                        alias_map[key_id].append(alias['AliasName'])

            keys_paginator = kms_client.get_paginator("list_keys")
            for page in keys_paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key['KeyId']
                    desc = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
                    
                    rotation_enabled = "N/A"
                    if desc.get('KeyManager') == 'CUSTOMER' and desc.get('KeySpec') == 'SYMMETRIC_DEFAULT':
                        try:
                            status = kms_client.get_key_rotation_status(KeyId=key_id)
                            rotation_enabled = "Enabled" if status.get('KeyRotationEnabled') else "Disabled"
                        except ClientError:
                            rotation_enabled = "Not Supported"
                    
                    policy_doc = "Could not retrieve"
                    try:
                        policy_str = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
                        policy_doc = json.loads(policy_str)
                    except (ClientError, json.JSONDecodeError):
                        pass

                    result_kms_keys.append({
                        "Region": region,
                        "KeyId": key_id,
                        "ARN": desc.get('Arn'),
                        "Aliases": ", ".join(alias_map.get(key_id, ["Without Alias"])),
                        "Status": desc.get('KeyState'),
                        "Origin": desc.get('Origin'),
                        "KeyManager": desc.get('KeyManager'),
                        "RotationEnabled": rotation_enabled,
                        "Policy": policy_doc,
                    })
        except ClientError as e:
            # Ignorar errores comunes de regiones no activas
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
            
    return {"keys": result_kms_keys}

