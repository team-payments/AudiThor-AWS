# collectors/iam.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_iam_data(session):
    client = session.client("iam")
    result_users, password_policy, result_roles, result_groups = [], {}, [], []
    users = client.list_users()["Users"]
    for user in users:
        username = user["UserName"]
        user_data = { "UserName": username, "CreateDate": str(user.get("CreateDate")), "PasswordEnabled": False, "PasswordLastUsed": str(user.get("PasswordLastUsed")) if user.get("PasswordLastUsed") else "N/A", "MFADevices": [m["SerialNumber"] for m in client.list_mfa_devices(UserName=username)["MFADevices"]], "AccessKeys": [], "Groups": [g["GroupName"] for g in client.list_groups_for_user(UserName=username)["Groups"]], "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_user_policies(UserName=username)["AttachedPolicies"]], "InlinePolicies": client.list_user_policies(UserName=username)["PolicyNames"], "Roles": [], "IsPrivileged": False, "PrivilegeReasons": [] }
        try:
            client.get_login_profile(UserName=username)
            user_data["PasswordEnabled"] = True
        except client.exceptions.NoSuchEntityException: pass
        for key in client.list_access_keys(UserName=username)["AccessKeyMetadata"]:
            last_used_info = client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
            user_data["AccessKeys"].append({"AccessKeyId": key["AccessKeyId"], "Status": key["Status"], "CreateDate": str(key["CreateDate"]), "LastUsedDate": str(last_used_info.get("LastUsedDate")) if last_used_info.get("LastUsedDate") else "N/A"})
        try:
            for tag in client.list_user_tags(UserName=username)["Tags"]:
                if tag['Key'].lower() == 'role': user_data["Roles"].append(tag['Value'])
        except client.exceptions.NoSuchEntityException: pass
        result_users.append(user_data)
    try:
        password_policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        password_policy = {"Error": "No password policy configured"}
    for role in client.list_roles()["Roles"]:
        result_roles.append({ "RoleName": role["RoleName"], "CreateDate": str(role["CreateDate"]), "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]], "InlinePolicies": client.list_role_policies(RoleName=role["RoleName"])["PolicyNames"], "IsPrivileged": False, "PrivilegeReasons": [] })
    for group in client.list_groups()["Groups"]:
        result_groups.append({ "GroupName": group["GroupName"], "CreateDate": str(group["CreateDate"]), "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]], "IsPrivileged": False, "PrivilegeReasons": [] })
    detectar_privilegios(result_users, result_roles, result_groups, session)
    return {"users": result_users, "roles": result_roles, "groups": result_groups, "password_policy": password_policy}

def collect_identity_center_data(session):
    """
    Recopila datos de AWS Identity Center con logs de depuración.
    """
    try:
        all_regions = get_all_aws_regions(session)
        instance_arn = None
        identity_store_id = None
        found_region = None

        for region in all_regions:
            try:
                regional_sso_client = session.client("sso-admin", region_name=region)
                instances = regional_sso_client.list_instances().get("Instances", [])
                if instances:
                    instance_arn = instances[0]['InstanceArn']
                    identity_store_id = instances[0]['IdentityStoreId']
                    found_region = region
                    break 
            except ClientError as e:
                
                continue
        
        if not instance_arn:
            return {"status": "Not found", "message": "No active AWS Identity Center instances were found in any region."}

        # A partir de aquí, solo se ejecuta si se encontró una instancia
        sso_admin_client = session.client("sso-admin", region_name=found_region)
        identity_client = session.client("identitystore", region_name=found_region)
        
        group_map = {}
        paginator_groups = identity_client.get_paginator('list_groups')
        for page in paginator_groups.paginate(IdentityStoreId=identity_store_id):
            for group in page.get("Groups", []):
                group_map[group['GroupId']] = group['DisplayName']
        ps_map = {}
        paginator_ps = sso_admin_client.get_paginator('list_permission_sets')
        for page in paginator_ps.paginate(InstanceArn=instance_arn):
            for ps_arn in page.get("PermissionSets", []):
                details = sso_admin_client.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)
                ps_map[ps_arn] = details.get("PermissionSet", {}).get("Name", "Unknown")
        
        privileged_ps_names = ["AWSAdministratorAccess", "AdministratorAccess", "AWSPowerUserAccess", "PowerUserAccess"]
        
        assignments = []
        paginator_accounts = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')

        for ps_arn, ps_name in ps_map.items():
            for page in paginator_accounts.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for account_id in page.get("AccountIds", []):
                    paginator_assignments = sso_admin_client.get_paginator('list_account_assignments')
                    for assign_page in paginator_assignments.paginate(InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn):
                        for assignment in assign_page.get("AccountAssignments", []):
                            if assignment.get("PrincipalType") == "GROUP":
                                group_id = assignment.get("PrincipalId")
                                assignments.append({
                                    "AccountId": account_id,
                                    "PermissionSetArn": ps_arn,
                                    "PermissionSetName": ps_name,
                                    "GroupId": group_id,
                                    "GroupName": group_map.get(group_id, "Unknown Group"),
                                    "IsPrivileged": ps_name in privileged_ps_names
                                })
        final_result = {
            "status": "Found",
            "instance_arn": instance_arn,
            "identity_store_id": identity_store_id,
            "assignments": sorted(assignments, key=lambda x: (x['GroupName'], x['PermissionSetName']))
        }
        return final_result

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             return {"status": "Error", "message": "Access denied. Permissions are required for 'sso-admin' and 'identitystore'."}
        return {"status": "Error", "message": f"Unexpected error while querying Identity Center: {str(e)}"}
    except Exception as e:
        return {"status": "General Error", "message": f"An unexpected error occurred in the function: {str(e)}"}

def detectar_privilegios(users, roles, groups, session):
    client = session.client("iam")
    politicas_peligrosas = [ "AdministratorAccess", "PowerUserAccess", "IAMFullAccess", "Billing", "OrganizationAccountAccessRole", "AWSCloudFormationFullAccess", "AmazonEC2FullAccess", "AWSLambda_FullAccess", "SecretsManagerReadWrite", "AWSKeyManagementServicePowerUser", "AmazonS3FullAccess", "AWSCloudTrail_FullAccess", "ServiceQuotasFullAccess" ]
    for user in users:
        evidencia = [f"Política adjunta: {p}" for p in user["AttachedPolicies"] if p in politicas_peligrosas]
        for group_name in user["Groups"]:
            try:
                group_policies = client.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
                evidencia.extend(f"Grupo '{group_name}': política {gp['PolicyName']}" for gp in group_policies if gp["PolicyName"] in politicas_peligrosas)
            except client.exceptions.NoSuchEntityException: continue
        if evidencia: user["IsPrivileged"], user["PrivilegeReasons"] = True, list(set(evidencia))
    for role in roles:
        evidencia = [f"Política adjunta: {p}" for p in role["AttachedPolicies"] if p in politicas_peligrosas]
        if evidencia: role["IsPrivileged"], role["PrivilegeReasons"] = True, list(set(evidencia))
    for group in groups:
        evidencia = [f"Política adjunta: {p}" for p in group["AttachedPolicies"] if p in politicas_peligrosas]
        if evidencia: group["IsPrivileged"], group["PrivilegeReasons"] = True, list(set(evidencia))

def check_critical_permissions(session, users):
    """
    Usa iam:SimulatePrincipalPolicy para verificar si los usuarios tienen permisos críticos 
    en varias categorías de servicios (Red, CloudTrail, Bases de Datos, WAF).
    """
    iam_client = session.client("iam")
    account_id = session.client("sts").get_caller_identity()["Account"]

    # --- Definición de Acciones Críticas por Categoría ---
    
    # 1. Acciones de Red
    network_actions = [
        "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute", "ec2:AssociateVpcCidrBlock",
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateNetworkAcl", "ec2:DeleteNetworkAcl", "ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry",
        "ec2:ReplaceNetworkAclEntry", "ec2:ReplaceNetworkAclAssociation"
    ]

    # 2. Acciones de CloudTrail
    cloudtrail_actions = [
        "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
        "cloudtrail:StartLogging", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"
    ]

    # 3. Acciones de Bases de Datos
    database_actions = [
        # RDS & Aurora
        "rds:CreateDBInstance", "rds:DeleteDBInstance", "rds:ModifyDBInstance", "rds:RebootDBInstance",
        "rds:CreateDBSnapshot", "rds:DeleteDBSnapshot", "rds:ModifyDBCluster", "rds:DeleteDBCluster",
        # DynamoDB
        "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable", "dynamodb:BatchWriteItem",
        "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem", "dynamodb:CreateBackup", "dynamodb:DeleteBackup"
    ]

    # 4. Acciones de WAF
    waf_actions = [
        "wafv2:CreateWebACL", "wafv2:DeleteWebACL", "wafv2:UpdateWebACL", "wafv2:AssociateWebACL",
        "wafv2:DisassociateWebACL", "wafv2:CreateIPSet", "wafv2:DeleteIPSet", "wafv2:UpdateIPSet"
    ]

    actions_map = {
        "network": network_actions,
        "cloudtrail": cloudtrail_actions,
        "database": database_actions,
        "waf": waf_actions
    }
    all_actions = network_actions + cloudtrail_actions + database_actions + waf_actions

    for user in users:
        user_arn = f"arn:aws:iam::{account_id}:user/{user['UserName']}"
        # Inicializamos un diccionario para guardar los permisos encontrados
        user["criticalPermissions"] = {
            "network": [],
            "cloudtrail": [],
            "database": [],
            "waf": []
        }

        try:
            response = iam_client.simulate_principal_policy(
                PolicySourceArn=user_arn,
                ActionNames=all_actions
            )

            # Clasificamos los permisos permitidos en su categoría correspondiente
            for result in response.get("EvaluationResults", []):
                if result["EvalDecision"] == "allowed":
                    action_name = result["EvalActionName"]
                    for category, action_list in actions_map.items():
                        if action_name in action_list:
                            user["criticalPermissions"][category].append(action_name)
                            break
                            
        except ClientError as e:
            print(f"Could not simulate the policy for {user['UserName']}: {e}")
            continue

    return users

def collect_federation_data(session):
    """
    Recopila información sobre la configuración de federación en la cuenta.
    MODIFICADO: Ahora también incluye datos de AWS Identity Center.
    """
    iam_client = session.client("iam")

    # --- Parte 1: Federación IAM (sin cambios) ---
    try:
        aliases = iam_client.list_account_aliases()['AccountAliases']
        account_alias = aliases[0] if aliases else None
    except ClientError:
        account_alias = None

    saml_providers = []
    try:
        response = iam_client.list_saml_providers()
        for provider in response.get('SAMLProviderList', []):
            saml_providers.append({
                "Arn": provider.get('Arn'),
                "CreateDate": provider.get('CreateDate').isoformat(),
                "ValidUntil": provider.get('ValidUntil').isoformat() if provider.get('ValidUntil') else 'N/A'
            })
    except ClientError: pass

    oidc_providers = []
    try:
        response = iam_client.list_open_id_connect_providers()
        for provider in response.get('OpenIDConnectProviderList', []):
             oidc_providers.append({"Arn": provider.get('Arn')})
    except ClientError: pass

    iam_federation_data = {
        "account_alias": account_alias,
        "saml_providers": saml_providers,
        "oidc_providers": oidc_providers
    }

    # --- Parte 2: AWS Identity Center (NUEVO) ---
    identity_center_data = collect_identity_center_data(session)

    # Devolvemos un diccionario con ambas secciones
    return {
        "iam_federation": iam_federation_data,
        "identity_center": identity_center_data
    }

def collect_access_analyzer_data(session):
    """
    Recopila los hallazgos y un resumen de los analizadores de Access Analyzer 
    de todas las regiones.
    """
    all_regions = get_all_aws_regions(session)
    findings_results = []
    analyzers_summary = [] # <-- 1. LISTA NUEVA para el resumen

    for region in all_regions:
        try:
            analyzer_client = session.client("accessanalyzer", region_name=region)
            paginator_analyzers = analyzer_client.get_paginator('list_analyzers')
            account_analyzer_arn = None
            
            for page in paginator_analyzers.paginate():
                for analyzer in page.get('analyzers', []):
                    # Añadimos CUALQUIER analizador activo al resumen
                    if analyzer.get('status') == 'ACTIVE':
                        analyzers_summary.append({
                            "Region": region,
                            "Name": analyzer.get('name'),
                            "Type": analyzer.get('type'),
                            "Arn": analyzer.get('arn')
                        })
                    
                    # Pero solo usamos los de acceso externo para buscar hallazgos
                    if analyzer.get('type') in ['ACCOUNT', 'ORGANIZATION'] and analyzer.get('status') == 'ACTIVE':
                        account_analyzer_arn = analyzer.get('arn')

            if not account_analyzer_arn:
                continue

            paginator_findings = analyzer_client.get_paginator('list_findings')
            for page in paginator_findings.paginate(
                analyzerArn=account_analyzer_arn,
                filter={'status': {'eq': ['ACTIVE']}}
            ):
                for finding in page.get('findings', []):
                    principal = finding.get('principal', {})
                    is_external = (finding.get('isPublic') or 
                                   'AWS' in principal or 
                                   'Federated' in principal)

                    if is_external:
                        principal_display = "Public"
                        if 'AWS' in principal:
                            principal_display = principal['AWS']
                        elif 'Federated' in principal:
                            principal_display = principal['Federated']

                        findings_results.append({
                            "Region": region,
                            "ResourceType": finding.get('resourceType'),
                            "Resource": finding.get('resource'),
                            "Principal": principal_display,
                            "IsPublic": finding.get('isPublic', False),
                            "Action": ", ".join(finding.get('action', ['N/A'])),
                            "AnalyzedAt": finding.get('analyzedAt').isoformat()
                        })
        except ClientError:
            continue
        except Exception:
            continue
            
    findings_results.sort(key=lambda x: (x['Region'], x['ResourceType'], x['Resource']))
    # --- ▼▼▼ 2. RETURN MODIFICADO ▼▼▼ ---
    return {"findings": findings_results, "summary": analyzers_summary}

def get_sso_group_members(session, group_id):
    """
    Obtiene los usernames de los miembros de un grupo específico de Identity Center.
    """
    all_regions = get_all_aws_regions(session)
    identity_store_id = None
    found_region = None

    # Primero, necesitamos encontrar la instancia de SSO para obtener el IdentityStoreId
    for region in all_regions:
        try:
            regional_sso_client = session.client("sso-admin", region_name=region)
            instances = regional_sso_client.list_instances().get("Instances", [])
            if instances:
                identity_store_id = instances[0]['IdentityStoreId']
                found_region = region
                break
        except ClientError:
            continue
    
    if not identity_store_id:
        raise Exception("Could not find an active AWS Identity Center instance.")

    # Ahora usamos el IdentityStoreId para buscar los miembros
    identity_client = session.client("identitystore", region_name=found_region)
    user_members = []
    
    paginator = identity_client.get_paginator('list_group_memberships')

    for page in paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_id):
        for member in page.get('GroupMemberships', []):
            user_id = member.get('MemberId', {}).get('UserId')
            if user_id:
                try:
                    user_details = identity_client.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=user_id
                    )
                    user_members.append(user_details.get('UserName', 'User not found'))
                except ClientError:
                    user_members.append(f"User (ID: {user_id}) - Access Denied to Details")

    return sorted(user_members)