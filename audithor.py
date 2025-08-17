from flask import Flask, request, jsonify, send_from_directory
from rules import RULES_TO_CHECK
from flask_cors import CORS
import boto3
import threading
import webbrowser
import json
from collections import defaultdict
from datetime import datetime, timedelta
import pytz
from botocore.exceptions import ClientError
import ipaddress
import socket
import re

# --- Configuración de la aplicación Flask ---
app = Flask(__name__)
CORS(app)

# --- Lógica Común ---
def get_session(data):
    try:
        access_key = data.get('access_key')
        secret_key = data.get('secret_key')
        session_token = data.get('session_token')
        if not access_key or not secret_key:
            return None, "Access Key o Secret Key no proporcionadas."
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        sts = session.client("sts")
        sts.get_caller_identity()
        return session, None
    except Exception as e:
        return None, f"Error al validar credenciales de AWS: {str(e)}"

def get_all_aws_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [region['RegionName'] for region in ec2.describe_regions()['Regions']]

# --- Lógica para IAM ---
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
        password_policy = {"Error": "No password policy configurada"}
    for role in client.list_roles()["Roles"]:
        result_roles.append({ "RoleName": role["RoleName"], "CreateDate": str(role["CreateDate"]), "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]], "InlinePolicies": client.list_role_policies(RoleName=role["RoleName"])["PolicyNames"], "IsPrivileged": False, "PrivilegeReasons": [] })
    for group in client.list_groups()["Groups"]:
        result_groups.append({ "GroupName": group["GroupName"], "CreateDate": str(group["CreateDate"]), "AttachedPolicies": [p["PolicyName"] for p in client.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]], "IsPrivileged": False, "PrivilegeReasons": [] })
    detectar_privilegios(result_users, result_roles, result_groups, session)
    return {"users": result_users, "roles": result_roles, "groups": result_groups, "password_policy": password_policy}

def collect_identity_center_data(session):
    """
    Recopila datos de AWS Identity Center, buscando primero la instancia en todas las regiones.
    """
    try:
        # --- INICIO DE LA MODIFICACIÓN ---
        
        # OBTENEMOS TODAS LAS REGIONES DE AWS
        # Reutilizamos la función que ya tienes para obtener la lista de regiones.
        all_regions = get_all_aws_regions(session)
        
        instance_arn = None
        identity_store_id = None
        found_region = None

        # BUSCAMOS LA INSTANCIA DE IDENTITY CENTER EN TODAS LAS REGIONES
        # Iteramos por cada región hasta encontrarla.
        for region in all_regions:
            try:
                # Creamos un cliente específico para esta región en el bucle
                regional_sso_client = session.client("sso-admin", region_name=region)
                instances = regional_sso_client.list_instances().get("Instances", [])
                if instances:
                    # ¡La encontramos! Guardamos los datos y la región, y salimos del bucle.
                    instance_arn = instances[0]['InstanceArn']
                    identity_store_id = instances[0]['IdentityStoreId']
                    found_region = region
                    break 
            except ClientError:
                # Ignoramos regiones donde no tengamos permisos o el servicio no esté disponible.
                continue
        
        # SI NO SE ENCONTRÓ NINGUNA INSTANCIA...
        # Si el bucle termina y no hemos encontrado nada, devolvemos un mensaje claro.
        if not instance_arn:
            return {"status": "No Encontrado", "message": "No se encontraron instancias de AWS Identity Center activas en ninguna región."}

        # SI LA ENCONTRAMOS, CONTINUAMOS...
        # Ahora creamos los clientes finales apuntando a la REGIÓN CORRECTA.
        sso_admin_client = session.client("sso-admin", region_name=found_region)
        identity_client = session.client("identitystore", region_name=found_region)
        
        # --- FIN DE LA MODIFICACIÓN ---
        # El resto de la lógica es la misma que ya tenías.

        # 2. Obtener todos los grupos y crear un mapa para búsqueda rápida
        group_map = {}
        paginator_groups = identity_client.get_paginator('list_groups')
        for page in paginator_groups.paginate(IdentityStoreId=identity_store_id):
            for group in page.get("Groups", []):
                group_map[group['GroupId']] = group['DisplayName']

        # 3. Obtener todos los Permission Sets
        ps_map = {}
        paginator_ps = sso_admin_client.get_paginator('list_permission_sets')
        for page in paginator_ps.paginate(InstanceArn=instance_arn):
            for ps_arn in page.get("PermissionSets", []):
                details = sso_admin_client.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)
                ps_map[ps_arn] = details.get("PermissionSet", {}).get("Name", "Desconocido")

        # 4. Correlacionar todo
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
                                    "GroupName": group_map.get(group_id, "Grupo Desconocido")
                                })

        return {
            "status": "Encontrado",
            "instance_arn": instance_arn,
            "identity_store_id": identity_store_id,
            "assignments": sorted(assignments, key=lambda x: (x['GroupName'], x['PermissionSetName']))
        }

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             return {"status": "Error", "message": "Acceso denegado. Se necesitan permisos para 'sso-admin' y 'identitystore'."}
        return {"status": "Error", "message": f"Error inesperado al consultar Identity Center: {str(e)}"}
    except Exception as e:
        return {"status": "Error General", "message": f"Ocurrió un error inesperado en la función: {str(e)}"}



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
            print(f"No se pudo simular la política para {user['UserName']}: {e}")
            continue

    return users

# --- Sirviendo el Frontend ---
@app.route('/dashboard.html')
def serve_dashboard():
    # Esta función sirve el fichero dashboard.html que debe estar
    # en el mismo directorio que tu backend.py
    return send_from_directory('.', 'dashboard.html')


@app.route('/api/run-iam-audit', methods=['POST'])
def run_iam_audit():
    session, error = get_session(request.get_json());
    if error: return jsonify({"error": error}), 401
    try:
        iam_results = collect_iam_data(session)
        
        # --- LÍNEA MODIFICADA ---
        # Ahora llamamos a la nueva función que comprueba todas las categorías
        iam_results["users"] = check_critical_permissions(session, iam_results["users"])
        # --- FIN DE LA MODIFICACIÓN ---

        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": iam_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de IAM: {str(e)}"}), 500


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



@app.route('/api/run-federation-audit', methods=['POST'])
def run_federation_audit():
    session, error = get_session(request.get_json())
    if error: 
        return jsonify({"error": error}), 401
    try:
        federation_results = collect_federation_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": federation_results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de federación: {str(e)}"}), 500


# --- Lógica para Security Hub ---

def check_security_hub_status_in_regions(session, regions):
    """
    Verifica el estado de Security Hub en cada región y, si está activo,
    OBTIENE EL RESUMEN DE CUMPLIMIENTO para cada estándar habilitado.
    """
    results = []
    for region in regions:
        # La estructura de datos que devolvemos ahora es más rica
        region_status = {
            "Region": region, 
            "SecurityHubEnabled": False,
            "ComplianceSummaries": [] # <-- NUEVO CAMPO para los datos de cumplimiento
        }
        
        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub() # Comprobamos si está activo
            
            # Si la línea anterior no falla, Security Hub está habilitado
            region_status["SecurityHubEnabled"] = True
            
            # --- INICIO DE LA NUEVA LÓGICA AÑADIDA ---
            # 1. Obtenemos los estándares habilitados (CIS, PCI, etc.)
            enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])
            
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsSubscriptionArn')
                standard_name_raw = standard.get('StandardsArn', 'N/A').split('/standard/')[-1].replace('-', ' ').title()

                # 2. Para cada estándar, obtenemos el estado de todos sus controles
                controls = securityhub_client.describe_standards_controls(
                    StandardsSubscriptionArn=standard_arn
                ).get('Controls', [])

                if not controls:
                    continue

                # 3. Calculamos el resumen de cumplimiento
                passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                total_controls = len(controls)
                compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

                # 4. Guardamos el resumen del estándar en nuestro nuevo campo
                region_status["ComplianceSummaries"].append({
                    "standardName": standard_name_raw,
                    "compliancePercentage": round(compliance_percentage, 2),
                    "passedCount": passed_count,
                    "totalControls": total_controls,
                })
            # --- FIN DE LA NUEVA LÓGICA AÑADIDA ---

        except ClientError:
            # Esto ocurre si SH no está activo, lo cual es normal.
            pass
            
        results.append(region_status)
        
    return results

def get_and_filter_security_hub_findings(session, region_statuses):
    all_findings, iam_findings, exposure_findings, waf_findings, cloudtrail_findings, cloudwatch_findings, inspector_findings = [], [], [], [], [], [], []
    active_regions = [r['Region'] for r in region_statuses if r['SecurityHubEnabled']]
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            pages = paginator.paginate(Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]})
            for page in pages: all_findings.extend(page['Findings'])
        except ClientError: pass
    
    iam_findings = [f for f in all_findings if 'IAM' in f.get('Compliance', {}).get('SecurityControlId', '')]
    exposure_keywords = ['public', 'internet-facing', 'exposed', 'open', '0.0.0.0/0', 's3', 'ec2', 'elb', 'rds', 'lambda', 'api gateway', 'cloudfront']
    exposure_findings = [f for f in all_findings if any(keyword in f.get('Title', '').lower() for keyword in exposure_keywords)]
    waf_findings = [f for f in all_findings if 'WAF' in f.get('Compliance', {}).get('SecurityControlId', '')]
    cloudtrail_findings = [f for f in all_findings if 'cloudtrail' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    cloudwatch_findings = [f for f in all_findings if 'cloudwatch' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    
    # --- INICIO DEL CÓDIGO MODIFICADO ---
    # Lista de IDs de control de Security Hub específicos para la configuración de Inspector
    # Basado en: https://docs.aws.amazon.com/es_es/securityhub/latest/userguide/inspector-controls.html
    inspector_control_ids = [
        "Inspector.1",
        "Inspector.2",
        "Inspector.3",
        "Inspector.4",
        "Inspector.5",
        "Inspector.6"
    ]
    inspector_findings = [
        f for f in all_findings 
        if f.get('Compliance', {}).get('SecurityControlId') in inspector_control_ids
    ]
    # --- FIN DEL CÓDIGO MODIFICADO ---

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    for findings_list in [iam_findings, exposure_findings, waf_findings, cloudtrail_findings, cloudwatch_findings, inspector_findings]:
        findings_list.sort(key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99))
    
    return { "iamFindings": iam_findings, "exposureFindings": exposure_findings, "wafFindings": waf_findings, "cloudtrailFindings": cloudtrail_findings, "cloudwatchFindings": cloudwatch_findings, "inspectorFindings": inspector_findings }





def calculate_compliance_from_findings(all_findings):
    """
    Calcula el estado de cumplimiento de cada estándar basándose en una lista de findings.
    Esta es la forma correcta de obtener el estado PASSED/FAILED.
    """
    compliance_data = {}
    
    for finding in all_findings:
        # Nos interesan solo los findings que vienen de un estándar de seguridad
        if 'Compliance' not in finding or not finding['Compliance'].get('SecurityControlId'):
            continue

        # Extraemos el nombre del estándar y el estado del control del finding
        standard_arn = finding.get('ProductFields', {}).get('StandardsArn', 'N/A')
        control_status = finding.get('Compliance', {}).get('Status', 'UNKNOWN')

        if standard_arn not in compliance_data:
            compliance_data[standard_arn] = {'passed': 0, 'failed': 0, 'other': 0}

        if control_status == 'PASSED':
            compliance_data[standard_arn]['passed'] += 1
        elif control_status == 'FAILED':
            compliance_data[standard_arn]['failed'] += 1
        else:
            compliance_data[standard_arn]['other'] += 1

    # Procesamos los conteos para devolver un resumen con porcentajes
    summary_list = []
    for arn, counts in compliance_data.items():
        total_controls_found = counts['passed'] + counts['failed']
        if total_controls_found > 0:
            percentage = round((counts['passed'] / total_controls_found) * 100, 2)
            
            # Extraemos un nombre legible del ARN
            standard_name = arn.split('/standard/')[-1].replace('-', ' ').title() if '/standard/' in arn else arn

            summary_list.append({
                "standardArn": arn,
                "standardName": standard_name,
                "compliancePercentage": percentage,
                "passedCount": counts['passed'],
                "failedCount": counts['failed'],
                "otherCount": counts['other'],
                "totalControls": total_controls_found # Usamos el total de findings (passed+failed)
            })
            
    return summary_list


# --- Lógica para Internet Exposure ---
EXPOSURE_SERVICES = { "S3 Public Buckets": "s3", "EC2 Public Instances": "ec2", "Security Groups Open": "ec2", "ALB/NLB Public": "elbv2", "Lambda URLs": "lambda", "API Gateway Public": "apigateway", "Assumable Roles": "iam", }
EXPOSURE_GLOBAL_SERVICES = {"S3 Public Buckets", "Assumable Roles"}
def is_bucket_public(s3, bucket):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket["Name"])
        for grant in acl.get("Grants", []):
            if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"): return True
    except ClientError: pass
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket["Name"])
        if policy_status.get("PolicyStatus", {}).get("IsPublic"): return True
    except ClientError: pass
    return False
def lambda_has_url(client, fn_name):
    try:
        configs = client.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
        return any(c.get("AuthType") == "NONE" for c in configs)
    except ClientError: return False
def role_is_assumable_by_anyone(role):
    try:
        pol = role.get("AssumeRolePolicyDocument", {})
        for stmt in pol.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal.get("AWS") == "*": return True
    except Exception: pass
    return False
    
def collect_network_ports_data(session, regions):
    exposed_ports = []
    
    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                for perm in sg.get("IpPermissions", []):
                    ip_protocol = perm.get("IpProtocol")
                    from_port = perm.get("FromPort", "All")
                    to_port = perm.get("ToPort", "All")
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            exposed_ports.append({
                                "Region": region, "ResourceId": sg_id, "ResourceType": "SecurityGroup",
                                "Direction": "Inbound", "Protocol": ip_protocol,
                                "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                "Source": ip_range.get("CidrIp"), "Description": f"SG: {sg_name}"
                            })
            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                acl_id = acl.get("NetworkAclId")
                for entry in acl.get("Entries", []):
                    if entry.get("RuleAction") == "allow" and not entry.get("Egress") and entry.get("CidrBlock") == "0.0.0.0/0":
                        ip_protocol = entry.get("Protocol")
                        port_range = entry.get("PortRange", {})
                        from_port = port_range.get("From", "All")
                        to_port = port_range.get("To", "All")
                        protocol = "All" if ip_protocol == -1 else ip_protocol
                        exposed_ports.append({
                            "Region": region, "ResourceId": acl_id, "ResourceType": "NetworkAcl",
                            "Direction": "Inbound", "Protocol": protocol,
                            "PortRange": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                            "Source": entry.get("CidrBlock"), "Description": f"NACL Rule Number: {entry.get('RuleNumber')}"
                        })
        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
    return exposed_ports

def collect_exposure_data(session):
    regions = get_all_aws_regions(session)
    result_summary, result_details = defaultdict(dict), defaultdict(lambda: defaultdict(list))
    lock, threads = threading.Lock(), []
    network_ports_results = collect_network_ports_data(session, regions)
    
    def worker(service, region, current_session):
        try:
            exposed = []
            if service == "S3 Public Buckets":
                client = current_session.client("s3", region_name=region if region != "Global" else "us-east-1")
                for b in client.list_buckets()["Buckets"]:
                    if is_bucket_public(client, b): exposed.append(b["Name"])
            
            elif service == "EC2 Public Instances":
                client = current_session.client("ec2", region_name=region)
                for r in client.describe_instances()["Reservations"]:
                    for inst in r["Instances"]:
                        if inst.get("PublicIpAddress"): exposed.append({ "Id": inst['InstanceId'], "State": inst.get("State", {}).get("Name", "unknown"), "PublicIp": inst.get("PublicIpAddress") })
            
            elif service == "Security Groups Open":
                client = current_session.client("ec2", region_name=region)
                for sg in client.describe_security_groups()["SecurityGroups"]:
                    if any(ip.get("CidrIp") == "0.0.0.0/0" for rule in sg.get("IpPermissions", []) for ip in rule.get("IpRanges", [])): exposed.append(f"{sg['GroupId']} ({sg['GroupName']})");
            
            elif service == "ALB/NLB Public":
                client = current_session.client("elbv2", region_name=region)
                
                try:
                    # --- LÍNEA CORREGIDA ---
                    # Se ha cambiado p['SslPolicyName'] por p['Name'] que es la clave correcta.
                    ssl_policies_details = {p['Name']: p for p in client.describe_ssl_policies().get('SslPolicies', [])}
                except ClientError:
                    ssl_policies_details = {}

                for lb in client.describe_load_balancers()["LoadBalancers"]:
                    if lb.get("Scheme") == "internet-facing":
                        lb_arn = lb["LoadBalancerArn"]
                        lb_data = {
                            "name": lb["LoadBalancerName"],
                            "arn": lb_arn,
                            "region": region,
                            "listeners": []
                        }
                        
                        listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                        for listener in listeners:
                            if listener.get("Protocol") in ["HTTPS", "TLS"]:
                                policy_name = listener.get("SslPolicy")
                                policy_details = ssl_policies_details.get(policy_name, {})
                                tls_versions = policy_details.get('SslProtocols', [])
                                ciphers = [c['Name'] for c in policy_details.get('Ciphers', [])]
                                is_outdated = any(v in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for v in tls_versions)
                                lb_data["listeners"].append({
                                    "port": listener.get("Port"), "protocol": listener.get("Protocol"),
                                    "policyName": policy_name, "isOutdated": is_outdated,
                                    "tlsVersions": tls_versions, "ciphers": ciphers
                                })
                        exposed.append(lb_data)

            elif service == "Lambda URLs":
                client = current_session.client("lambda", region_name=region)
                for fn in client.list_functions()["Functions"]:
                    if lambda_has_url(client, fn["FunctionName"]): exposed.append(fn["FunctionName"])
            
            elif service == "API Gateway Public":
                client = current_session.client("apigateway", region_name=region)
                for api in client.get_rest_apis()["items"]:
                    if "REGIONAL" in api.get("endpointConfiguration", {}).get("types", []): exposed.append(f"{api['name']} (Regional)")
            
            elif service == "Assumable Roles":
                client = current_session.client("iam", region_name="us-east-1")
                for role in client.list_roles()["Roles"]:
                    if role_is_assumable_by_anyone(role): exposed.append(role["RoleName"])
            
            with lock:
                if exposed:
                    result_summary[service][region], result_details[service][region] = len(exposed), exposed
        except ClientError: pass

    tasks = [(s, "Global") if s in EXPOSURE_GLOBAL_SERVICES else (s, r) for s in EXPOSURE_SERVICES for r in (["Global"] if s in EXPOSURE_GLOBAL_SERVICES else regions)]
    for service, region in tasks:
        t = threading.Thread(target=worker, args=(service, region, session)); threads.append(t); t.start()
    for t in threads: t.join()
    
    return {
        "summary": dict(result_summary), 
        "details": dict(result_details),
        "network_ports": network_ports_results
    }


# --- Lógica para GuardDuty ---

def collect_guardduty_data(session):
    all_regions = get_all_aws_regions(session)
    status_by_region = []
    all_findings_raw = []

    for region in all_regions:
        try:
            gd_client = session.client("guardduty", region_name=region)
            detectors = gd_client.list_detectors()
            
            if not detectors.get("DetectorIds"):
                # --- MODIFICADO: Añadimos las nuevas claves también al estado por defecto ---
                status_by_region.append({"Region": region, "Status": "No Habilitado", "S3 Logs": "-", "Kubernetes Logs": "-", "EC2 Malware Protection": "-", "EKS Malware Protection": "-"})
                continue

            detector_id = detectors["DetectorIds"][0]
            detector_details = gd_client.get_detector(DetectorId=detector_id)
            
            features = {f["Name"]: "Habilitado" if f["Status"] == "ENABLED" else "Deshabilitado" for f in detector_details.get("Features", [])}

            status_by_region.append({
                "Region": region,
                "Status": "Habilitado" if detector_details.get("Status") == "ENABLED" else "Suspendido",
                "S3 Logs": features.get("S3_DATA_EVENTS", "N/A"),
                "Kubernetes Logs": features.get("KUBERNETES_AUDIT_LOGS", "N/A"),
                # --- MODIFICADO: Se crean dos claves distintas y claras ---
                "EC2 Malware Protection": features.get("MALWARE_PROTECTION", "N/A"),
                "EKS Malware Protection": features.get("EKS_RUNTIME_MONITORING", "N/A"),
            })

            if detector_details.get("Status") == "ENABLED":
                paginator = gd_client.get_paginator('list_findings')
                pages = paginator.paginate(DetectorId=detector_id, FindingCriteria={'Criterion': {'service.archived': {'Eq': ['false']}}})
                for page in pages:
                    if page.get("FindingIds"):
                        findings_details = gd_client.get_findings(DetectorId=detector_id, FindingIds=page["FindingIds"])
                        all_findings_raw.extend(findings_details.get("Findings", []))
        except ClientError as e:
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e): continue
            status_by_region.append({"Region": region, "Status": f"Error ({type(e).__name__})", "S3 Logs": "-", "Kubernetes Logs": "-", "EC2 Malware Protection": "-", "EKS Malware Protection": "-"})

    # El resto de la función para procesar findings no cambia
    processed_findings = []
    for f in all_findings_raw:
        severity_map = {1: "LOW", 2: "LOW", 3: "LOW", 4: "MEDIUM", 5: "MEDIUM", 6: "MEDIUM", 7: "HIGH", 8: "HIGH", 9: "CRITICAL", 10: "CRITICAL"}
        severity_score = int(f.get("Severity", 0))
        resource = f.get("Resource", {})
        resource_type = resource.get("ResourceType", "N/A")
        resource_details_str = "N/A"
        if resource_type == "AccessKey":
            details = resource.get('AccessKeyDetails', {})
            resource_details_str = f"{details.get('UserType', 'N/A')}: {details.get('UserName', 'N/A')}"
        elif resource_type == "Instance":
             details = resource.get('InstanceDetails', {})
             resource_details_str = f"ID: {details.get('InstanceId', 'N/A')}"
        elif resource_type == 'EksCluster':
            details = resource.get('EksClusterDetails', {})
            resource_details_str = f"Cluster: {details.get('Name', 'N/A')}"
        elif resource_type == 'S3Bucket':
            details = resource.get('S3BucketDetails', [])
            if details: resource_details_str = f"Bucket: {details[0].get('Name', 'N/A')}"
        processed_findings.append({
            "SeverityScore": severity_score, "SeverityLabel": severity_map.get(severity_score, "INFORMATIONAL"),
            "Region": f.get("Region", "N/A"), "Type": f.get("Type", "N/A"),
            "Resource": f"{resource_type} - {resource_details_str}", "LastSeen": f.get("UpdatedAt", "N/A").split("T")[0],
            "Title": f.get("Title", "N/A")
        })
    processed_findings.sort(key=lambda x: x["SeverityScore"], reverse=True)
    
    return {"status": status_by_region, "findings": processed_findings}

# --- Lógica para WAF ---
def parse_resource_arn(arn):
    try:
        parts = arn.split(':')
        resource_part = parts[5]
        if 'loadbalancer' in resource_part:
            lb_parts = resource_part.split('/')
            if len(lb_parts) > 2: return f"{lb_parts[0]}/{lb_parts[1]}/{lb_parts[2]}"
        if 'restapis' in resource_part:
            api_parts = resource_part.split('/')
            if len(api_parts) > 2: return f"{api_parts[1]}/{api_parts[2]}"
        return resource_part.split('/')[-1]
    except Exception: return arn


def collect_waf_data(session):
    all_acls, all_ip_sets = [], []
    regions = get_all_aws_regions(session)
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_web_acls(Scope="CLOUDFRONT")
        for acl in response.get("WebACLs", []):
            # --- LÍNEA CORREGIDA ---
            resources_raw = client_global.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
            all_acls.append({ "Name": acl["Name"], "ARN": acl["ARN"], "Scope": "CLOUDFRONT", "Region": "Global", "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw] })
    except ClientError: pass
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_web_acls(Scope="REGIONAL")
            for acl in response.get("WebACLs", []):
                resources_raw = client_regional.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
                all_acls.append({ "Name": acl["Name"], "ARN": acl["ARN"], "Scope": "REGIONAL", "Region": region, "AssociatedResourceArns": [parse_resource_arn(r) for r in resources_raw] })
        except ClientError: pass
    try:
        client_global = session.client("wafv2", region_name="us-east-1")
        response = client_global.list_ip_sets(Scope="CLOUDFRONT")
        for ip_set_summary in response.get("IPSets", []):
            details = client_global.get_ip_set(Name=ip_set_summary["Name"], Scope="CLOUDFRONT", Id=ip_set_summary["Id"])
            all_ip_sets.append({ "Name": details["IPSet"]["Name"], "ARN": details["IPSet"]["ARN"], "Scope": "CLOUDFRONT", "Region": "Global", "IPAddressVersion": details["IPSet"]["IPAddressVersion"], "AddressCount": len(details["IPSet"]["Addresses"]) })
    except ClientError: pass
    for region in regions:
        try:
            client_regional = session.client("wafv2", region_name=region)
            response = client_regional.list_ip_sets(Scope="REGIONAL")
            for ip_set_summary in response.get("IPSets", []):
                details = client_regional.get_ip_set(Name=ip_set_summary["Name"], Scope="REGIONAL", Id=ip_set_summary["Id"])
                all_ip_sets.append({ "Name": details["IPSet"]["Name"], "ARN": details["IPSet"]["ARN"], "Scope": "REGIONAL", "Region": region, "IPAddressVersion": details["IPSet"]["IPAddressVersion"], "AddressCount": len(details["IPSet"]["Addresses"]) })
        except ClientError: pass
    return {"acls": all_acls, "ip_sets": all_ip_sets}


# --- Lógica para KMS (NUEVA SECCIÓN) ---
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
                            rotation_enabled = "Activada" if status.get('KeyRotationEnabled') else "Desactivada"
                        except ClientError:
                            rotation_enabled = "No Soportada"
                    
                    policy_doc = "No se pudo obtener"
                    try:
                        policy_str = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
                        policy_doc = json.loads(policy_str)
                    except (ClientError, json.JSONDecodeError):
                        pass

                    result_kms_keys.append({
                        "Region": region,
                        "KeyId": key_id,
                        "ARN": desc.get('Arn'),
                        "Aliases": ", ".join(alias_map.get(key_id, ["Sin Alias"])),
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



# --- Lógica para CloudTrail ---
def collect_cloudtrail_data(session):
    regions = get_all_aws_regions(session)
    result_trails, result_events, processed_trail_arns = [], [], set()
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for trail in client.describe_trails().get('trailList', []):
                trail_arn = trail.get("TrailARN")
                if trail_arn not in processed_trail_arns:
                    try:
                        trail_status = client.get_trail_status(Name=trail_arn)
                        result_trails.append({ "Name": trail.get("Name"), "HomeRegion": trail.get("HomeRegion"), "S3BucketName": trail.get("S3BucketName"), "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False), "IsOrganizationTrail": trail.get("IsOrganizationTrail", False), "IsLogging": trail_status.get("IsLogging", False), "KmsKeyId": trail.get("KmsKeyId"), "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False), "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"), "TrailARN": trail_arn })
                        processed_trail_arns.add(trail_arn)
                    except ClientError: continue 
        except ClientError: continue
    eventos_a_buscar = [ "ConsoleLogin", "CreateUser", "DeleteUser", "CreateTrail", "StopLogging", "UpdateTrail", "DeleteTrail", "CreateLoginProfile", "DeleteLoginProfile", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "StartInstances", "StopInstances", "TerminateInstances", "DisableKey", "ScheduleKeyDeletion" ]
    end_time, start_time = datetime.now(pytz.utc), datetime.now(pytz.utc) - timedelta(days=7)
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            for event_name in eventos_a_buscar:
                paginator = client.get_paginator('lookup_events')
                for page in paginator.paginate(LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}], StartTime=start_time, EndTime=end_time):
                    for event in page.get('Events', []):
                        cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        result_events.append({ "EventName": event.get("EventName"), "EventTime": str(event.get("EventTime")), "Username": event.get("Username", "N/A"), "EventRegion": cloudtrail_event_data.get("awsRegion", region), "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"), "RequestParameters": cloudtrail_event_data.get("requestParameters", {}) })
        except ClientError: continue
    result_events.sort(key=lambda x: x['EventTime'], reverse=True)
    return {"trails": result_trails, "events": result_events}

def lookup_cloudtrail_events(session, region, event_name, start_time, end_time):
    found_events = []
    try:
        client = session.client("cloudtrail", region_name=region)
        paginator = client.get_paginator('lookup_events')
        
        lookup_attributes = []
        if event_name:
            lookup_attributes.append({'AttributeKey': 'EventName', 'AttributeValue': event_name})

        pages = paginator.paginate(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time
        )

        for page in pages:
            for event in page.get('Events', []):
                cloudtrail_event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                found_events.append({
                    "EventId": event.get("EventId"),
                    "CloudTrailEvent": event.get('CloudTrailEvent', '{}'),
                    "EventName": event.get("EventName"),
                    "EventTime": str(event.get("EventTime")),
                    "Username": event.get("Username", "N/A"),
                    "EventRegion": cloudtrail_event_data.get("awsRegion", region),
                    "SourceIPAddress": cloudtrail_event_data.get("sourceIPAddress", "N/A"),
                    "RequestParameters": cloudtrail_event_data.get("requestParameters", {})
                })
    except ClientError as e:
        # Lanza una excepción para que el endpoint la capture y devuelva un error claro.
        raise Exception(f"Error al buscar eventos en CloudTrail en la región {region}: {str(e)}")

    found_events.sort(key=lambda x: x['EventTime'], reverse=True)
    return {"events": found_events}
    
# --- Lógica para CloudWatch ---
def collect_cloudwatch_data(session):
    all_regions = get_all_aws_regions(session)
    result_alarms, result_topics = [], []
    for region in all_regions:
        try:
            session_regional = boto3.Session(aws_access_key_id=session.get_credentials().access_key, aws_secret_access_key=session.get_credentials().secret_key, aws_session_token=session.get_credentials().token, region_name=region)
            cw_client, sns_client = session_regional.client("cloudwatch"), session_regional.client("sns")
            try:
                paginator_alarms = cw_client.get_paginator('describe_alarms')
                for page in paginator_alarms.paginate():
                    for alarm in page['MetricAlarms']: alarm['Region'] = region; result_alarms.append(alarm)
            except ClientError as e:
                if "OptInRequired" in str(e): continue
            try:
                paginator_topics, all_topics_in_region = sns_client.get_paginator('list_topics'), []
                for page in paginator_topics.paginate(): all_topics_in_region.extend(page.get("Topics", []))
                for topic in all_topics_in_region:
                    topic_arn, subscriptions = topic['TopicArn'], []
                    try:
                        paginator_subs = sns_client.get_paginator('list_subscriptions_by_topic')
                        for page in paginator_subs.paginate(TopicArn=topic_arn):
                            for sub in page.get("Subscriptions", []):
                                if sub.get("Protocol") in ["email", "email-json"] and sub.get("SubscriptionArn") != "PendingConfirmation":
                                    subscriptions.append({"Endpoint": sub.get("Endpoint"), "Protocol": sub.get("Protocol")})
                    except ClientError: pass
                    if subscriptions: result_topics.append({"TopicArn": topic_arn, "Region": region, "Subscriptions": subscriptions})
            except ClientError as e:
                if "OptInRequired" in str(e): continue
        except ClientError as e:
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e): continue
    return {"alarms": result_alarms, "topics": result_topics}

# --- Lógica para Inspector ---

def collect_inspector_status(session):
    """
    FUNCIÓN RÁPIDA: Obtiene solo el estado de activación de Inspector por región.
    """
    result_scan_status = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []
    
    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            account_state = status_response.get('accounts', [{}])[0]

            if account_state.get('state', {}).get('status') in ['ENABLED', 'ENABLING']:
                resource_state = account_state.get('resourceState', {})
                status = {
                    "Region": region,
                    "InspectorStatus": account_state.get('state', {}).get('status'),
                    "ScanEC2": resource_state.get('ec2', {}).get('status'),
                    "ScanECR": resource_state.get('ecr', {}).get('status'),
                    "ScanLambda": resource_state.get('lambda', {}).get('status', 'NOT_AVAILABLE')
                }
                result_scan_status.append(status)
        except ClientError:
            continue
    return {"scan_status": result_scan_status}

def collect_inspector_findings(session):
    """
    FUNCIÓN LENTA: Obtiene todos los hallazgos (findings) de Inspector.
    MODIFICADA: Ahora también obtiene el tag "Name" de las instancias EC2.
    """
    result_findings = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            if status_response.get('accounts', [{}])[0].get('state', {}).get('status') != 'ENABLED':
                continue

            paginator = inspector_client.get_paginator('list_findings')
            pages = paginator.paginate(filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]})
            for page in pages:
                for finding in page.get('findings', []):
                    finding['Region'] = region
                    result_findings.append(finding)
        except ClientError:
            continue

    # --- INICIO DE LA LÓGICA AÑADIDA ---
    # Agrupar IDs de instancias EC2 por región para una consulta eficiente
    ec2_findings_by_region = defaultdict(list)
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            region = f['Region']
            instance_id = f['resources'][0]['id']
            ec2_findings_by_region[region].append(instance_id)

    # Mapa para guardar los nombres de las instancias: { "i-12345": "WebServer01" }
    instance_name_map = {}

    # Consultar los nombres de las instancias en bloque por cada región
    for region, instance_ids in ec2_findings_by_region.items():
        if not instance_ids: continue
        try:
            ec2_client = session.client('ec2', region_name=region)
            paginator = ec2_client.get_paginator('describe_instances')
            pages = paginator.paginate(InstanceIds=list(set(instance_ids)))
            for page in pages:
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        name_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None)
                        if name_tag:
                            instance_name_map[instance['InstanceId']] = name_tag
        except ClientError:
            continue

    # Añadir el nombre resuelto de vuelta al objeto del finding
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            instance_id = f['resources'][0]['id']
            # Añadimos un nuevo campo 'resourceName' al finding
            f['resourceName'] = instance_name_map.get(instance_id, '')
    # --- FIN DE LA LÓGICA AÑADIDA ---

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNDEFINED': 5}
    result_findings.sort(key=lambda f: severity_order.get(f.get('severity'), 99))
    return {"findings": result_findings}


# ... (Aquí irían las otras funciones de recolección de datos como ACM, Compute, etc.)

# --- Endpoints de la API ---

# ... (Aquí irían los otros endpoints como IAM, SecurityHub, etc.)

@app.route('/api/run-inspector-audit', methods=['POST'])
def run_inspector_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        # Ahora solo llama a la función rápida de estado
        inspector_status = collect_inspector_status(session)
        sts = session.client("sts")
        # Devuelve el estado y una lista de findings vacía por defecto
        inspector_status["findings"] = []
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_status })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar el estado de Inspector: {str(e)}"}), 500

@app.route('/api/run-inspector-findings-audit', methods=['POST'])
def run_inspector_findings_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        # Este endpoint llama a la función lenta de búsqueda de findings
        inspector_findings = collect_inspector_findings(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_findings })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar los findings de Inspector: {str(e)}"}), 500







def collect_inspector_findings(session):
    """
    FUNCIÓN LENTA: Obtiene todos los hallazgos (findings) de Inspector.
    """
    result_findings = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception: 
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            # Solo continuamos si Inspector está realmente activo en la región
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            if status_response.get('accounts', [{}])[0].get('state', {}).get('status') != 'ENABLED':
                continue

            paginator = inspector_client.get_paginator('list_findings')
            pages = paginator.paginate(filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]})
            for page in pages:
                for finding in page.get('findings', []):
                    finding['Region'] = region
                    result_findings.append(finding)
        except ClientError:
            continue
            
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNDEFINED': 5}
    result_findings.sort(key=lambda f: severity_order.get(f.get('severity'), 99))
    return {"findings": result_findings}








# --- Lógica para ACM ---
def collect_acm_data_web(session):
    all_regions = session.get_available_regions('acm')
    result_certificates = []
    
    for region in all_regions:
        try:
            acm_client = session.client("acm", region_name=region)
            paginator_certs = acm_client.get_paginator('list_certificates')
            
            for page in paginator_certs.paginate():
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    try:
                        cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
                        cert_details['Region'] = region
                        if 'IssuedAt' in cert_details:
                            cert_details['IssuedAt'] = cert_details['IssuedAt'].isoformat()
                        if 'NotAfter' in cert_details:
                            cert_details['NotAfter'] = cert_details['NotAfter'].isoformat()
                        result_certificates.append(cert_details)
                    except ClientError as e:
                        if "OptInRequired" in str(e) or "endpoint" in str(e):
                            continue
                        print(f"Warning: Could not retrieve details for certificate {cert_arn} in {region}: {e}")
        except ClientError as e:
            if "OptInRequired" in str(e) or "endpoint" in str(e) or "SignatureDoesNotMatch" in str(e): 
                continue
            print(f"Notice: ACM service not available or no permissions in {region}: {e}")

    result_certificates.sort(key=lambda x: (x.get('Region', ''), x.get('DomainName', '')))
    
    return {"certificates": result_certificates}



# --- Lógica para Databases ---
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
            
            # 1. Clústeres Aurora
            aurora_paginator = rds_client.get_paginator("describe_db_clusters")
            for page in aurora_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    if "aurora" in cluster.get("Engine", ""):
                        db_subnet_group_name = cluster.get("DBSubnetGroup")
                        vpc_id = None
                        subnet_ids = []
                        if db_subnet_group_name:
                            try:
                                subnet_group_details = rds_client.describe_db_subnet_groups(DBSubnetGroupName=db_subnet_group_name).get("DBSubnetGroups", [])
                                if subnet_group_details:
                                    vpc_id = subnet_group_details[0].get("VpcId")
                                    subnet_ids = [s.get("SubnetIdentifier") for s in subnet_group_details[0].get("Subnets", [])]
                            except ClientError:
                                pass
                        aurora_clusters.append({
                            "Region": region,
                            "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                            "Engine": cluster.get("Engine"),
                            "Status": cluster.get("Status"),
                            "Endpoint": cluster.get("Endpoint", "N/A"),
                            "ARN": cluster.get("DBClusterArn"),
                            "VpcId": vpc_id,
                            "SubnetIds": subnet_ids
                        })
            
            # 2. Instancias RDS (que no pertenezcan a un clúster de Aurora)
            rds_paginator = rds_client.get_paginator("describe_db_instances")
            for page in rds_paginator.paginate():
                for instance in page.get("DBInstances", []):
                    if not instance.get("DBClusterIdentifier"):
                        db_subnet_group = instance.get("DBSubnetGroup", {})
                        vpc_id = db_subnet_group.get("VpcId")
                        subnet_ids = [s.get("SubnetIdentifier") for s in db_subnet_group.get("Subnets", [])]
                        rds_instances.append({
                            "Region": region,
                            "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                            "DBInstanceClass": instance.get("DBInstanceClass"),
                            "Engine": instance.get("Engine"),
                            "DBInstanceStatus": instance.get("DBInstanceStatus"),
                            "Endpoint": instance.get("Endpoint", {}).get("Address", "N/A"),
                            "ARN": instance.get("DBInstanceArn"),
                            "PubliclyAccessible": instance.get('PubliclyAccessible', False),
                            "VpcId": vpc_id,
                            "SubnetIds": subnet_ids
                        })

            # 3. Tablas de DynamoDB
            dynamo_paginator = dynamodb_client.get_paginator("list_tables")
            for page in dynamo_paginator.paginate():
                for table_name in page.get("TableNames", []):
                    table_details = dynamodb_client.describe_table(TableName=table_name).get("Table", {})
                    dynamodb_tables.append({
                        "Region": region,
                        "TableName": table_name,
                        "Status": table_details.get("TableStatus"),
                        "ItemCount": table_details.get("ItemCount", 0),
                        "SizeBytes": table_details.get("TableSizeBytes", 0),
                        "ARN": table_details.get("TableArn")
                    })
            # 4. Clústeres de DocumentDB
            docdb_paginator = docdb_client.get_paginator("describe_db_clusters")
            for page in docdb_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    documentdb_clusters.append({
                        "Region": region,
                        "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                        "Engine": cluster.get("Engine"),
                        "Status": cluster.get("Status"),
                        "Endpoint": cluster.get("Endpoint", "N/A"),
                        "ARN": cluster.get("DBClusterArn")
                    })

        except ClientError as e:
            if e.response['Error']['Code'] not in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                print(f"Error procesando bases de datos en la región {region}: {e}")
            continue
    
    return {
        "rds_instances": rds_instances,
        "aurora_clusters": aurora_clusters,
        "dynamodb_tables": dynamodb_tables,
        "documentdb_clusters": documentdb_clusters
    }








# --- Lógica para Compute ---

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
                                os_info = "Información no disponible"

                        result_ec2_instances.append({
                            "Region": region, "InstanceId": instance_id,
                            "InstanceType": instance.get("InstanceType"), "State": instance.get("State", {}).get("Name"),
                            "PublicIpAddress": instance.get("PublicIpAddress", "N/A"), "Tags": tags_dict,
                            "OperatingSystem": os_info,
                            "ARN": f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                            "SubnetId": instance.get("SubnetId")
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


# --- Lógica para Network Security Policies ---

def collect_network_policies_data(session):
    regions = get_all_aws_regions(session) # Se obtiene la lista completa de regiones aquí
    result_vpcs = []
    result_acls = []
    result_sgs = []
    result_subnets = [] # <-- AÑADIDO

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            
            # Recopilar VPCs
            vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                tags_dict = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                result_vpcs.append({
                    "Region": region, "VpcId": vpc.get("VpcId"), "CidrBlock": vpc.get("CidrBlock"),
                    "IsDefault": vpc.get("IsDefault"), "Tags": tags_dict
                })

            # Recopilar Network ACLs
            acls = ec2_client.describe_network_acls().get("NetworkAcls", [])
            for acl in acls:
                tags_dict = {tag['Key']: tag['Value'] for tag in acl.get('Tags', [])}
                result_acls.append({
                    "Region": region, "AclId": acl.get("NetworkAclId"), "VpcId": acl.get("VpcId"),
                    "IsDefault": acl.get("IsDefault"), "Tags": tags_dict
                })

            # Recopilar Security Groups
            sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                tags_dict = {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                result_sgs.append({
                    "Region": region, "GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"), "Description": sg.get("Description"), "Tags": tags_dict
                })
            
            # --- INICIO DEL CÓDIGO AÑADIDO ---
            # Recopilar Subredes
            subnets = ec2_client.describe_subnets().get("Subnets", [])
            for subnet in subnets:
                tags_dict = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                result_subnets.append({
                    "Region": region,
                    "SubnetId": subnet.get("SubnetId"),
                    "VpcId": subnet.get("VpcId"),
                    "CidrBlock": subnet.get("CidrBlock"),
                    "AvailabilityZone": subnet.get("AvailabilityZone"),
                    "Tags": tags_dict
                })
            # --- FIN DEL CÓDIGO AÑADIDO ---

        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
            
    # El return ahora incluye la lista de subredes
    return { 
        "vpcs": result_vpcs, 
        "acls": result_acls, 
        "security_groups": result_sgs,
        "subnets": result_subnets, # <-- AÑADIDO
        "all_regions": regions 
    }

def collect_connectivity_data(session):
    """
    Recopila información sobre VPC Peering, Transit Gateway, VPNs y VPC Endpoints.
    """
    regions = get_all_aws_regions(session)
    result = {
        "peering_connections": [],
        "tgw_attachments": [],
        "vpn_connections": [],
        "vpc_endpoints": []
    }

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            
            # 1. VPC Peering Connections (solo activas)
            peering_paginator = ec2_client.get_paginator('describe_vpc_peering_connections')
            for page in peering_paginator.paginate(Filters=[{'Name': 'status-code', 'Values': ['active']}]):
                for pcx in page.get("VpcPeeringConnections", []):
                    result["peering_connections"].append({
                        "Region": region,
                        "ConnectionId": pcx.get("VpcPeeringConnectionId"),
                        "RequesterVpc": pcx.get("RequesterVpcInfo", {}),
                        "AccepterVpc": pcx.get("AccepterVpcInfo", {})
                    })

            # 2. Transit Gateway VPC Attachments (solo disponibles)
            tgw_paginator = ec2_client.get_paginator('describe_transit_gateway_attachments')
            for page in tgw_paginator.paginate(Filters=[{'Name': 'resource-type', 'Values': ['vpc']}, {'Name': 'state', 'Values': ['available']}]):
                for tgw_attachment in page.get("TransitGatewayAttachments", []):
                    result["tgw_attachments"].append({
                        "Region": region,
                        "AttachmentId": tgw_attachment.get("TransitGatewayAttachmentId"),
                        "TransitGatewayId": tgw_attachment.get("TransitGatewayId"),
                        "VpcId": tgw_attachment.get("ResourceId"),
                        "VpcOwnerId": tgw_attachment.get("ResourceOwnerId")
                    })

            # 3. Site-to-Site VPN Connections (solo disponibles)
            vpns = ec2_client.describe_vpn_connections(Filters=[{'Name': 'state', 'Values': ['available']}])
            for vpn in vpns.get("VpnConnections", []):
                result["vpn_connections"].append({
                    "Region": region,
                    "VpnConnectionId": vpn.get("VpnConnectionId"),
                    "CustomerGatewayId": vpn.get("CustomerGatewayId"),
                    "TransitGatewayId": vpn.get("TransitGatewayId", "N/A"),
                    "State": vpn.get("State")
                })

            # 4. VPC Endpoints
            endpoint_paginator = ec2_client.get_paginator('describe_vpc_endpoints')
            for page in endpoint_paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                     result["vpc_endpoints"].append({
                        "Region": region,
                        "VpcEndpointId": endpoint.get("VpcEndpointId"),
                        "VpcId": endpoint.get("VpcId"),
                        "ServiceName": endpoint.get("ServiceName"),
                        "EndpointType": endpoint.get("VpcEndpointType"),
                        "State": endpoint.get("State")
                    })

        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
            
    return result


# --- Lógica de Utilidad para formateo de Tablas ---
PROTOCOLS = {'-1': 'ALL', '6': 'TCP', '17': 'UDP', '1': 'ICMP'}

def _format_to_table(headers, rows, title):
    """Función de utilidad para crear una tabla de texto."""
    if not rows:
        return f"{title}\nNo rules or entries found."
    
    # Calcular anchos de columna
    col_widths = {header: len(header) for header in headers}
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[headers[i]] = max(col_widths[headers[i]], len(str(cell)))
    
    # Crear líneas de la tabla
    header_line = " | ".join(header.ljust(col_widths[header]) for header in headers)
    separator = "-+-".join("-" * col_widths[header] for header in headers)
    body_lines = "\n".join(" | ".join(str(cell).ljust(col_widths[headers[i]]) for i, cell in enumerate(row)) for row in rows)
    
    return f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n" \
           f"| {title.center(len(header_line))} |\n" \
           f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+\n" \
           f"| {header_line} |\n" \
           f"+={separator}=+\n" \
           f"| " + body_lines.replace("\n", " |\n| ") + " |\n" \
           f"+-{'-+-'.join('-' * col_widths[h] for h in headers)}-+"


# --- Network Detail Logic ---
def format_sg_details_table(sg_details):
    sg = sg_details['SecurityGroups'][0]
    title = f"Detalles para Security Group: {sg['GroupId']} ({sg['GroupName']})"
    headers = ['Dirección', 'Protocolo', 'Puerto', 'Origen/Destino', 'Descripción']
    rows = []

    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Ingress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Ingress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])
    
    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(str(rule.get('IpProtocol', '-1')), rule.get('IpProtocol', 'N/A'))
        port = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}".replace('-1-All', 'All')
        for ip_range in rule.get('IpRanges', []):
            rows.append(['Egress', proto, port, ip_range.get('CidrIp'), ip_range.get('Description', '-')])
        for group_pair in rule.get('UserIdGroupPairs', []):
            rows.append(['Egress', proto, port, group_pair.get('GroupId'), group_pair.get('Description', '-')])

    return _format_to_table(headers, rows, title)

def format_nacl_details_table(nacl_details):
    nacl = nacl_details['NetworkAcls'][0]
    title = f"Detalles para Network ACL: {nacl['NetworkAclId']}"
    headers = ['# Regla', 'Dirección', 'Acción', 'Protocolo', 'Puerto', 'CIDR', 'Tags']
    rows = []
    
    tags_str = ", ".join([f"{t['Key']}={t['Value']}" for t in nacl.get('Tags', [])]) or "-"

    for entry in sorted(nacl['Entries'], key=lambda x: x['RuleNumber']):
        direction = 'Egress' if entry.get('Egress') else 'Ingress'
        action = entry.get('RuleAction', 'N/A').upper()
        proto = PROTOCOLS.get(str(entry.get('Protocol', '-1')), entry.get('Protocol', 'N/A'))
        port_range = entry.get('PortRange', {})
        port = f"{port_range.get('From', 'All')}-{port_range.get('To', 'All')}".replace('-1-All', 'All')
        cidr = entry.get('CidrBlock', '-')
        rows.append([entry.get('RuleNumber'), direction, action, proto, port, cidr, tags_str])
        
    return _format_to_table(headers, rows, title)

# --- Lógica para Playground ---
def pg_format_sg_rules(ec2_client, sg_id):
    """Obtiene y formatea las reglas de un Security Group en una tabla de texto."""
    sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
    rows = []
    
    for rule in sg.get('IpPermissions', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        port_range = f"{from_port}-{to_port}" if from_port != 'N/A' else 'ALL'
        
        sources = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                  [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])] + \
                  [i.get('PrefixListId') for i in rule.get('PrefixListIds', [])]
        
        for source in (sources or ['-']):
            rows.append(['Ingress', proto, port_range, source or 'N/A'])

    for rule in sg.get('IpPermissionsEgress', []):
        proto = PROTOCOLS.get(rule.get('IpProtocol'), rule.get('IpProtocol'))
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        port_range = f"{from_port}-{to_port}" if from_port != 'N/A' else 'ALL'

        dests = [i.get('CidrIp') for i in rule.get('IpRanges', [])] + \
                [i.get('GroupId') for i in rule.get('UserIdGroupPairs', [])] + \
                [i.get('PrefixListId') for i in rule.get('PrefixListIds', [])]

        for dest in (dests or ['-']):
            rows.append(['Egress', proto, port_range, dest or 'N/A'])

    return _format_to_table(['Direction', 'Protocol', 'Port Range', 'Source/Destination'], rows, f"Details for Security Group: {sg_id}")

def pg_format_nacl_rules(ec2_client, nacl_id):
    """Obtiene y formatea las reglas de una Network ACL en una tabla de texto."""
    nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]
    rows = []
    
    sorted_entries = sorted(nacl['Entries'], key=lambda x: x['RuleNumber'])
    
    for entry in sorted_entries:
        direction = 'Egress' if entry['Egress'] else 'Ingress'
        proto = PROTOCOLS.get(entry['Protocol'], entry['Protocol'])
        port_range = 'ALL'
        if 'PortRange' in entry:
            port_range = f"{entry['PortRange']['From']}-{entry['PortRange']['To']}"
        
        cidr = entry.get('CidrBlock') or entry.get('Ipv6CidrBlock', '-')
        rows.append([entry['RuleNumber'], direction, entry['RuleAction'].upper(), proto, port_range, cidr])

    return _format_to_table(['Rule #', 'Direction', 'Action', 'Protocol', 'Port Range', 'CIDR'], rows, f"Details for Network ACL: {nacl_id}")

def pg_format_route_table(ec2_client, rtb_id):
    """Obtiene y formatea las rutas de una Route Table en una tabla de texto."""
    rt = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])['RouteTables'][0]
    rows = []

    for route in rt['Routes']:
        target = next((v for k, v in route.items() if k != 'DestinationCidrBlock' and (k.endswith('Id') or k.endswith('id'))), 'local')
        rows.append([route['DestinationCidrBlock'], target, route['State']])
        
    return _format_to_table(['Destination', 'Target', 'State'], rows, f"Details for Route Table: {rtb_id}")

def pg_get_ec2_details(ec2_client, instance_id):
    """Obtiene detalles de red de una instancia EC2."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        if not instance.get('PrivateIpAddress'):
            raise ValueError(f"La instancia EC2 '{instance_id}' no tiene una IP privada asignada (podría estar detenida).")
        return {
            "id": instance['InstanceId'], "service": "EC2",
            "private_ip": instance.get('PrivateIpAddress'),
            "subnet_id": instance['SubnetId'], "vpc_id": instance['VpcId'],
            "security_group_ids": [sg['GroupId'] for sg in instance['SecurityGroups']]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            raise ValueError(f"No se encontró la instancia EC2 con ID '{instance_id}'.")
        raise


def pg_get_rds_details(session, region, db_identifier, ec2_client):
    """Obtiene detalles de red de una instancia RDS."""
    rds_client = session.client('rds', region_name=region)
    try:
        db = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)['DBInstances'][0]

        # --- INICIO DE LA MODIFICACIÓN: Comprobación de acceso público ---
        # Primero, verificamos si la instancia es públicamente accesible.
        if db.get('PubliclyAccessible', False):
            public_ip = "No resuelta"
            try:
                # Intentamos resolver la IP solo para mostrarla en el mensaje de error.
                endpoint_address = db.get('Endpoint', {}).get('Address')
                if endpoint_address:
                    public_ip = socket.gethostbyname(endpoint_address)
            except Exception:
                pass # Si no se puede resolver, no es crítico.
            
            # Creamos un mensaje de error claro y explicativo.
            error_message = (f"Análisis no soportado: La instancia RDS '{db_identifier}' es públicamente accesible (IP: {public_ip}). "
                           "Esta herramienta solo puede analizar rutas de red privadas dentro de una VPC. "
                           "Para poder realizar el análisis, la base de datos debería tener el 'Acceso público' configurado en 'No' en la consola de AWS.")
            raise ValueError(error_message)
        # --- FIN DE LA MODIFICACIÓN ---

        endpoint = db.get('Endpoint', {}).get('Address')
        if not endpoint:
            raise ValueError(f"La instancia RDS '{db_identifier}' no tiene un endpoint (podría estar creándose o en un estado no disponible).")
        
        try:
            private_ip = socket.gethostbyname(endpoint)
        except socket.gaierror:
            raise ValueError(f"No se pudo resolver la IP privada para el endpoint de RDS: {endpoint}")

        all_subnets_in_vpc = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [db['DBSubnetGroup']['VpcId']]}])['Subnets']
        current_subnet_id = None
        for subnet in all_subnets_in_vpc:
            if ipaddress.ip_address(private_ip) in ipaddress.ip_network(subnet['CidrBlock']):
                current_subnet_id = subnet['SubnetId']
                break
        
        if not current_subnet_id:
            # Este error ahora solo saltará en casos muy extraños de configuración de red.
            raise ValueError(f"No se pudo determinar la subred actual para la IP {private_ip} de la instancia RDS.")

        return {
            "id": db['DBInstanceIdentifier'], "service": "RDS",
            "private_ip": private_ip,
            "subnet_id": current_subnet_id, "vpc_id": db['DBSubnetGroup']['VpcId'],
            "security_group_ids": [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            raise ValueError(f"No se encontró la instancia RDS con identificador '{db_identifier}'.")
        raise


def pg_get_lambda_details(session, region, function_name, ec2_client):
    """Obtiene detalles de red de una función Lambda conectada a una VPC."""
    lambda_client = session.client('lambda', region_name=region)
    try:
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        vpc_config = config.get('VpcConfig')
        if not (vpc_config and vpc_config.get('VpcId')):
            raise ValueError(f"La función Lambda '{function_name}' no está conectada a una VPC. El análisis solo es posible para Lambdas en una VPC.")

        paginator = ec2_client.get_paginator('describe_network_interfaces')
        pages = paginator.paginate(Filters=[
            {'Name': 'group-id', 'Values': vpc_config['SecurityGroupIds']},
            {'Name': 'description', 'Values': [f'AWS Lambda VPC ENI-{function_name}-*']}
        ])
        eni = next((eni for page in pages for eni in page['NetworkInterfaces']), None)

        if not (eni and eni.get('PrivateIpAddress')):
            raise ValueError(f"No se pudo encontrar una interfaz de red (ENI) con una IP privada para la función Lambda '{function_name}'. Puede que se esté desplegando.")

        return {
            "id": config['FunctionName'], "service": "Lambda",
            "private_ip": eni['PrivateIpAddress'],
            "subnet_id": eni['SubnetId'], "vpc_id": eni['VpcId'],
            "security_group_ids": [sg['GroupId'] for sg in eni['Groups']]
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise ValueError(f"No se encontró la función Lambda con el nombre '{function_name}'.")
        raise

def pg_get_resource_network_details(session, arn):
    """Función 'dispatcher' que obtiene detalles de red para cualquier recurso soportado."""
    try:
        parts = arn.split(':')
        service = parts[2]
        region = parts[3]
        resource_full = ":".join(parts[5:])
        
        ec2_client = session.client('ec2', region_name=region)

        if service == 'ec2' and resource_full.startswith('instance/'):
            instance_id = resource_full.split('/')[1]
            return pg_get_ec2_details(ec2_client, instance_id)
        elif service == 'rds' and resource_full.startswith('db:'):
            db_identifier = resource_full[3:]
            return pg_get_rds_details(session, region, db_identifier, ec2_client)
        elif service == 'lambda' and resource_full.startswith('function:'):
            function_name = resource_full[9:]
            return pg_get_lambda_details(session, region, function_name, ec2_client)
        else:
            raise ValueError(f"Tipo de ARN no soportado: '{arn}'. Solo se soportan instancias EC2, RDS y funciones Lambda (en VPC).")
    except (IndexError, AttributeError):
        raise ValueError(f"El formato del ARN '{arn}' es inválido.")

def pg_check_nacl_fully(ec2_client, subnet_id, direction, remote_ip, protocol, port):
    try:
        response = ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        acl = response['NetworkAcls'][0]
    except (IndexError, ClientError):
        vpc_id_res = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]['VpcId']
        response = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id_res]}, {'Name': 'default', 'Values': ['true']}])
        acl = response['NetworkAcls'][0]

    protocol_str = str(protocol)
    rules = sorted([e for e in acl['Entries'] if e['Egress'] == (direction == 'outbound')], key=lambda x: x['RuleNumber'])

    for rule in rules:
        if rule['RuleNumber'] == 32767: continue
        cidr = rule.get('CidrBlock')
        if not (cidr and ipaddress.ip_address(remote_ip) in ipaddress.ip_network(cidr)): continue
        rule_protocol = rule.get('Protocol')
        if rule_protocol != '-1' and rule_protocol != protocol_str: continue
        port_range = rule.get('PortRange', {})
        rule_from_port = port_range.get('From')
        if rule_from_port is not None:
            rule_to_port = port_range.get('To')
            if port != -1 and not (port >= rule_from_port and port <= rule_to_port): continue
        
        matched_rule = {**rule, 'AclId': acl['NetworkAclId']}
        if rule['RuleAction'] == 'deny': return False, matched_rule
        return True, matched_rule
    
    implicit_deny_rule = {'RuleNumber': '*', 'RuleAction': 'deny', 'AclId': acl['NetworkAclId'], 'CidrBlock': '0.0.0.0/0'}
    return False, implicit_deny_rule

def pg_check_route_table(ec2_client, source_subnet_id, dest_ip):
    try:
        response = ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [source_subnet_id]}])
        if not response['RouteTables']:
            subnet_info = ec2_client.describe_subnets(SubnetIds=[source_subnet_id])
            vpc_id = subnet_info['Subnets'][0]['VpcId']
            response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'association.main', 'Values': ['true']}])

        rt = response['RouteTables'][0]
        best_route = None
        longest_prefix = -1

        for route in rt['Routes']:
            cidr = ipaddress.ip_network(route['DestinationCidrBlock'])
            if ipaddress.ip_address(dest_ip) in cidr:
                if cidr.prefixlen > longest_prefix:
                    longest_prefix = cidr.prefixlen
                    best_route = route
        
        if best_route:
            target = next((v for k, v in best_route.items() if k.endswith('GatewayId') or k.endswith('InstanceId') or k.endswith('InterfaceId') or k.endswith('PeeringConnectionId')), 'local')
            return True, {'RouteTableId': rt['RouteTableId'], 'Destination': best_route['DestinationCidrBlock'], 'Target': target}
    except (ClientError, IndexError):
        pass
    return False, {'RouteTableId': 'N/A', 'Destination': 'N/A', 'Target': 'No Route Found'}

def pg_build_decision_table(path_info, consolidated_ports):
    rows_data = []
    def get_sg_source_dest(rule):
        key_order = ['IpRanges', 'UserIdGroupPairs', 'PrefixListIds']
        key_extract = {'IpRanges': 'CidrIp', 'UserIdGroupPairs': 'GroupId', 'PrefixListIds': 'PrefixListId'}
        for key in key_order:
            items = rule.get(key)
            if items: return items[0].get(key_extract[key], 'N/A')
        return 'N/A'

    sg_out = path_info['source_sg_rule']
    rows_data.append(["SG Origen", path_info['source_sg_id'], "Egress", "N/A", "allow", str(sg_out.get('IpProtocol','-1')), f"{sg_out.get('FromPort', 'All')}-{sg_out.get('ToPort', 'All')}".replace('-1','All'), get_sg_source_dest(sg_out)])
    nacl_out = path_info['source_nacl_rule']
    rows_data.append(["NACL Origen", nacl_out.get('AclId'), "Egress", str(nacl_out.get('RuleNumber')), nacl_out.get('RuleAction'), str(nacl_out.get('Protocol','-1')), f"{nacl_out.get('PortRange',{}).get('From','All')}-{nacl_out.get('PortRange',{}).get('To','All')}", nacl_out.get('CidrBlock')])
    route_info = path_info['route_rule']
    rows_data.append(["Route Table", route_info.get('RouteTableId'), "Forwarding", route_info.get('Destination'), "N/A", "N/A", "N/A", route_info.get('Target')])
    nacl_in = path_info['target_nacl_rule']
    rows_data.append(["NACL Destino", nacl_in.get('AclId'), "Ingress", str(nacl_in.get('RuleNumber')), nacl_in.get('RuleAction'), str(nacl_in.get('Protocol','-1')), f"{nacl_in.get('PortRange',{}).get('From','All')}-{nacl_in.get('PortRange',{}).get('To','All')}", nacl_in.get('CidrBlock')])
    sg_in = path_info['target_sg_rule']
    rows_data.append(["SG Destino", path_info['target_sg_id'], "Ingress", "N/A", "allow", str(sg_in.get('IpProtocol','-1')), consolidated_ports, get_sg_source_dest(sg_in)])
    
    title = f"Ruta de Decisión para {consolidated_ports}:"
    headers = ["Capa", "ID Recurso", "Dirección", "Destino/Regla", "Acción", "Protocolo", "Puerto(s)", "Origen/Target"]
    return _format_to_table(headers, rows_data, title)

def pg_consolidate_ports(port_tuples):
    if not port_tuples: return ""
    ports_by_proto = defaultdict(set)
    for proto, from_port, to_port in port_tuples:
        proto_str = PROTOCOLS.get(str(proto), str(proto))
        if from_port == -1: ports_by_proto[proto_str] = {"All"}; continue
        ports_by_proto[proto_str].add(f"{from_port}-{to_port}" if from_port != to_port else str(from_port))
    
    output_parts = []
    for proto, ports in sorted(ports_by_proto.items()):
        if "All" in ports: output_parts.append(f"Todos los puertos {proto}"); continue
        sorted_ports = sorted(list(ports), key=lambda x: tuple(map(int, x.split('-'))) if '-' in x else (int(x),))
        output_parts.append(f"Puerto(s) {', '.join(sorted_ports)} ({proto})")
    return " | ".join(output_parts)

def analyze_network_path_data(session, source_arn, target_arn):
    """Función principal que ahora usa el dispatcher para analizar la ruta."""
    source = pg_get_resource_network_details(session, source_arn)
    target = pg_get_resource_network_details(session, target_arn)

    if source['vpc_id'] != target['vpc_id']:
        return {'status': 'UNREACHABLE', 'reason': f"Los recursos están en VPCs diferentes ({source['vpc_id']} y {target['vpc_id']}) y este análisis no cubre Peering/Transit Gateway.", 'tables': [], 'detail_tables': {}}
    
    region = source_arn.split(':')[3]
    ec2 = session.client('ec2', region_name=region)
    
    route_ok, route_rule = pg_check_route_table(ec2, source['subnet_id'], target['private_ip'])
    if not route_ok:
        return {'status': 'UNREACHABLE', 'reason': f"No se encontró una ruta en la tabla '{route_rule.get('RouteTableId')}' desde la subred de origen hacia la IP de destino '{target['private_ip']}'.", 'tables': [], 'detail_tables': {}}

    result = {
        'status': 'UNREACHABLE', 'reason': 'No hay reglas en el SG de origen/destino que permitan la conexión.',
        'perms': [], 'tables': [], 'detail_tables': {}
    }
    
    source_sgs_rules = ec2.describe_security_groups(GroupIds=source['security_group_ids'])['SecurityGroups']
    target_sgs_rules = ec2.describe_security_groups(GroupIds=target['security_group_ids'])['SecurityGroups']
    path_found_for_target = False

    for sg_out_details in source_sgs_rules:
        for egress_rule in sg_out_details.get('IpPermissionsEgress', []):
            target_matches_egress_rule = any(ipaddress.ip_address(target['private_ip']) in ipaddress.ip_network(ip_range.get('CidrIp', '0.0.0.0/32')) for ip_range in egress_rule.get('IpRanges', [])) or \
                                         any(sg_ref.get('GroupId') in target['security_group_ids'] for sg_ref in egress_rule.get('UserIdGroupPairs', []))
            if not target_matches_egress_rule: continue

            for target_sg_details in target_sgs_rules:
                for ingress_rule in target_sg_details.get('IpPermissions', []):
                    egress_proto = egress_rule.get('IpProtocol', '-1')
                    ingress_proto = ingress_rule.get('IpProtocol', '-1')
                    if not (egress_proto == ingress_proto or egress_proto == '-1' or ingress_proto == '-1'): continue
                    
                    egress_from, egress_to = egress_rule.get('FromPort', -1), egress_rule.get('ToPort', -1)
                    ingress_from, ingress_to = ingress_rule.get('FromPort', -1), ingress_rule.get('ToPort', -1)
                    if not (egress_from == -1 or ingress_from == -1 or max(egress_from, ingress_from) <= min(egress_to, ingress_to)): continue

                    source_allowed = any(ipaddress.ip_address(source['private_ip']) in ipaddress.ip_network(in_cidr.get('CidrIp', '0.0.0.0/32')) for in_cidr in ingress_rule.get('IpRanges',[])) or \
                                     any(in_sg_ref.get('GroupId') in source['security_group_ids'] for in_sg_ref in ingress_rule.get('UserIdGroupPairs',[]))
                    if not source_allowed: continue
                    
                    report_proto = ingress_proto if egress_proto == '-1' and ingress_proto != '-1' else egress_proto
                    report_from = ingress_from if egress_from == -1 and ingress_from != -1 else egress_from
                    
                    nacl_out_allowed, nacl_out_rule = pg_check_nacl_fully(ec2, source['subnet_id'], 'outbound', target['private_ip'], report_proto, report_from if report_from != -1 else 0)
                    if not nacl_out_allowed:
                        result['reason'] = f"Bloqueado por NACL de salida: Regla #{nacl_out_rule.get('RuleNumber')} ({nacl_out_rule.get('RuleAction')} en {nacl_out_rule.get('AclId')})"; continue
                    
                    nacl_in_allowed, nacl_in_rule = pg_check_nacl_fully(ec2, target['subnet_id'], 'inbound', source['private_ip'], report_proto, report_from if report_from != -1 else 0)
                    if not nacl_in_allowed:
                        result['reason'] = f"Bloqueado por NACL de entrada: Regla #{nacl_in_rule.get('RuleNumber')} ({nacl_in_rule.get('RuleAction')} en {nacl_in_rule.get('AclId')})"; continue
                    
                    path_found_for_target = True
                    result['status'] = 'REACHABLE'
                    result['perms'].append({
                        'perm_tuple': (ingress_proto, ingress_from, ingress_rule.get('ToPort', -1)),
                        'source_sg_rule': egress_rule, 'source_sg_id': sg_out_details['GroupId'],
                        'target_sg_rule': ingress_rule, 'target_sg_id': target_sg_details['GroupId'],
                        'source_nacl_rule': nacl_out_rule, 'target_nacl_rule': nacl_in_rule,
                        'route_rule': route_rule
                    })
    
    if path_found_for_target:
        result['reason'] = ''
        grouped_paths = defaultdict(list)
        involved_ids = set()

        for perm_path in result['perms']:
            path_signature = (perm_path['source_sg_id'], perm_path['target_sg_id'], perm_path['source_nacl_rule']['AclId'], perm_path['source_nacl_rule']['RuleNumber'], perm_path['target_nacl_rule']['AclId'], perm_path['target_nacl_rule']['RuleNumber'], str(perm_path['source_sg_rule']), str(perm_path['target_sg_rule']), str(perm_path['route_rule']))
            grouped_paths[path_signature].append(perm_path['perm_tuple'])
        
        for perms in grouped_paths.values():
            representative_path = next(p for p in result['perms'] if p['perm_tuple'] in perms)
            consolidated_ports_str = pg_consolidate_ports(perms)
            result['tables'].append(pg_build_decision_table(representative_path, consolidated_ports_str))
            
            involved_ids.add(("sg", representative_path['source_sg_id']))
            involved_ids.add(("sg", representative_path['target_sg_id']))
            involved_ids.add(("nacl", representative_path['source_nacl_rule']['AclId']))
            involved_ids.add(("nacl", representative_path['target_nacl_rule']['AclId']))
            involved_ids.add(("rtb", representative_path['route_rule']['RouteTableId']))

        for type, res_id in sorted(list(involved_ids)):
            if res_id not in result['detail_tables']:
                if type == "sg": result['detail_tables'][res_id] = pg_format_sg_rules(ec2, res_id)
                elif type == "nacl": result['detail_tables'][res_id] = pg_format_nacl_rules(ec2, res_id)
                elif type == "rtb": result['detail_tables'][res_id] = pg_format_route_table(ec2, res_id)

    del result['perms']
    return result

# --- INICIO: NUEVA LÓGICA PARA AWS CONFIG & SECURITY HUB ---

def sh_check_regional_services(session, regions):
    """
    MODIFICADO: Ahora también devuelve un mapa para relacionar cada control con su estándar.
    """
    results = []
    # Este mapa nos ayudará a saber a qué estándar pertenece cada control (ej: 'ACM.1' -> 'arn:aws:.../aws-foundational-security-best-practices/v/1.0.0')
    control_to_standard_map = {}

    for region in regions:
        region_status = {
            "Region": region, "ConfigEnabled": False, "SecurityHubEnabled": False,
            "EnabledStandards": [], "EnabledConformancePacks": [],
            "ComplianceSummaries": []
        }
        try:
            config_client = session.client("config", region_name=region)
            # ... (el resto del chequeo de Config no cambia)
            status = config_client.describe_configuration_recorder_status()
            if status.get("ConfigurationRecordersStatus") and status["ConfigurationRecordersStatus"][0].get("recording"):
                region_status["ConfigEnabled"] = True
                try:
                    cp_response = config_client.describe_conformance_packs()
                    for cp in cp_response.get('ConformancePackDetails', []):
                        region_status["EnabledConformancePacks"].append(cp.get('ConformancePackName'))
                except ClientError: pass
        except ClientError: pass
            
        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub()
            region_status["SecurityHubEnabled"] = True
            
            try:
                standards_response = securityhub_client.get_enabled_standards()
                for standard in standards_response.get('StandardsSubscriptions', []):
                    standard_arn_full = standard.get('StandardsArn', 'unknown')
                    region_status["EnabledStandards"].append(standard_arn_full)
                    
                    standard_subscription_arn = standard.get('StandardsSubscriptionArn')
                    controls = securityhub_client.describe_standards_controls(
                        StandardsSubscriptionArn=standard_subscription_arn
                    ).get('Controls', [])

                    if not controls: continue

                    # --- Lógica de mapeo añadida ---
                    for control in controls:
                        control_id = control.get('ControlId')
                        if control_id:
                            control_to_standard_map[control_id] = standard_arn_full
                    
                    # El cálculo de contadores aquí ya no es necesario para el gráfico, 
                    # pero lo dejamos por si se usa en otro lado.
                    passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                    region_status["ComplianceSummaries"].append({
                        "standardArn": standard_arn_full,
                        "standardName": standard_arn_full.split('/standard/')[-1].replace('-', ' ').title(),
                        "totalControls": len(controls),
                        "passedCount": passed_count
                    })
            except ClientError: pass
        except ClientError: pass
            
        results.append(region_status)
    # Devolvemos tanto los resultados como el mapa de controles
    return results, control_to_standard_map

def collect_config_sh_status_only(session):
    """
    FUNCIÓN RÁPIDA: Obtiene solo el estado de activación de Config y SH por región,
    incluyendo los estándares y conformance packs habilitados.
    """
    regions = get_all_aws_regions(session)
    # Reutilizamos la función existente que ya obtiene eficientemente esta información
    service_status_results = sh_check_regional_services(session, regions)

    return {
        "service_status": service_status_results
    }

def get_compliance_for_region(securityhub_client):
    """
    Recibe un cliente de Security Hub ya inicializado para una región activa
    y devuelve el resumen de cumplimiento para sus estándares.
    """
    compliance_summary = []
    try:
        enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])
        for standard in enabled_standards:
            standard_arn = standard.get('StandardsSubscriptionArn')
            standard_name_raw = standard.get('StandardsArn', 'N/A').split('/standard/')[-1].replace('-', ' ').title()

            controls = securityhub_client.describe_standards_controls(
                StandardsSubscriptionArn=standard_arn
            ).get('Controls', [])

            if not controls:
                continue

            passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
            total_controls = len(controls)
            compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

            compliance_summary.append({
                "standardName": standard_name_raw,
                "compliancePercentage": round(compliance_percentage, 2),
                "passedCount": passed_count,
                "totalControls": total_controls,
            })
    except Exception as e:
        print(f"    [!] No se pudo obtener el resumen de cumplimiento: {e}")

    return compliance_summary

def sh_get_security_hub_findings(session, service_status):
    """
    Obtiene todos los findings ACTIVOS de Security Hub de todas las regiones.
    Adaptado de securityhub.py para la API web (sin prints/tqdm).
    """
    all_findings = []
    active_regions = [r['Region'] for r in service_status if r['SecurityHubEnabled']]
    
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            pages = paginator.paginate(Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]})
            for page in pages:
                all_findings.extend(page['Findings'])
        except ClientError:
            pass # Si falla (ej. permisos), se omite la región.
            
    return all_findings

def collect_config_sh_data(session):
    """
    MODIFICADO: Reconstruye el resumen de cumplimiento basándose en los hallazgos
    para asegurar consistencia entre las pestañas.
    """
    regions = get_all_aws_regions(session)
    service_status_results, control_map = sh_check_regional_services(session, regions)
    findings = sh_get_security_hub_findings(session, service_status_results)
    
    compliance_summary_map = {}
    for region_data in service_status_results:
        for summary in region_data.get("ComplianceSummaries", []):
            arn = summary['standardArn']
            if arn not in compliance_summary_map:
                compliance_summary_map[arn] = {
                    "standardArn": arn,
                    "standardName": summary['standardName'],
                    "totalControls": summary.get('totalControls', 0),
                    "passedCount": 0, "failedCount": 0, "warningCount": 0, 
                    "notAvailableCount": 0, "otherCount": 0
                }

    for finding in findings:
        status = finding.get('Compliance', {}).get('Status')
        control_id = finding.get('Compliance', {}).get('SecurityControlId')
        
        standard_arn = control_map.get(control_id)

        if standard_arn and standard_arn in compliance_summary_map:
            if status == 'PASSED':
                compliance_summary_map[standard_arn]['passedCount'] += 1
            elif status == 'FAILED':
                compliance_summary_map[standard_arn]['failedCount'] += 1
            elif status == 'WARNING':
                compliance_summary_map[standard_arn]['warningCount'] += 1
            elif status == 'NOT_AVAILABLE':
                compliance_summary_map[standard_arn]['notAvailableCount'] += 1

    final_summary = []
    for arn, data in compliance_summary_map.items():
        counted = data['passedCount'] + data['failedCount'] + data['warningCount'] + data['notAvailableCount']
        
        # --- ▼▼▼ LÍNEA CORREGIDA ▼▼▼ ---
        # Nos aseguramos de que el resultado de la resta nunca sea menor que 0.
        data['otherCount'] = max(0, data['totalControls'] - counted)
        # --- ▲▲▲ FIN DE LA CORRECCIÓN ▲▲▲ ---

        final_summary.append(data)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99))

    return {
        "service_status": service_status_results,
        "findings": findings,
        "compliance_summary": final_summary
    }

# --- FIN: NUEVA LÓGICA PARA AWS CONFIG & SECURITY HUB ---


# --- Endpoints de la API ---

@app.route('/api/run-securityhub-audit', methods=['POST'])
def run_securityhub_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        all_regions = get_all_aws_regions(session)
        service_status = check_security_hub_status_in_regions(session, all_regions)
        findings_data = get_and_filter_security_hub_findings(session, service_status)
        enabled_service_status = [s for s in service_status if s['SecurityHubEnabled']]
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z") }, "results": { "servicesStatus": enabled_service_status, "findings": findings_data } })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Security Hub: {str(e)}"}), 500

@app.route('/api/run-exposure-audit', methods=['POST'])
def run_exposure_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        exposure_results = collect_exposure_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": exposure_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar la exposición a Internet: {str(e)}"}), 500

@app.route('/api/run-guardduty-audit', methods=['POST'])
def run_guardduty_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        guardduty_results = collect_guardduty_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": guardduty_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de GuardDuty: {str(e)}"}), 500

@app.route('/api/run-waf-audit', methods=['POST'])
def run_waf_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        waf_results = collect_waf_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": waf_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de WAF: {str(e)}"}), 500

@app.route('/api/run-cloudtrail-audit', methods=['POST'])
def run_cloudtrail_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        cloudtrail_results = collect_cloudtrail_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudtrail_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de CloudTrail: {str(e)}"}), 500

@app.route('/api/run-cloudtrail-lookup', methods=['POST'])
def run_cloudtrail_lookup():
    session, error = get_session(request.get_json())
    if error:
        return jsonify({"error": error}), 401
    
    data = request.get_json()
    event_name = data.get('event_name')
    start_date_str = data.get('start_date')
    end_date_str = data.get('end_date')
    region = data.get('region')

    if not all([start_date_str, end_date_str, region]):
        return jsonify({"error": "Faltan parámetros. Se requiere 'start_date', 'end_date' y 'region'."}), 400
        
    try:
        # Añadir la hora para cubrir el día completo
        start_time = datetime.strptime(start_date_str, '%d-%m-%Y').replace(tzinfo=pytz.utc)
        end_time = (datetime.strptime(end_date_str, '%d-%m-%Y') + timedelta(days=1, seconds=-1)).replace(tzinfo=pytz.utc)

    except ValueError:
        return jsonify({"error": "Formato de fecha inválido. Utilice 'dd-mm-yyyy'."}), 400

    try:
        lookup_results = lookup_cloudtrail_events(session, region, event_name, start_time, end_time)
        return jsonify({"results": lookup_results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-cloudwatch-audit', methods=['POST'])
def run_cloudwatch_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        cloudwatch_results = collect_cloudwatch_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudwatch_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de CloudWatch/SNS: {str(e)}"}), 500

@app.route('/api/run-inspector-audit', methods=['POST'])
def run_inspector_audita():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inspector_results = collect_inspector_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Inspector: {str(e)}"}), 500

@app.route('/api/run-acm-audit', methods=['POST'])
def run_acm_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        acm_results = collect_acm_data_web(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": acm_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de ACM: {str(e)}"}), 500

@app.route('/api/run-compute-audit', methods=['POST'])
def run_compute_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        compute_results = collect_compute_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": compute_results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Compute: {str(e)}"}), 500


@app.route('/api/run-databases-audit', methods=['POST'])
def run_databases_audit():
    session, error = get_session(request.get_json())
    if error: 
        return jsonify({"error": error}), 401
    try:
        database_results = collect_database_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": database_results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Databases: {str(e)}"}), 500


@app.route('/api/run-network-policies-audit', methods=['POST'])
def run_network_policies_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        network_policies_results = collect_network_policies_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": network_policies_results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Network Policies: {str(e)}"}), 500
        

@app.route('/api/run-config-sh-audit', methods=['POST'])
def run_config_sh_audit():
    session, error = get_session(request.get_json())
    if error: 
        return jsonify({"error": error}), 401
    try:
        results = collect_config_sh_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de Config & Security Hub: {str(e)}"}), 500

@app.route('/api/run-config-sh-status-audit', methods=['POST'])
def run_config_sh_status_audit():
    session, error = get_session(request.get_json())
    if error: 
        return jsonify({"error": error}), 401
    try:
        # Llamamos a una función que solo obtiene el estado, es mucho más rápida
        regions = get_all_aws_regions(session)
        
        # --- ▼▼▼ LÍNEA CORREGIDA ▼▼▼ ---
        # Ahora desempaquetamos la tupla, ignorando el segundo valor (el mapa) que no necesitamos aquí.
        service_status, _ = sh_check_regional_services(session, regions)
        # --- ▲▲▲ FIN DE LA CORRECCIÓN ▲▲▲ ---
        
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": {
                "service_status": service_status
            }
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar el estado de Config & SH: {str(e)}"}), 500



@app.route('/api/run-network-detail-audit', methods=['POST'])
def run_network_detail_audit():
    session, error = get_session(request.get_json())
    if error:
        return jsonify({"error": error}), 401

    data = request.get_json()
    resource_id = data.get('resource_id')
    region = data.get('region')

    if not resource_id or not region:
        return jsonify({"error": "Se requiere el ID del recurso y la región."}), 400

    try:
        ec2_client = session.client("ec2", region_name=region)
        details_table = ""

        if resource_id.startswith('sg-'):
            sg_details = ec2_client.describe_security_groups(GroupIds=[resource_id])
            details_table = format_sg_details_table(sg_details)
        elif resource_id.startswith('acl-'):
            nacl_details = ec2_client.describe_network_acls(NetworkAclIds=[resource_id])
            details_table = format_nacl_details_table(nacl_details)
        else:
            return jsonify({"error": "ID de recurso no válido. Debe empezar con 'sg-' o 'acl-'."}), 400
        
        return jsonify({"results": {"details_table": details_table}})

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if 'NotFound' in error_code:
            return jsonify({"error": f"No se encontró el recurso con ID '{resource_id}' en la región '{region}'."}), 404
        return jsonify({"error": f"Error de AWS: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500


@app.route('/api/run-connectivity-audit', methods=['POST'])
def run_connectivity_audit():
    session, error = get_session(request.get_json())
    if error: 
        return jsonify({"error": error}), 401
    try:
        connectivity_results = collect_connectivity_data(session)
        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": connectivity_results
        })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de conectividad: {str(e)}"}), 500


@app.route('/api/run-playground-audit', methods=['POST'])
def run_playground_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        data = request.get_json()
        source_arn = data.get('source_arn')
        target_arn = data.get('target_arn')
        if not source_arn or not target_arn:
            return jsonify({"error": "Se requiere el ARN de origen y de destino."}), 400

        path_results = analyze_network_path_data(session, source_arn, target_arn)

        if 'error' in path_results:
            return jsonify(path_results), 400

        sts = session.client("sts")
        return jsonify({
            "metadata": {
                "accountId": sts.get_caller_identity()["Account"],
                "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")
            },
            "results": path_results
        })
    except ValueError as e: 
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error inesperado al analizar la ruta de red: {str(e)}"}), 500

@app.route('/api/run-kms-audit', methods=['POST'])
def run_kms_audit():
    session, error = get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        kms_results = collect_kms_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": kms_results })
    except Exception as e:
        return jsonify({"error": f"Error inesperado al recopilar datos de KMS: {str(e)}"}), 500

@app.route('/api/run-sslscan', methods=['POST'])
def run_sslscan():
    data = request.get_json()
    targets_str = data.get('target')

    if not targets_str:
        return jsonify({"error": "No se ha proporcionado ningún objetivo (target)."}), 400

    targets = [t.strip() for t in targets_str.split(',')]
    results = []
    
    # Importamos la librería 'shutil' para encontrar el ejecutable
    import shutil
    import subprocess

    # Comprobamos si 'sslscan' está disponible en el PATH del sistema
    if not shutil.which("sslscan"):
        # Si no se encuentra, devolvemos un error claro y terminamos
        error_msg = "El comando 'sslscan' no se encuentra en el PATH de tu sistema. Asegúrate de que está instalado y accesible."
        return jsonify({"results": [{"target": ", ".join(targets), "error": error_msg}]})
    # --- FIN DE LA MODIFICACIÓN ---

    threads = []

    def scan_target(target):
        safe_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
        if not all(char in safe_characters for char in target) or not target:
            results.append({"target": target, "error": "El objetivo contiene caracteres no válidos o está vacío."})
            return
        
        try:
            # --- LÍNEA CORREGIDA ---
            # Ahora usamos 'sslscan' directamente, sin la ruta fija.
            command = ['sslscan', '--no-colour', target]
            
            print(f"Ejecutando comando: {' '.join(command)}")

            result = subprocess.run(
                command, capture_output=True, text=True, timeout=120, check=False
            )

            if not result.stdout and not result.stderr:
                results.append({"target": target, "error": "El comando se ejecutó pero no devolvió ninguna salida. Revisa los permisos o la instalación de sslscan en el servidor."})
            else:
                full_output = result.stdout + result.stderr
                results.append({"target": target, "output": full_output})

        except FileNotFoundError:
            results.append({"target": target, "error": f"Comando no encontrado. Verifica que sslscan esté instalado y en el PATH del sistema."})
        except subprocess.TimeoutExpired:
            results.append({"target": target, "error": "El escaneo ha superado el tiempo de espera (120 segundos)."})
        except Exception as e:
            results.append({"target": target, "error": f"Ha ocurrido un error inesperado: {str(e)}"})

    for target in targets:
        thread = threading.Thread(target=scan_target, args=(target,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return jsonify({"results": results})

# ==============================================================================
# ENDPOINT PARA EL EXECUTIVE SUMMARY
# ==============================================================================

@app.route('/run_executive_summary', methods=['POST'])
def run_executive_summary():
    """
    Recibe los datos de la auditoría y los procesa con el motor de reglas.
    """
    audit_data = request.json
    if not audit_data:
        return jsonify({"error": "No audit data provided"}), 400

    # --- LOG AÑADIDO ---
    # Imprimimos en la terminal los datos que acabamos de recibir.
    import json
    print("\n" + "="*50)
    print("--- DATOS RECIBIDOS EN EL ENDPOINT /run_executive_summary ---")
    print(json.dumps(audit_data, indent=2))
    print("="*50 + "\n")


    executive_summary_findings = []

    for rule in RULES_TO_CHECK:
        check_function = rule.get("check_function")
        
        if callable(check_function):
            violating_resources_raw = check_function(audit_data)

            if violating_resources_raw:
                affected_resources_structured = []
                for resource in violating_resources_raw:
                    if isinstance(resource, dict):
                        affected_resources_structured.append({
                            "display": f"{resource['resource']} en {resource['region']}",
                            "region": resource.get("region", "Global")
                        })
                    else:
                        affected_resources_structured.append({
                            "display": str(resource),
                            "region": "Global"
                        })
                
                finding = {
                    "rule_id": rule.get("rule_id"),
                    "name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                    "remediation": rule.get("remediation"),
                    "status": "🚩 RED FLAG",
                    "affected_resources": affected_resources_structured
                }
                executive_summary_findings.append(finding)

    return jsonify(executive_summary_findings)


# --- Ejecución del servidor ---
if __name__ == '__main__':
    # Define el puerto y la URL para que sea fácil de cambiar
    port = 5001
    url = f"http://127.0.0.1:{port}/dashboard.html"

    # Función que abrirá el navegador
    def open_browser():
        webbrowser.open_new(url)

    # Inicia el servidor Flask
    # Usamos un temporizador para darle un instante al servidor para que arranque
    # antes de intentar abrir el navegador.
    threading.Timer(1, open_browser).start()
    
    # El debug=False es mejor para este comportamiento, 
    # ya que evita que el script se ejecute dos veces al iniciar.
    app.run(host='0.0.0.0', port=port, debug=False)