# ==============================================================================
# rules.py - Motor de Reglas para AudiThor-AWS (ACTUALIZADO)
# ==============================================================================
from datetime import datetime, timezone

# ------------------------------------------------------------------------------
# 1. Definición de Niveles de Severidad
# ------------------------------------------------------------------------------
SEVERITY = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Medio",
    "LOW": "Bajo",
    "INFO": "Informativo"
}

# ------------------------------------------------------------------------------
# 2. Funciones de Chequeo de Reglas
# ------------------------------------------------------------------------------

def check_mfa_for_all_users(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        if not user.get("MFADevices"):
            failing_resources.append(user.get("arn", user.get("UserName")))
    return failing_resources

def check_iam_access_key_age(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    ninety_days = 90
    now = datetime.now(timezone.utc)
    for user in users:
        for key in user.get("AccessKeys", []):
            try:
                create_date_str = key.get("CreateDate")
                create_date = datetime.fromisoformat(create_date_str)
                age = now - create_date
                if age.days > ninety_days:
                    user_identifier = user.get("arn", user.get("UserName"))
                    if user_identifier not in failing_resources:
                        failing_resources.append(user_identifier)
            except (ValueError, TypeError):
                continue
    return failing_resources


def check_password_policy_strength(audit_data):
    policy = audit_data.get("iam", {}).get("password_policy", {})
    if policy.get("Error"):
        return ["Account Password Policy"]
    checks = [
        policy.get("MinimumPasswordLength", 0) >= 12,
        policy.get("RequireUppercaseCharacters") is True,
        policy.get("RequireLowercaseCharacters") is True,
        policy.get("RequireNumbers") is True,
        policy.get("RequireSymbols") is True,
        policy.get("MaxPasswordAge") is not None and policy.get("MaxPasswordAge") <= 90,
        policy.get("PasswordReusePrevention", 0) >= 4,
    ]
    if not all(checks):
        return ["Account Password Policy"]
    return []


def check_guardduty_disabled(audit_data):
    """Verifica si GuardDuty está deshabilitado o suspendido."""
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])
    
    # CORRECCIÓN: Si la lista está vacía, significa que no está habilitado en NINGUNA parte.
    if not guardduty_status:
        failing_resources.append({"resource": "GuardDuty", "region": "Todas las regiones"})
        return failing_resources

    for status in guardduty_status:
        if status.get("Status") != "Habilitado":
            failing_resources.append({
                "resource": "GuardDuty",
                "region": status.get("Region")
            })
    return failing_resources

def check_config_disabled(audit_data):
    """Verifica si AWS Config está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    # CORRECCIÓN: Comprobamos si hay alguna región con el servicio activo.
    # Si ninguna lo está, se devuelve un hallazgo global.
    if not any(s.get("ConfigEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "AWS Config", "region": "Todas las regiones"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("ConfigEnabled"):
            failing_resources.append({
                "resource": "AWS Config",
                "region": status.get("Region")
            })
    return failing_resources

def check_security_hub_disabled(audit_data):
    """Verifica si AWS Security Hub está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    # CORRECCIÓN: Misma lógica que para AWS Config.
    if not any(s.get("SecurityHubEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "Security Hub", "region": "Todas las regiones"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("SecurityHubEnabled"):
            failing_resources.append({
                "resource": "Security Hub",
                "region": status.get("Region")
            })
    return failing_resources

def check_inspector_platform_eol(audit_data):
    """
    Busca hallazgos de Inspector que indiquen que una plataforma ha llegado al final de su vida útil (End of Life).
    """
    failing_resources = []
    
    # --- ▼▼▼ LÍNEA CORREGIDA ▼▼▼ ---
    # Eliminamos el ".get("results", {})" extra para acceder directamente a los hallazgos.
    inspector_findings = audit_data.get("inspector", {}).get("findings", [])
    # --- ▲▲▲ FIN DE LA CORRECCIÓN ▲▲▲ ---

    for finding in inspector_findings:
        # Comprobamos si el título del hallazgo contiene la frase clave
        if "Platform End Of Life" in finding.get("title", ""):
            # Si la encuentra, extraemos el ID del recurso afectado para reportarlo
            if finding.get("resources"):
                resource_id = finding["resources"][0].get("id", "ID no encontrado")
                # Añadimos el recurso a la lista de hallazgos
                failing_resources.append(resource_id)
                
    return failing_resources

def check_user_has_attached_policies(audit_data):
    """Verifica si un usuario tiene políticas de IAM adjuntadas directamente."""
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        # Si la lista de políticas adjuntas no está vacía, es un hallazgo.
        if user.get("AttachedPolicies"):
            failing_resources.append(user.get("UserName"))
    return failing_resources

def check_guardduty_malware_protection_disabled_with_ec2(audit_data):
    """
    Verifica si GuardDuty Malware Protection para EC2 está desactivado en regiones
    donde existen instancias EC2 y GuardDuty está habilitado.
    """
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    
    # --- LOGS AÑADIDOS ---
    print("\n--- DEBUG: REGLA GUARDDUTY_002 ---")
    print(f"Regiones con instancias EC2 detectadas: {regions_with_ec2}")
    
    for status in guardduty_status:
        region = status.get("Region")
        
        # --- LOGS AÑADIDOS DENTRO DEL BUCLE ---
        print(f"\nAnalizando región: {region}...")
        
        cond1_gd_enabled = status.get("Status") == "Habilitado"
        cond2_malware_disabled = status.get("EC2 Malware Protection") in ["Deshabilitado", "N/A"]
        cond3_ec2_present = region in regions_with_ec2
        
        print(f"  - Condición 1 (GuardDuty Habilitado): {cond1_gd_enabled} (Valor: '{status.get('Status')}')")
        print(f"  - Condición 2 (Malware Deshabilitado o N/A): {cond2_malware_disabled} (Valor: '{status.get('EC2 Malware Protection')}')")
        print(f"  - Condición 3 (EC2 presente en la región): {cond3_ec2_present}")

        if (cond1_gd_enabled and cond2_malware_disabled and cond3_ec2_present):
            print(f"  -> ¡HALLAZGO GENERADO PARA {region}!")
            failing_resources.append({
                "resource": "GuardDuty Malware Protection para EC2",
                "region": region
            })

    print("--- FIN DEBUG: REGLA GUARDDUTY_002 ---\n")
    return failing_resources

def check_no_cloudtrail_in_region(audit_data):
    """Verifica cada región para asegurar que al menos un trail de CloudTrail está definido."""
    failing_resources = []
    
    # 1. Obtener la lista de TODAS las regiones de AWS
    all_regions = audit_data.get("networkPolicies", {}).get("all_regions", [])
    if not all_regions:
        return [] # No se puede continuar si no tenemos la lista de regiones

    # 2. Obtener los trails existentes y crear un conjunto con sus regiones "Home"
    trails = audit_data.get("cloudtrail", {}).get("trails", [])
    regions_with_trails = {trail.get("HomeRegion") for trail in trails}

    # 3. Comparar la lista completa de regiones con las que tienen trails
    for region in all_regions:
        if region not in regions_with_trails:
            # Si una región no está en el conjunto, significa que no tiene trail
            failing_resources.append({
                "resource": "CloudTrail",
                "region": region
            })
    
    return failing_resources

def check_inspector_ec2_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de EC2 de Inspector está desactivado en regiones donde existen instancias EC2.
    """
    failing_resources = []
    
    # 1. Obtener los datos necesarios
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
    
    # 2. Crear un conjunto de regiones que tienen instancias EC2 para una búsqueda rápida
    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    
    # 3. Crear un mapa del estado de escaneo de Inspector por región para un acceso fácil
    inspector_ec2_scan_status = {status['Region']: status.get('ScanEC2') for status in inspector_status}
    
    # 4. Iterar sobre las regiones que SÍ tienen EC2
    for region in regions_with_ec2:
        scan_status = inspector_ec2_scan_status.get(region)
        
        # 5. Si el estado no es 'ENABLED' (puede ser DISABLED, DISABLING, o no existir), es un hallazgo
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector EC2 Scanning",
                "region": region
            })
            
    return failing_resources

def check_inspector_lambda_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de Lambda de Inspector está desactivado en regiones donde existen funciones Lambda.
    """
    failing_resources = []
    
    # 1. Obtener los datos necesarios
    lambda_functions = audit_data.get("compute", {}).get("lambda_functions", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
    
    # 2. Crear un conjunto de regiones que tienen funciones Lambda
    regions_with_lambdas = {function['Region'] for function in lambda_functions}
    
    # 3. Crear un mapa del estado de escaneo de Lambda por región
    inspector_lambda_scan_status = {status['Region']: status.get('ScanLambda') for status in inspector_status}
    
    # 4. Iterar sobre las regiones que SÍ tienen Lambdas
    for region in regions_with_lambdas:
        scan_status = inspector_lambda_scan_status.get(region)
        
        # 5. Si el estado no es 'ENABLED', es un hallazgo
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector Lambda Scanning",
                "region": region
            })
            
    return failing_resources

def check_inspector_ecr_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de ECR de Inspector está desactivado en regiones donde existen repositorios.
    """
    failing_resources = []
    
    # 1. Obtener los datos necesarios
    ecr_repositories = audit_data.get("ecr", {}).get("repositories", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
    
    # 2. Crear un conjunto de regiones que tienen repositorios ECR
    regions_with_ecr = {repo['Region'] for repo in ecr_repositories}
    
    # 3. Crear un mapa del estado de escaneo de ECR por región
    inspector_ecr_scan_status = {status['Region']: status.get('ScanECR') for status in inspector_status}
    
    # 4. Iterar sobre las regiones que SÍ tienen ECR
    for region in regions_with_ecr:
        scan_status = inspector_ecr_scan_status.get(region)
        
        # 5. Si el estado no es 'ENABLED', es un hallazgo
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector ECR Scanning",
                "region": region
            })
            
    return failing_resources

def check_network_connectivity_exists(audit_data):
    """
    Verifica si existen componentes de red avanzados que justifiquen una revisión de segmentación.
    """
    # Accedemos a los datos recopilados por el módulo de conectividad
    connectivity_data = audit_data.get("connectivity", {})
    
    # Comprobamos si alguna de las listas de recursos de conectividad tiene elementos
    peering_exists = len(connectivity_data.get("peering_connections", [])) > 0
    tgw_exists = len(connectivity_data.get("tgw_attachments", [])) > 0
    vpn_exists = len(connectivity_data.get("vpn_connections", [])) > 0
    endpoints_exist = len(connectivity_data.get("vpc_endpoints", [])) > 0

    # Si se encuentra cualquiera de ellos, se genera un único hallazgo informativo.
    if peering_exists or tgw_exists or vpn_exists or endpoints_exist:
        return ["Servicios de Conectividad de Red Avanzada"]
        
    return []


# ------------------------------------------------------------------------------
# 3. Lista Maestra de Reglas (Sin cambios aquí, pero se incluye por completitud)
# ------------------------------------------------------------------------------
RULES_TO_CHECK = [
    {
        "rule_id": "IAM_001",
        "section": "Identity & Access",
        "name": "Usuario sin MFA activado",
        "severity": SEVERITY["HIGH"],
        "description": "Un usuario de IAM no tiene la Autenticación Multi-Factor (MFA) activada. Requerir MFA para todos los usuarios es una práctica de seguridad fundamental para añadir una capa extra de protección contra accesos no autorizados.",
        "remediation": "Navega al servicio de IAM en la consola de AWS, selecciona el usuario afectado y, en la pestaña 'Security credentials', asigna un dispositivo MFA.",
        "check_function": check_mfa_for_all_users
    },
    {
        "rule_id": "IAM_002",
        "section": "Identity & Access",
        "name": "Clave de acceso (Access Key) con más de 90 días",
        "severity": SEVERITY["MEDIUM"],
        "description": "Existen claves de acceso programático con una antigüedad superior a 90 días. Es una buena práctica de seguridad rotar las credenciales regularmente para limitar el riesgo en caso de que una clave se vea expuesta.",
        "remediation": "En la consola de IAM, crea una nueva clave de acceso para el usuario, actualiza las aplicaciones que la usan, y luego desactiva y elimina la clave antigua.",
        "check_function": check_iam_access_key_age
    },
    {
        "rule_id": "IAM_003",
        "section": "Identity & Access",
        "name": "Política de contraseñas no es suficientemente robusta",
        "severity": SEVERITY["HIGH"],
        "description": "La política de contraseñas de la cuenta no cumple con los estándares de seguridad recomendados, haciendo las cuentas de usuario más vulnerables a ataques de fuerza bruta o adivinación.",
        "remediation": "En la consola de IAM, ve a 'Account settings' y edita la política de contraseñas para que cumpla con todos los requisitos: longitud >= 12, uso de mayúsculas, minúsculas, números y símbolos, expiración <= 90 días, reutilización >= 4 y expiración forzada.",
        "check_function": check_password_policy_strength
    },
    {
        "rule_id": "IAM_004",
        "section": "Identity & Access",
        "name": "Usuario con políticas adjuntadas directamente",
        "severity": SEVERITY["LOW"],
        "description": "Se ha detectado un usuario que tiene una o más políticas de IAM adjuntadas directamente a su identidad. La buena práctica de AWS recomienda gestionar los permisos a través de grupos y roles para simplificar la administración y reducir el riesgo de errores de configuración.",
        "remediation": "Crea un grupo de IAM que represente la función del usuario, adjunta las políticas necesarias a ese grupo y luego añade al usuario al grupo. Finalmente, elimina las políticas que están directamente adjuntadas al usuario.",
        "check_function": check_user_has_attached_policies
    },
    {
        "rule_id": "GUARDDUTY_001",
        "section": "Security Services",
        "name": "GuardDuty no habilitado en alguna región",
        "severity": SEVERITY["LOW"],
        "description": "AWS GuardDuty, el servicio de detección de amenazas, no está habilitado o se encuentra suspendido en una o más regiones. Habilitarlo es clave para detectar actividad maliciosa o no autorizada en la cuenta.",
        "remediation": "Accede a la consola de AWS, ve al servicio GuardDuty y habilítalo en las regiones indicadas para mejorar la detección de amenazas de tu cuenta.",
        "check_function": check_guardduty_disabled
    },
    {
        "rule_id": "GUARDDUTY_002",
        "section": "Security Services",
        "name": "GuardDuty Malware Protection desactivado con instancias EC2 presentes",
        "severity": SEVERITY["LOW"],
        "description": "GuardDuty Malware Protection está desactivado en una región donde existen instancias EC2. Aunque GuardDuty esté activo, esta característica específica añade una capa de protección para detectar software malicioso en las cargas de trabajo de EC2, y debería estar habilitada si se utilizan estas instancias.",
        "remediation": "Accede a la consola de GuardDuty, ve a la configuración del detector para la región afectada y habilita la característica 'Malware Protection'. Esto no tiene coste adicional a no ser que se detecte malware y se inicie un escaneo.",
        "check_function": check_guardduty_malware_protection_disabled_with_ec2
    },
    {
        "rule_id": "CONFIG_001",
        "section": "Security Services",
        "name": "AWS Config no habilitado en alguna región",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Config no está habilitado en una o más regiones. Este servicio es fundamental para auditar y evaluar las configuraciones de los recursos de AWS, permitiendo el monitoreo continuo de la conformidad.",
        "remediation": "Accede a la consola de AWS, ve al servicio AWS Config y habilítalo en las regiones indicadas para mejorar la visibilidad y el cumplimiento de la configuración de tus recursos.",
        "check_function": check_config_disabled
    },
    {
        "rule_id": "SECURITYHUB_001",
        "section": "Security Services",
        "name": "AWS Security Hub no habilitado en alguna región",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Security Hub no está habilitado en una o más regiones. Security Hub proporciona una vista integral de las alertas de seguridad de alta prioridad y del estado de cumplimiento en todos los servicios de AWS.",
        "remediation": "Accede a la consola de AWS, ve al servicio Security Hub y habilítalo en las regiones indicadas para centralizar y gestionar la postura de seguridad de tu cuenta.",
        "check_function": check_security_hub_disabled
    },
    {
        "rule_id": "INSPECTOR_001",
        "section": "Vulnerability Management",
        "name": "Recurso con plataforma en Fin de Vida (End of Life)",
        "severity": SEVERITY["CRITICAL"],
        "description": "Se ha detectado un recurso (como una instancia EC2) que utiliza un sistema operativo o plataforma que ha alcanzado su 'Fin de Vida' (EOL). Esto significa que ya no recibe actualizaciones de seguridad del proveedor, dejándolo expuesto a vulnerabilidades conocidas y futuras.",
        "remediation": "Migra la aplicación o servicio a una instancia con un sistema operativo o plataforma soportado y que reciba actualizaciones de seguridad. Planifica la actualización de los recursos antes de que alcancen su fecha de EOL.",
        "check_function": check_inspector_platform_eol
    },
    {
        "rule_id": "INSPECTOR_002",
        "section": "Vulnerability Management",
        "name": "Escaneo de EC2 en Inspector desactivado en región con instancias",
        "severity": SEVERITY["MEDIUM"],
        "description": "Se han detectado instancias EC2 en una región donde el escaneo de vulnerabilidades de Amazon Inspector para EC2 no está activado. Esto representa un punto ciego de seguridad, ya que las nuevas vulnerabilidades en estas instancias no serán descubiertas.",
        "remediation": "Accede a la consola de Amazon Inspector, ve a 'Configuración de la cuenta' -> 'Estado del escaneo' y asegúrate de que 'Escaneo de Amazon EC2' está activado para la región afectada.",
        "check_function": check_inspector_ec2_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_003",
        "section": "Vulnerability Management",
        "name": "Escaneo de Lambda en Inspector desactivado en región con funciones",
        "severity": SEVERITY["MEDIUM"],
        "description": "Se han detectado funciones Lambda en una región donde el escaneo de vulnerabilidades de Amazon Inspector para Lambda no está activado. Esto puede dejar el código y las dependencias de tus funciones sin analizar en busca de vulnerabilidades conocidas.",
        "remediation": "Accede a la consola de Amazon Inspector, ve a 'Configuración de la cuenta' -> 'Estado del escaneo' y asegúrate de que 'Escaneo de funciones Lambda' está activado para la región afectada.",
        "check_function": check_inspector_lambda_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_004",
        "section": "Vulnerability Management",
        "name": "Escaneo de ECR en Inspector desactivado en región con repositorios",
        "severity": SEVERITY["MEDIUM"],
        "description": "Se han detectado repositorios de ECR en una región donde el escaneo de imágenes de contenedor de Amazon Inspector no está activado. Las imágenes pueden contener vulnerabilidades en sus paquetes de sistema operativo o software, y no analizarlas representa un riesgo de seguridad significativo.",
        "remediation": "Accede a la consola de Amazon Inspector, ve a 'Configuración de la cuenta' -> 'Estado del escaneo' y asegúrate de que 'Escaneo de Amazon ECR' está activado para la región afectada.",
        "check_function": check_inspector_ecr_scanning_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_001",
        "section": "Logging & Monitoring",
        "name": "Región sin un trail de CloudTrail definido",
        "severity": SEVERITY["MEDIUM"],
        "description": "Se ha detectado una región de AWS que no tiene definido ningún trail de CloudTrail. Tener un registro de auditoría de todas las llamadas a la API en cada región es una práctica de seguridad fundamental para la investigación de incidentes y el monitoreo de actividades.",
        "remediation": "Crea un trail de CloudTrail en la región afectada. Se recomienda encarecidamente crear un trail multi-región desde la región principal para consolidar los logs de todas las regiones en un solo bucket de S3.",
        "check_function": check_no_cloudtrail_in_region
    },
    {
        "rule_id": "CONNECTIVITY_001",
        "section": "Network & Connectivity",
        "name": "Revisión de segmentación de red recomendada",
        "severity": SEVERITY["INFO"],
        "description": "Se ha detectado el uso de componentes de red avanzados como VPC Peering, Transit Gateway, VPNs o VPC Endpoints. Estos servicios indican una arquitectura de red compleja que interconecta diferentes entornos. Es una buena práctica realizar pruebas de segmentación de red para asegurar que el aislamiento entre VPCs y redes on-premises es el esperado y no existen rutas de comunicación no deseadas.",
        "remediation": "Planifica y ejecuta un test de segmentación de red. Verifica que solo los flujos de tráfico explícitamente permitidos son posibles entre los diferentes segmentos de red (ej: desarrollo, pre-producción, producción) y con las redes corporativas.",
        "check_function": check_network_connectivity_exists
    }
]