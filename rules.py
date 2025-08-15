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
        policy.get("HardExpiry") is True
    ]
    if not all(checks):
        return ["Account Password Policy"]
    return []

# --- ▼▼▼ FUNCIONES CORREGIDAS ▼▼▼ ---

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

# --- ▲▲▲ FIN DE FUNCIONES CORREGIDAS ▲▲▲ ---


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
        "rule_id": "GUARDDUTY_001",
        "section": "Security Services",
        "name": "GuardDuty no habilitado en alguna región",
        "severity": SEVERITY["LOW"],
        "description": "AWS GuardDuty, el servicio de detección de amenazas, no está habilitado o se encuentra suspendido en una o más regiones. Habilitarlo es clave para detectar actividad maliciosa o no autorizada en la cuenta.",
        "remediation": "Accede a la consola de AWS, ve al servicio GuardDuty y habilítalo en las regiones indicadas para mejorar la detección de amenazas de tu cuenta.",
        "check_function": check_guardduty_disabled
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
    }
]