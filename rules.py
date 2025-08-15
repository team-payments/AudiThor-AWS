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

def check_foundational_services_disabled(audit_data):
    """
    Verifica si GuardDuty, AWS Config o Security Hub están deshabilitados
    o suspendidos en alguna de las regiones auditadas.
    """
    failing_resources = []

    # 1. Comprobar GuardDuty
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])
    # --- LÍNEA MODIFICADA AQUÍ ---
    # Ahora alerta si el estado NO es 'Habilitado' (cubre 'No Habilitado', 'Suspendido', etc.)
    disabled_gd_regions = [s.get("Region") for s in guardduty_status if s.get("Status") != "Habilitado"]
    if disabled_gd_regions:
        failing_resources.append(f"GuardDuty no está activo en: {', '.join(sorted(list(set(disabled_gd_regions))))}")

    # 2. Comprobar AWS Config y Security Hub
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])
    if config_sh_status:
        disabled_config_regions = [s.get("Region") for s in config_sh_status if not s.get("ConfigEnabled")]
        if disabled_config_regions:
            failing_resources.append(f"AWS Config deshabilitado en: {', '.join(sorted(list(set(disabled_config_regions))))}")
        
        disabled_sh_regions = [s.get("Region") for s in config_sh_status if not s.get("SecurityHubEnabled")]
        if disabled_sh_regions:
            failing_resources.append(f"Security Hub deshabilitado en: {', '.join(sorted(list(set(disabled_sh_regions))))}")

    return failing_resources

# ------------------------------------------------------------------------------
# 3. Lista Maestra de Reglas
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
        "rule_id": "FOUNDATIONAL_001",
        "section": "Security Services",
        "name": "Servicios de seguridad fundamentales no habilitados",
        "severity": SEVERITY["LOW"],
        "description": "GuardDuty, AWS Config o AWS Security Hub no están habilitados en todas las regiones. Estos servicios son la base para la detección de amenazas, el monitoreo de la configuración y la gestión de la postura de seguridad.",
        "remediation": "Accede a la consola de AWS y habilita el servicio correspondiente en las regiones indicadas para mejorar la visibilidad y la seguridad de tu cuenta.",
        "check_function": check_foundational_services_disabled
    }
]