# ==============================================================================
# rules.py - Motor de Reglas para AudiThor-AWS (CORREGIDO)
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

def check_mfa_for_console_users(audit_data):
    """
    Identifica a los usuarios con acceso a la consola (contraseña activada)
    que no tienen un dispositivo MFA activo.
    """
    failing_resources = []
    # Usamos audit_data.get("iam", {}) para evitar errores si la clave 'iam' no existe
    users = audit_data.get("iam", {}).get("users", [])

    for user in users:
        # --- CORRECCIÓN AQUÍ ---
        # 1. Se usa "PasswordEnabled" (mayúscula) para que coincida con audithor.py
        # 2. Se comprueba la lista "MFADevices". Si está vacía, `not user.get("MFADevices")` será True.
        if user.get("PasswordEnabled") and not user.get("MFADevices"):
            # Se usa "UserName" para que coincida con la estructura de datos
            failing_resources.append(user.get("arn", user.get("UserName")))

    return failing_resources


def check_iam_access_key_age(audit_data):
    """
    Identifica las claves de acceso de usuario que no han sido rotadas
    en los últimos 90 días.
    """
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    ninety_days = 90
    now = datetime.now(timezone.utc)

    for user in users:
        # --- CORRECCIÓN AQUÍ ---
        # Se usa "AccessKeys" (mayúscula) para que coincida con audithor.py
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


# ------------------------------------------------------------------------------
# 3. Lista Maestra de Reglas (Sin cambios, ya era correcta)
# ------------------------------------------------------------------------------
RULES_TO_CHECK = [
    {
        "rule_id": "IAM_001",
        "section": "Identity & Access",
        "name": "Usuario de consola sin MFA activado",
        "severity": SEVERITY["HIGH"],
        "description": "Un usuario con contraseña para acceder a la consola no tiene la Autenticación Multi-Factor (MFA) activada, lo que representa un riesgo elevado de acceso no autorizado si la contraseña se ve comprometida.",
        "remediation": "Navega al servicio de IAM en la consola de AWS, selecciona el usuario afectado y, en la pestaña 'Security credentials', asigna un dispositivo MFA.",
        "check_function": check_mfa_for_console_users
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
]