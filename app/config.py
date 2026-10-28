import os
import secrets

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _resolve_secret(env_var_name):
    """
    F-01 y F-03: Nunca utiliza cadenas fijas en el código fuente.
    En producción exige que la variable de entorno esté configurada (>= 32 caracteres);
    en desarrollo local genera una clave aleatoria efímera por proceso.
    """
    val = os.environ.get(env_var_name, '').strip()
    is_prod = (
        os.environ.get('FLASK_ENV', '').lower() == 'production'
        or bool(os.environ.get('RAILWAY_ENVIRONMENT'))
    )
    if val:
        if is_prod and len(val) < 32:
            raise RuntimeError(f"Configuración insegura: {env_var_name} en producción debe tener al menos 32 caracteres.")
        return val
    if is_prod:
        raise RuntimeError(
            f"Error crítico de despliegue (F-01/F-03): La variable de entorno obligatoria '{env_var_name}' "
            f"no está definida en producción."
        )
    return secrets.token_hex(32)


class Config:
    SECRET_KEY = _resolve_secret('SECRET_KEY')
    SOC_HMAC_SECRET_KEY = _resolve_secret('SOC_HMAC_SECRET_KEY')

    # F-09: Límite global del cuerpo de la solicitud HTTP en Flask (1 MB)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    # F-15 y F-21: Rutas absolutas centralizadas y política de retención
    STORAGE_DIR = os.path.join(BASE_DIR, 'app', 'storage')
    SESSIONS_DIR = os.path.join(STORAGE_DIR, 'sesiones')
    REPORT_RETENTION_SECONDS = int(os.environ.get('REPORT_RETENTION_SECONDS', '3600'))
    MAX_STORED_SESSIONS = int(os.environ.get('MAX_STORED_SESSIONS', '100'))

    # F-01: Endurecimiento de cookies de sesión
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = (
        os.environ.get('FLASK_ENV', '').lower() == 'production'
        or bool(os.environ.get('RAILWAY_ENVIRONMENT'))
    )