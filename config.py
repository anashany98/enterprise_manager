import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv


# ==============================
# 📂 RUTAS Y CARGA DE ENTORNO
# ==============================
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

# Carga el archivo .env local si existe, o variables del entorno del sistema
load_dotenv(ENV_PATH if ENV_PATH.exists() else None)


# ==============================
# ⚙️ CONFIGURACIÓN BASE
# ==============================
class Config:
    """Configuración base de la aplicación Enterprise Manager."""

    # --- Seguridad y claves ---
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-please")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

    # --- Base de datos ---
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'empresa.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Sesiones y cookies ---
    SESSION_PROTECTION = "strong"
    REMEMBER_COOKIE_DURATION = timedelta(days=14)

    # Flask-WTF espera un número (segundos), no un timedelta
    WTF_CSRF_TIME_LIMIT = 24 * 3600  # 24 h
    WTF_CSRF_SSL_STRICT = False  # cambia a True en producción HTTPS

    # --- Rutas internas ---
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    BACKUP_DIR = os.getenv("BACKUP_DIR", str(BASE_DIR / "backups"))
    REPORT_EXPORT_DIR = os.getenv("REPORT_EXPORT_DIR", str(BASE_DIR / "exports"))

    # --- Credenciales del administrador inicial ---
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

    # --- Retención y copias de seguridad ---
    SECURITY_LOG_RETENTION_DAYS = int(os.getenv("SECURITY_LOG_RETENTION_DAYS", "90"))
    DATABASE_BACKUP_INTERVAL_HOURS = int(os.getenv("DATABASE_BACKUP_INTERVAL_HOURS", "24"))

    # --- JWT (tokens de autenticación) ---
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_EXP_MINUTES", "30"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("JWT_REFRESH_DAYS", "7"))
    )

    # --- Inicialización segura de carpetas ---
    for _path in ("uploads", "backups", "exports"):
        folder = BASE_DIR / _path
        folder.mkdir(exist_ok=True)


# ==============================
# 💻 ENTORNOS DE EJECUCIÓN
# ==============================
class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"
    WTF_CSRF_SSL_STRICT = True  # exige HTTPS en formularios


# ==============================
# 🔧 SELECCIÓN AUTOMÁTICA
# ==============================
config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}


def get_config() -> Config:
    """Devuelve la configuración según FLASK_ENV (por defecto 'development')."""
    env = os.getenv("FLASK_ENV", "development").lower()
    return config_by_name.get(env, DevelopmentConfig)
