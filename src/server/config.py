"""
Configuración del servidor.
"""
import os
from pathlib import Path

# Rutas
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "data" / "server.db"
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

# Red
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))

# Seguridad
MASTER_KEY = os.getenv("MASTER_KEY")  # Debe configurarse en producción
if not MASTER_KEY:
    # En desarrollo, usar una clave por defecto (NUNCA en producción)
    MASTER_KEY = "dev_master_key_256_bits_change_in_production_environment_please"

MASTER_KEY_BYTES = MASTER_KEY.encode('utf-8')[:32].ljust(32, b'\0')

# Anti-replay: Ventana de tiempo válida para timestamps (en segundos)
TIMESTAMP_WINDOW = 300  # 5 minutos

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutos
BACKOFF_BASE = 2  # Base para backoff exponencial (2^n segundos)

# Sesiones
SESSION_TIMEOUT = 3600  # 1 hora

# Logs
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_TO_FILE = True
LOG_TO_CONSOLE = True

# Base de datos
DB_TIMEOUT = 10.0  # Timeout para operaciones SQLite

# Concurrencia
MAX_CONNECTIONS = 100  # Máximo de conexiones simultáneas
