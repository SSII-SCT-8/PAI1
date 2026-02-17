"""
Configuración del servidor.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "data" / "server.db"
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))

MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    MASTER_KEY = "dev_master_key_256_bits_change_in_production_environment_please"

MASTER_KEY_BYTES = MASTER_KEY.encode('utf-8')[:32].ljust(32, b'\0')

TIMESTAMP_WINDOW = 300        # 5 min
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300       # 5 min
BACKOFF_BASE = 2              # 2^n segundos
SESSION_TIMEOUT = 3600        # 1 hora

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_TO_FILE = True
LOG_TO_CONSOLE = True

DB_TIMEOUT = 10.0
MAX_CONNECTIONS = 100
CLIENT_MESSAGE_TIMEOUT = float(os.getenv("CLIENT_MESSAGE_TIMEOUT", "60.0"))
