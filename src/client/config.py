"""
Configuración del cliente.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))

# Clave maestra (debe ser la misma que el servidor)
MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    MASTER_KEY = "dev_master_key_256_bits_change_in_production_environment_please"

MASTER_KEY_BYTES = MASTER_KEY.encode('utf-8')[:32].ljust(32, b'\0')

CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "10.0"))
MESSAGE_TIMEOUT = float(os.getenv("MESSAGE_TIMEOUT", "60.0"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_TO_FILE = True
LOG_TO_CONSOLE = True

CLIENT_VERSION = "1.0.0"
