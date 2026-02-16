"""
Configuración del cliente.
"""
import os
from pathlib import Path

# Rutas
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"

# Conexión
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))

# Timeouts
CONNECT_TIMEOUT = 10.0
MESSAGE_TIMEOUT = 30.0

# Logs
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_TO_FILE = True
LOG_TO_CONSOLE = True

# Cliente
CLIENT_VERSION = "1.0.0"
