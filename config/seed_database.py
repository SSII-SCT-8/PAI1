"""
Script para inicializar la base de datos con usuarios de prueba.
"""

import json
import sys
from pathlib import Path

# Añadir el directorio raíz al path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.crypto import derive_user_key
from src.server.config import MASTER_KEY_BYTES
from src.server.storage import Storage


def seed_database():
    """Carga usuarios desde seed_users.json."""
    # Leer usuarios del archivo de seed
    seed_file = Path(__file__).parent / "seed_users.json"

    if not seed_file.exists():
        print(f"❌ Error: No se encontró {seed_file}")
        return False

    with open(seed_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    users = data.get("users", [])

    if not users:
        print("⚠️  No hay usuarios en seed_users.json")
        return False

    # Inicializar storage
    storage = Storage()

    print(f"\n{'='*60}")
    print("Inicializando base de datos con usuarios de prueba")
    print(f"{'='*60}\n")

    created = 0
    skipped = 0

    for user_data in users:
        username = user_data["username"]
        password = user_data["password"]

        # Verificar si ya existe
        if storage.user_exists(username):
            print(f"⊘ Usuario '{username}' ya existe - omitido")
            skipped += 1
            continue

        # Derivar clave del usuario
        user_key, user_key_salt = derive_user_key(MASTER_KEY_BYTES, username)

        # Crear usuario
        try:
            storage.create_user(username, password, user_key, user_key_salt)
            print(f"✓ Usuario '{username}' creado")
            created += 1
        except Exception as e:
            print(f"❌ Error creando usuario '{username}': {e}")

    print(f"\n{'='*60}")
    print(f"Resumen: {created} creados, {skipped} omitidos")
    print(f"{'='*60}\n")

    if created > 0:
        print("Usuarios disponibles para login:")
        for user_data in users:
            print(f"  - Usuario: {user_data['username']}")
            print(f"    Password: {user_data['password']}")
        print()

    return True


if __name__ == "__main__":
    seed_database()
