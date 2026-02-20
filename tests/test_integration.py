"""
Tests de integración completos.
"""

import unittest
import tempfile
from pathlib import Path

import sys

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.server.storage import Storage
from src.server.security import SecurityManager
from src.server.handlers import MessageHandler
from src.server.config import MASTER_KEY_BYTES
from src.common.crypto import derive_user_key, verify_password


class TestIntegration(unittest.TestCase):
    """Tests de integración end-to-end."""

    def setUp(self):
        """Configura componentes del servidor."""
        self.temp_db = Path(tempfile.mktemp(suffix=".db"))
        self.storage = Storage(self.temp_db)
        self.security = SecurityManager(self.storage)
        self.handler = MessageHandler(self.storage, self.security)

    def tearDown(self):
        """Limpia archivos temporales."""
        if self.temp_db.exists():
            self.temp_db.unlink()

    def test_full_user_lifecycle(self):
        """Test del ciclo completo: registro -> login -> transacción -> logout."""
        username = "alice"
        password = "SecurePass123!"
        client_ip = "127.0.0.1"

        # 1. REGISTRO
        print("\n1. Registrando usuario...")
        resp = self.handler.handle_register(username, {"password": password}, client_ip)
        self.assertTrue(resp["success"])
        print(f"   [OK] {resp['message']}")

        # Verificar que el usuario existe en BD
        user = self.storage.get_user(username)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], username)

        # Verificar que el password está hasheado (no en claro)
        self.assertTrue(verify_password(password, user["pw_hash"], user["pw_salt"]))

        # 2. LOGIN
        print("\n2. Iniciando sesión...")
        resp = self.handler.handle_login(username, {"password": password}, client_ip)
        self.assertTrue(resp["success"])
        session_id = resp["data"]["session_id"]
        print(f"   [OK] {resp['message']}")
        print(f"   Session ID: {session_id[:16]}...")

        # 3. TRANSACCIÓN
        print("\n3. Enviando transacción...")
        resp = self.handler.handle_transaction(
            username,
            {"from_account": "ES1111", "to_account": "ES2222", "amount": "500.00"},
            raw_message='{"test": "message"}',
            mac_trunc="abc...",
            ts=1234567890,
        )
        self.assertTrue(resp["success"])
        self.assertIn("integridad", resp["message"].lower())
        tx_id = resp["data"]["transaction_id"]
        print(f"   [OK] {resp['message']}")
        print(f"   TX ID: {tx_id}")

        # Verificar que la transacción está en BD
        txs = self.storage.get_user_transactions(username)
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0]["from_account"], "ES1111")

        # 4. LOGOUT
        print("\n4. Cerrando sesion...")
        resp = self.handler.handle_logout(username, {"session_id": session_id})
        self.assertTrue(resp["success"])
        print(f"   [OK] {resp['message']}")

        # Verificar que la sesión fue eliminada
        session = self.storage.get_session(session_id)
        self.assertIsNone(session)

    def test_register_duplicate_user(self):
        """Test de que no se puede registrar un usuario duplicado."""
        username = "bob"
        password = "pass123"
        client_ip = "127.0.0.1"

        # Primera vez - OK
        resp1 = self.handler.handle_register(
            username, {"password": password}, client_ip
        )
        self.assertTrue(resp1["success"])

        # Segunda vez - debe fallar
        resp2 = self.handler.handle_register(
            username, {"password": password}, client_ip
        )
        self.assertFalse(resp2["success"])
        self.assertIn("ya existe", resp2["message"].lower())

    def test_login_wrong_password(self):
        """Test de que login con password incorrecto falla."""
        username = "charlie"
        correct_password = "CorrectPass"
        wrong_password = "WrongPass"
        client_ip = "127.0.0.1"

        # Registrar usuario
        user_key, user_key_salt = derive_user_key(MASTER_KEY_BYTES, username)
        self.storage.create_user(username, correct_password, user_key, user_key_salt)

        # Intentar login con password incorrecto
        resp = self.handler.handle_login(
            username, {"password": wrong_password}, client_ip
        )
        self.assertFalse(resp["success"])
        self.assertIn("inválidas", resp["message"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
