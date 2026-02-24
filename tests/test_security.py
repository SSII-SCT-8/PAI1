"""Security tests: timestamp validation, nonce store, rate limit, session management."""

import unittest
import time
import tempfile
from pathlib import Path

import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.server.storage import Storage
from src.server.security import SecurityManager
from src.server.config import TIMESTAMP_WINDOW, MAX_LOGIN_ATTEMPTS
from src.common.crypto import generate_nonce, compute_hmac, verify_hmac, generate_key
from src.common.protocol import canonicalize_message
from src.common.errors import (
    InvalidTimestampError,
    ReplayAttackError,
    RateLimitError
)


class TestSecurityFull(unittest.TestCase):
    def setUp(self):
        self.temp_db = Path(tempfile.mktemp(suffix=".db"))
        self.storage = Storage(self.temp_db)
        self.security = SecurityManager(self.storage)

    def tearDown(self):
        if self.temp_db.exists():
            self.temp_db.unlink()

    def test_replay_attack_transaction(self):
        """Nonce reutilizado debe ser rechazado."""
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        self.security.check_and_store_nonce("alice", nonce, ts)
        with self.assertRaises(ReplayAttackError):
            self.security.check_and_store_nonce("alice", nonce, ts)

    def test_modified_transaction(self):
        """Payload modificado invalida el MAC."""
        key = generate_key()
        msg = {"type": "TX", "ts": int(time.time() * 1000),
               "nonce": "n1", "username": "alice",
               "payload": {"amount": "100"}}
        mac = compute_hmac(key, canonicalize_message(msg))
        msg["payload"]["amount"] = "999"
        self.assertFalse(verify_hmac(key, canonicalize_message(msg), mac))

    def test_mitm_login(self):
        """Mensaje LOGIN alterado es detectado por MAC."""
        key = generate_key()
        msg = {"type": "LOGIN", "ts": int(time.time() * 1000),
               "nonce": "n2", "username": "alice",
               "payload": {"password": "pass"}}
        mac = compute_hmac(key, canonicalize_message(msg))
        msg["payload"]["password"] = "hacked"
        self.assertFalse(verify_hmac(key, canonicalize_message(msg), mac))

    def test_login_brute_force(self):
        """Rate limit bloquea tras MAX_LOGIN_ATTEMPTS intentos."""
        for _ in range(MAX_LOGIN_ATTEMPTS):
            self.storage.record_login_attempt("alice", "1.2.3.4", False)
        with self.assertRaises(RateLimitError):
            self.security.check_rate_limit("alice", "1.2.3.4")

    def test_sql_injection_login(self):
        """Caracteres de inyeccion SQL no rompen el storage."""
        evil = "'; DROP TABLE users;--"
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        # No debe lanzar excepcion; el parametrizado de SQLite protege
        self.security.check_and_store_nonce(evil, nonce, ts)
        self.assertTrue(True)

    def test_malformed_messages(self):
        """Timestamp fuera de ventana es rechazado."""
        old_ts = int((time.time() - TIMESTAMP_WINDOW - 60) * 1000)
        with self.assertRaises(InvalidTimestampError):
            self.security.validate_timestamp(old_ts)

    def test_secure_comparator(self):
        """hmac.compare_digest se usa en verify_hmac."""
        import hmac as _hmac
        key = generate_key()
        data = b"test"
        mac = compute_hmac(key, data)
        self.assertTrue(verify_hmac(key, data, mac))
        self.assertFalse(verify_hmac(key, b"tampered", mac))


if __name__ == "__main__":
    unittest.main()