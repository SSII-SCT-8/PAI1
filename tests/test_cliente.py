"""Tests del lado cliente: creacion de mensajes, MAC, nonce unicidad."""

import unittest
import time

import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.crypto import (
    compute_hmac, verify_hmac, generate_key, generate_nonce
)
from src.common.protocol import canonicalize_message


class TestCliente(unittest.TestCase):
    def _build_msg(self, msg_type="TX", **extra):
        msg = {
            "type": msg_type,
            "ts": int(time.time() * 1000),
            "nonce": generate_nonce(),
            "username": "alice",
            "payload": extra.get("payload", {"amount": "100"}),
        }
        return msg

    def test_fuerza_bruta_login(self):
        """MAC con clave erronea siempre falla."""
        key_real = generate_key()
        msg = self._build_msg("LOGIN", payload={"password": "pass"})
        mac = compute_hmac(key_real, canonicalize_message(msg))
        for _ in range(10):
            key_wrong = generate_key()
            self.assertFalse(verify_hmac(key_wrong, canonicalize_message(msg), mac))

    def test_replay_attack(self):
        """Dos mensajes con distinto nonce producen MAC distinto."""
        key = generate_key()
        msg1 = self._build_msg()
        msg2 = self._build_msg()
        self.assertNotEqual(msg1["nonce"], msg2["nonce"])
        mac1 = compute_hmac(key, canonicalize_message(msg1))
        mac2 = compute_hmac(key, canonicalize_message(msg2))
        self.assertNotEqual(mac1, mac2)

    def test_inyeccion_sql_login(self):
        """Caracteres maliciosos en payload no corrompen canonical."""
        msg = self._build_msg(payload={"password": "'; DROP TABLE users;--"})
        canonical = canonicalize_message(msg)
        self.assertIsInstance(canonical, bytes)

    def test_modificar_respuesta(self):
        """MAC invalido al alterar amount."""
        key = generate_key()
        msg = self._build_msg(payload={"amount": "500"})
        mac = compute_hmac(key, canonicalize_message(msg))
        msg["payload"]["amount"] = "1"
        self.assertFalse(verify_hmac(key, canonicalize_message(msg), mac))

    def test_enviar_datos_malformados(self):
        """canonicalize_message funciona aunque falten campos opcionales."""
        msg = {"type": "TX"}
        canonical = canonicalize_message(msg)
        self.assertIsInstance(canonical, bytes)


if __name__ == "__main__":
    unittest.main()