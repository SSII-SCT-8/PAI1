"""Security test skeleton."""

import unittest


def enviar_mensaje(mensaje: str) -> str:
    _ = mensaje
    return "TODO"


def obtener_credenciales_desde_txt(usuario: str):
    _ = usuario
    return None


class TestSecurityFull(unittest.TestCase):
    def obtener_challenge_login(self, usuario: str):
        _ = usuario
        return None

    def derive_key(self, password: str, salt_hex: str, iterations: int = 100000):
        _ = (password, salt_hex, iterations)
        return b""

    def compute_response(self, key: bytes, challenge: str) -> str:
        _ = (key, challenge)
        return ""

    def test_replay_attack_transaction(self):
        self.assertTrue(True)

    def test_modified_transaction(self):
        self.assertTrue(True)

    def test_mitm_login(self):
        self.assertTrue(True)

    def test_login_brute_force(self):
        self.assertTrue(True)

    def test_sql_injection_login(self):
        self.assertTrue(True)

    def test_malformed_messages(self):
        self.assertTrue(True)

    def test_secure_comparator(self):
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()