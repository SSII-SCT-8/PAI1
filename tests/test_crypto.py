"""
Tests para funciones criptográficas.
"""

import unittest

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.crypto import (
    generate_key,
    generate_nonce,
    compute_hmac,
    verify_hmac,
    hash_password,
    verify_password,
    derive_user_key,
    secure_compare,
    HMAC_KEY_SIZE,
    NONCE_SIZE,
)


class TestCrypto(unittest.TestCase):
    """Tests de funciones criptográficas."""

    def test_generate_key_size(self):
        """Test de que las claves generadas tienen el tamaño correcto."""
        key = generate_key()
        self.assertEqual(len(key), HMAC_KEY_SIZE)
        self.assertEqual(len(key), 32)  # 256 bits

    def test_generate_key_uniqueness(self):
        """Test de que las claves generadas son únicas."""
        keys = [generate_key() for _ in range(100)]
        self.assertEqual(len(set(keys)), 100)

    def test_generate_nonce_uniqueness(self):
        """Test de que los nonces son únicos."""
        nonces = [generate_nonce() for _ in range(1000)]
        self.assertEqual(len(set(nonces)), 1000)

    def test_hmac_computation(self):
        """Test de cálculo de HMAC."""
        key = b"test_key_256_bits_long_enough!!"
        message = b"test message"

        mac = compute_hmac(key, message)

        # Verificar que retorna una string base64
        self.assertIsInstance(mac, str)
        self.assertTrue(len(mac) > 0)

    def test_hmac_verification_valid(self):
        """Test de verificación de HMAC válido."""
        key = b"test_key_256_bits_long_enough!!"
        message = b"test message"

        mac = compute_hmac(key, message)
        self.assertTrue(verify_hmac(key, message, mac))

    def test_hmac_verification_invalid_message(self):
        """Test de que HMAC inválido es rechazado (mensaje modificado)."""
        key = b"test_key_256_bits_long_enough!!"
        message = b"test message"
        tampered_message = b"tampered message"

        mac = compute_hmac(key, message)

        # MITM: mensaje modificado debe fallar
        self.assertFalse(verify_hmac(key, tampered_message, mac))

    def test_hmac_verification_invalid_key(self):
        """Test de que HMAC con clave incorrecta es rechazado."""
        key1 = b"key1_256_bits_long_enough!!!!!"
        key2 = b"key2_256_bits_long_enough!!!!!"
        message = b"test message"

        mac = compute_hmac(key1, message)

        # Clave diferente debe fallar
        self.assertFalse(verify_hmac(key2, message, mac))

    def test_password_verification_correct(self):
        """Test de verificación de password correcto."""
        password = "MyPassword"
        pw_hash = hash_password(password)

        self.assertTrue(verify_password(password, pw_hash))

    def test_password_verification_incorrect(self):
        """Test de verificación de password incorrecto."""
        password = "MyPassword"
        wrong_password = "WrongPassword"
        pw_hash = hash_password(password)

        self.assertFalse(verify_password(wrong_password, pw_hash))

    def test_derive_user_key(self):
        """Test de derivación de claves por usuario."""
        master_key = b"master_key_256_bits!!!!!!!!!!!"
        username = "alice"

        user_key, salt = derive_user_key(master_key, username)

        # Verificar tamaño de la clave (32 bytes = 256 bits)
        self.assertEqual(len(user_key), 32)

        # Verificar que es determinista con el mismo salt
        user_key2, _ = derive_user_key(master_key, username, salt)
        self.assertEqual(user_key, user_key2)

        # Verificar que usuarios diferentes tienen claves diferentes
        user_key_bob, _ = derive_user_key(master_key, "bob", salt)
        self.assertNotEqual(user_key, user_key_bob)

    def test_derive_user_key_default_is_deterministic(self):
        """Sin salt explicito, la derivacion debe ser determinista por usuario."""
        master_key = b"master_key_256_bits!!!!!!!!!!!"
        username = "alice"

        key1, salt1 = derive_user_key(master_key, username)
        key2, salt2 = derive_user_key(master_key, username)

        self.assertEqual(salt1, salt2)
        self.assertEqual(key1, key2)

    def test_secure_compare_equal(self):
        """Test de comparación segura con strings iguales."""
        self.assertTrue(secure_compare("test", "test"))

    def test_secure_compare_different(self):
        """Test de comparación segura con strings diferentes."""
        self.assertFalse(secure_compare("test1", "test2"))

    def test_key_size_strength(self):
        """
        Test conceptual: demostrar por qué 32 bits es inseguro.

        Una clave de 32 bits tiene solo 2^32 = 4,294,967,296 combinaciones.
        Con hardware moderno (GPU, ASIC), esto se puede romper en segundos.

        Una clave de 256 bits tiene 2^256 combinaciones, computacionalmente
        inviable de romper por fuerza bruta.
        """
        # Clave de 32 bits (4 bytes)
        weak_key_32_bits = 0xFFFFFFFF
        combinations_32_bits = 2**32

        # Clave de 256 bits (32 bytes)
        combinations_256_bits = 2**256

        # La diferencia es astronómica
        ratio = combinations_256_bits / combinations_32_bits

        # Verificar que 256 bits es MUCHO más seguro
        self.assertTrue(ratio > 10**60)  # 2^224 ≈ 2.7 × 10^67

        print(f"\n--- ANÁLISIS DE FUERZA DE CLAVES ---")
        print(f"32 bits:  {combinations_32_bits:,} combinaciones")
        print(f"256 bits: {combinations_256_bits:.2e} combinaciones")
        print(f"Ratio:    {ratio:.2e}x más seguro")
        print(f"\nCon GPU moderna (10^9 intentos/seg):")
        print(f"  32 bits:  ~4 segundos para romper")
        print(
            f"  256 bits: ~10^{int(__import__('math').log10(combinations_256_bits / 1e9))} años"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
