"""
Tests para el protocolo de comunicación y canonicalización.
"""
import unittest
import json

import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.protocol import canonicalize_message, create_error_response, create_success_response


class TestProtocol(unittest.TestCase):
    """Tests del protocolo de comunicación."""
    
    def test_canonicalize_message(self):
        """Test de canonicalización de mensajes."""
        msg = {
            "type": "TX",
            "username": "alice",
            "ts": 1234567890,
            "nonce": "abc123",
            "payload": {"amount": "100"},
            "mac": "should_be_excluded"
        }
        
        canonical = canonicalize_message(msg)
        
        # Verificar que es bytes
        self.assertIsInstance(canonical, bytes)
        
        # Verificar que NO contiene 'mac'
        self.assertNotIn(b'"mac"', canonical)
        
        # Verificar que contiene los demás campos
        self.assertIn(b'"type"', canonical)
        self.assertIn(b'"username"', canonical)
        
        # Verificar que es determinista
        canonical2 = canonicalize_message(msg)
        self.assertEqual(canonical, canonical2)
    
    def test_canonicalize_deterministic_order(self):
        """Test de que el orden de las claves es determinista."""
        msg1 = {"z": 1, "a": 2, "m": 3}
        msg2 = {"a": 2, "z": 1, "m": 3}
        
        self.assertEqual(
            canonicalize_message(msg1),
            canonicalize_message(msg2)
        )
    
    def test_error_response(self):
        """Test de creación de respuestas de error."""
        resp = create_error_response("TEST_CODE", "Test message")
        
        self.assertEqual(resp["type"], "ERROR")
        self.assertEqual(resp["code"], "TEST_CODE")
        self.assertEqual(resp["message"], "Test message")
        self.assertFalse(resp["success"])
    
    def test_success_response(self):
        """Test de creación de respuestas exitosas."""
        resp = create_success_response("Success", {"key": "value"})
        
        self.assertEqual(resp["type"], "RESPONSE")
        self.assertEqual(resp["message"], "Success")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["data"]["key"], "value")


if __name__ == "__main__":
    unittest.main()
