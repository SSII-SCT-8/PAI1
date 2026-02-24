"""
Tests para protección contra ataques MITM (Man-in-the-Middle).
"""
import unittest
import time

import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.crypto import compute_hmac, verify_hmac, generate_key
from src.common.protocol import canonicalize_message


class TestMITMProtection(unittest.TestCase):
    """Tests de protección contra MITM con HMAC."""
    
    def test_valid_message_accepted(self):
        """Test de que un mensaje válido es aceptado."""
        key = generate_key()
        
        message = {
            "type": "TX",
            "username": "alice",
            "ts": int(time.time() * 1000),
            "nonce": "abc123",
            "payload": {
                "from_account": "ES1234",
                "to_account": "ES5678",
                "amount": "1000.00"
            }
        }
        
        # Calcular MAC
        canonical = canonicalize_message(message)
        mac = compute_hmac(key, canonical)
        
        # Verificar que el MAC es válido
        self.assertTrue(verify_hmac(key, canonical, mac))
    
    def test_tampered_payload_rejected(self):
        """Test de que un payload modificado es rechazado (MITM)."""
        key = generate_key()
        
        message = {
            "type": "TX",
            "username": "alice",
            "ts": int(time.time() * 1000),
            "nonce": "abc123",
            "payload": {
                "from_account": "ES1234",
                "to_account": "ES5678",
                "amount": "1000.00"
            }
        }
        
        # Calcular MAC del mensaje original
        canonical = canonicalize_message(message)
        mac = compute_hmac(key, canonical)
        
        # MITM: Atacante modifica el amount
        message["payload"]["amount"] = "999999.00"
        
        # Calcular canonical del mensaje modificado
        tampered_canonical = canonicalize_message(message)
        
        # El MAC ya no es válido
        self.assertFalse(verify_hmac(key, tampered_canonical, mac))
    
    def test_tampered_timestamp_rejected(self):
        """Test de que modificar el timestamp invalida el MAC."""
        key = generate_key()
        
        message = {
            "type": "TX",
            "username": "alice",
            "ts": int(time.time() * 1000),
            "nonce": "abc123",
            "payload": {"amount": "100"}
        }
        
        # MAC original
        canonical = canonicalize_message(message)
        mac = compute_hmac(key, canonical)
        
        # MITM: Modificar timestamp
        message["ts"] = message["ts"] + 1000
        
        # MAC inválido
        tampered_canonical = canonicalize_message(message)
        self.assertFalse(verify_hmac(key, tampered_canonical, mac))
    
    def test_tampered_username_rejected(self):
        """Test de que modificar el username invalida el MAC."""
        key = generate_key()
        
        message = {
            "type": "TX",
            "username": "alice",
            "ts": int(time.time() * 1000),
            "nonce": "abc123",
            "payload": {"amount": "100"}
        }
        
        canonical = canonicalize_message(message)
        mac = compute_hmac(key, canonical)
        
        # MITM: Cambiar usuario
        message["username"] = "attacker"
        
        tampered_canonical = canonicalize_message(message)
        self.assertFalse(verify_hmac(key, tampered_canonical, mac))
    
    def test_mac_not_included_in_signature(self):
        """Test de que el campo 'mac' no se incluye en el cálculo del MAC."""
        key = generate_key()
        
        message = {
            "type": "TX",
            "username": "alice",
            "ts": 123456,
            "nonce": "nonce",
            "payload": {},
            "mac": "dummy_mac"
        }
        
        canonical = canonicalize_message(message)
        
        # El canonical NO debe contener 'mac'
        self.assertNotIn(b'"mac"', canonical)


class TestMITMScenarios(unittest.TestCase):
    """Tests de escenarios realistas de MITM."""
    
    def test_mitm_attack_simulation(self):
        """
        Simula un ataque MITM completo.
        
        Escenario:
        1. Cliente envía transacción de 1000€
        2. Atacante intercepta y modifica a 10€
        3. Servidor detecta MAC inválido y rechaza
        """
        key = generate_key()
        
        # Cliente prepara mensaje original
        original_message = {
            "type": "TX",
            "username": "alice",
            "ts": int(time.time() * 1000),
            "nonce": "original_nonce",
            "payload": {
                "from_account": "ES1111",
                "to_account": "ES2222",
                "amount": "1000.00"
            }
        }
        
        print("\n[CLIENTE] Enviando transaccion de 1000 EUR...")
        canonical = canonicalize_message(original_message)
        mac = compute_hmac(key, canonical)
        original_message["mac"] = mac
        print(f"  [OK] MAC calculado: {mac[:16]}...")
        
        # MITM: Atacante modifica el mensaje en transito
        print("[ATACANTE] Interceptando mensaje y modificando amount a 10 EUR...")
        tampered_message = original_message.copy()
        tampered_message["payload"] = original_message["payload"].copy()
        tampered_message["payload"]["amount"] = "10.00"
        # El MAC permanece igual (el atacante no puede recalcularlo sin la clave)
        
        # Servidor verifica
        print("[SERVIDOR] Verificando integridad del mensaje...")
        tampered_canonical = canonicalize_message(tampered_message)
        
        if verify_hmac(key, tampered_canonical, mac):
            self.fail("VULNERABLE: El servidor acepto el mensaje modificado!")
        else:
            print("  [OK] MAC INVALIDO detectado: mensaje rechazado")
            print("  [OK] Ataque MITM bloqueado exitosamente")


if __name__ == "__main__":
    unittest.main(verbosity=2)
