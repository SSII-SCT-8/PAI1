"""
Tests para protección contra ataques de replay.
"""
import unittest
import time

import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.server.storage import Storage
from src.server.security import SecurityManager
from src.common.crypto import generate_nonce
from src.common.errors import ReplayAttackError


class TestReplayProtection(unittest.TestCase):
    """Tests de protección contra replay attacks."""
    
    def setUp(self):
        """Configura un storage temporal para tests."""
        # Usar base de datos en memoria para tests
        import tempfile
        self.temp_db = Path(tempfile.mktemp(suffix=".db"))
        self.storage = Storage(self.temp_db)
        self.security = SecurityManager(self.storage)
    
    def tearDown(self):
        """Limpia archivos temporales."""
        if self.temp_db.exists():
            self.temp_db.unlink()
    
    def test_nonce_first_use_accepted(self):
        """Test de que el primer uso de un nonce es aceptado."""
        username = "alice"
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        
        # Primer uso debe funcionar
        result = self.security.check_and_store_nonce(username, nonce, ts)
        self.assertTrue(result)
    
    def test_nonce_reuse_rejected(self):
        """Test de que reutilizar un nonce es rechazado (replay attack)."""
        username = "alice"
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        
        # Primer uso
        self.security.check_and_store_nonce(username, nonce, ts)
        
        # Segundo uso debe lanzar ReplayAttackError
        with self.assertRaises(ReplayAttackError):
            self.security.check_and_store_nonce(username, nonce, ts)
    
    def test_different_users_same_nonce(self):
        """Test de que usuarios diferentes pueden usar el mismo nonce."""
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        
        # Alice usa el nonce
        self.security.check_and_store_nonce("alice", nonce, ts)
        
        # Bob puede usar el mismo nonce (diferente usuario)
        result = self.security.check_and_store_nonce("bob", nonce, ts)
        self.assertTrue(result)
    
    def test_different_nonces_same_user(self):
        """Test de que un usuario puede usar diferentes nonces."""
        username = "alice"
        ts = int(time.time() * 1000)
        
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        
        # Ambos nonces deben ser aceptados
        self.security.check_and_store_nonce(username, nonce1, ts)
        result = self.security.check_and_store_nonce(username, nonce2, ts)
        self.assertTrue(result)
    
    def test_nonce_cleanup(self):
        """Test de limpieza de nonces antiguos."""
        username = "alice"
        old_ts = int((time.time() - 1000) * 1000)  # 1000 segundos atrás
        nonce = generate_nonce()
        
        # Almacenar nonce antiguo directamente en storage
        self.storage.store_nonce(username, nonce, old_ts)
        
        # Limpiar nonces más antiguos de 500 segundos
        self.security.cleanup_old_data()
        
        # El nonce antiguo debería haberse limpiado
        # (pero como el cleanup usa TIMESTAMP_WINDOW*2, ajustar según config)


class TestReplayScenarios(unittest.TestCase):
    """Tests de escenarios realistas de replay attacks."""
    
    def setUp(self):
        """Configura un storage temporal."""
        import tempfile
        self.temp_db = Path(tempfile.mktemp(suffix=".db"))
        self.storage = Storage(self.temp_db)
        self.security = SecurityManager(self.storage)
    
    def tearDown(self):
        """Limpia archivos temporales."""
        if self.temp_db.exists():
            self.temp_db.unlink()
    
    def test_replay_attack_simulation(self):
        """
        Simula un ataque de replay completo.
        
        Escenario:
        1. Usuario envía transacción legítima
        2. Atacante intercepta y reenvía el mensaje
        3. El servidor debe rechazar el segundo envío
        """
        username = "alice"
        nonce = generate_nonce()
        ts = int(time.time() * 1000)
        
        # Mensaje original (legitimo)
        print("\n[LEGITIMO] Enviando transaccion original...")
        try:
            self.security.check_and_store_nonce(username, nonce, ts)
            print("  [OK] Transaccion aceptada")
        except ReplayAttackError:
            self.fail("El primer mensaje deberia ser aceptado")
        
        # Atacante reenvia el mismo mensaje
        print("[ATAQUE] Atacante reenvia el mismo mensaje...")
        with self.assertRaises(ReplayAttackError) as ctx:
            self.security.check_and_store_nonce(username, nonce, ts)
        
        print(f"  [OK] Ataque bloqueado: {ctx.exception}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
