"""Funciones criptográficas para integridad y protección de credenciales."""
import hmac
import hashlib
import secrets
import base64
from typing import Tuple


HMAC_KEY_SIZE = 32      # 256 bits
NONCE_SIZE = 16         # 128 bits
SALT_SIZE = 16          # 128 bits
PBKDF2_ITERATIONS = 150000  # OWASP >= 120,000 para SHA-256


def generate_key(size: int = HMAC_KEY_SIZE) -> bytes:
    """Genera una clave criptográficamente segura."""
    return secrets.token_bytes(size)


def generate_nonce(size: int = NONCE_SIZE) -> str:
    """Genera un nonce único criptográficamente seguro en base64."""
    return base64.b64encode(secrets.token_bytes(size)).decode('ascii')


def compute_hmac(key: bytes, message: bytes) -> str:
    """Calcula HMAC-SHA256 y devuelve en base64."""
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(mac).decode('ascii')


def verify_hmac(key: bytes, message: bytes, mac_b64: str) -> bool:
    """Verifica HMAC en tiempo constante (anti timing attacks)."""
    try:
        expected_mac = base64.b64decode(mac_b64)
        computed_mac = hmac.new(key, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected_mac, computed_mac)
    except Exception:
        return False


def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Hash de password con PBKDF2-HMAC-SHA256. Retorna (hash, salt)."""
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )
    
    return pw_hash, salt


def verify_password(password: str, pw_hash: bytes, salt: bytes) -> bool:
    """Verifica password en tiempo constante."""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(pw_hash, computed_hash)


def derive_user_key(master_key: bytes, username: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Deriva clave HMAC por usuario con HKDF. Retorna (clave, salt).

    Si no se proporciona salt, se genera uno determinista a partir del username
    para que cliente y servidor deriven la misma clave sin intercambio adicional.
    """
    if salt is None:
        salt = hashlib.sha256(f"user_salt:{username}".encode('utf-8')).digest()[:16]
    
    info = f"user:{username}".encode('utf-8')
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()     # HKDF-Extract
    okm = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()  # HKDF-Expand
    
    return okm[:32], salt


def secure_compare(a: str, b: str) -> bool:
    """Compara dos strings en tiempo constante."""
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def truncate_for_log(secret: str, visible_chars: int = 8) -> str:
    """Trunca secretos para logs."""
    if len(secret) <= visible_chars:
        return "***"
    return secret[:visible_chars] + "..." + f"[{len(secret)} chars total]"
