"""
Funciones criptográficas para integridad y protección de credenciales.

DECISIONES DE DISEÑO:
- HMAC-SHA256 para integridad (clave >= 256 bits)
- PBKDF2-HMAC-SHA256 para KDF de passwords (100,000+ iteraciones)
- HKDF para derivación de claves por usuario
- hmac.compare_digest para comparaciones en tiempo constante
- secrets para generación de valores aleatorios criptográficamente seguros

POR QUÉ NO 32 BITS:
Una clave de 32 bits tiene solo 2^32 = 4,294,967,296 combinaciones posibles.
Con hardware moderno, un atacante puede probar todas las combinaciones en segundos
(ej: GPU puede hacer >10^9 hashes/segundo). Por eso usamos claves de 256 bits
que ofrecen 2^256 combinaciones, computacionalmente inviable de romper por fuerza bruta.
"""
import hmac
import hashlib
import secrets
import base64
from typing import Tuple


# Parámetros de seguridad recomendados
HMAC_KEY_SIZE = 32  # 256 bits para HMAC
NONCE_SIZE = 16     # 128 bits para nonce (suficiente para evitar colisiones)
SALT_SIZE = 16      # 128 bits para salt de password
PBKDF2_ITERATIONS = 150000  # OWASP recomienda >= 120,000 para SHA-256 (2023)


def generate_key(size: int = HMAC_KEY_SIZE) -> bytes:
    """
    Genera una clave criptográficamente segura.
    
    Args:
        size: Tamaño en bytes (default: 32 bytes = 256 bits)
    
    Returns:
        Clave aleatoria en bytes
    """
    return secrets.token_bytes(size)


def generate_nonce(size: int = NONCE_SIZE) -> str:
    """
    Genera un nonce único criptográficamente seguro.
    
    Returns:
        Nonce en base64
    """
    return base64.b64encode(secrets.token_bytes(size)).decode('ascii')


def compute_hmac(key: bytes, message: bytes) -> str:
    """
    Calcula HMAC-SHA256 de un mensaje.
    
    Args:
        key: Clave secreta (>= 256 bits recomendado)
        message: Mensaje a autenticar
    
    Returns:
        HMAC en base64
    """
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(mac).decode('ascii')


def verify_hmac(key: bytes, message: bytes, mac_b64: str) -> bool:
    """
    Verifica HMAC en tiempo constante para evitar ataques de canal lateral.
    
    Args:
        key: Clave secreta
        message: Mensaje a verificar
        mac_b64: HMAC esperado en base64
    
    Returns:
        True si el MAC es válido
    """
    try:
        expected_mac = base64.b64decode(mac_b64)
        computed_mac = hmac.new(key, message, hashlib.sha256).digest()
        # CRÍTICO: usar compare_digest para evitar timing attacks
        return hmac.compare_digest(expected_mac, computed_mac)
    except Exception:
        return False


def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Genera hash de password usando PBKDF2-HMAC-SHA256.
    
    Args:
        password: Contraseña en texto plano
        salt: Salt (si None, se genera uno aleatorio)
    
    Returns:
        Tupla (hash, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32  # 256 bits
    )
    
    return pw_hash, salt


def verify_password(password: str, pw_hash: bytes, salt: bytes) -> bool:
    """
    Verifica password en tiempo constante.
    
    Args:
        password: Password a verificar
        pw_hash: Hash almacenado
        salt: Salt usado
    
    Returns:
        True si la contraseña es correcta
    """
    computed_hash, _ = hash_password(password, salt)
    # CRÍTICO: comparación en tiempo constante
    return hmac.compare_digest(pw_hash, computed_hash)


def derive_user_key(master_key: bytes, username: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Deriva una clave específica por usuario usando HKDF.
    
    Esto permite que cada usuario tenga su propia clave HMAC derivada
    de una master key del servidor, evitando que un compromiso de una
    clave comprometa a todos los usuarios.
    
    Args:
        master_key: Clave maestra del servidor (256 bits)
        username: Identificador del usuario
        salt: Salt (si None, se genera uno)
    
    Returns:
        Tupla (clave_derivada, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # HKDF-Expand simplificado con HMAC-SHA256
    # En producción, usar cryptography.hazmat.primitives.kdf.hkdf.HKDF
    info = f"user:{username}".encode('utf-8')
    
    # HKDF-Extract
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    
    # HKDF-Expand
    okm = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()
    
    return okm[:32], salt  # 256 bits


def secure_compare(a: str, b: str) -> bool:
    """
    Compara dos strings en tiempo constante.
    
    Args:
        a: Primer string
        b: Segundo string
    
    Returns:
        True si son iguales
    """
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def truncate_for_log(secret: str, visible_chars: int = 8) -> str:
    """
    Trunca secretos para logs mostrando solo los primeros caracteres.
    
    Args:
        secret: Secreto a truncar
        visible_chars: Caracteres visibles
    
    Returns:
        String truncado con "..."
    """
    if len(secret) <= visible_chars:
        return "***"
    return secret[:visible_chars] + "..." + f"[{len(secret)} chars total]"
