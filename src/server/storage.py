"""
Capa de almacenamiento con SQLite para persistencia de usuarios, transacciones, nonces y sesiones.
"""
import sqlite3
import json
import base64
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from contextlib import contextmanager

from .config import DB_PATH, DB_TIMEOUT
from ..common.crypto import hash_password, PBKDF2_ITERATIONS


logger = logging.getLogger(__name__)


class Storage:
    """Maneja la persistencia en SQLite."""
    
    def __init__(self, db_path: Path = DB_PATH):
        """
        Inicializa el storage.
        
        Args:
            db_path: Ruta al archivo SQLite
        """
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager para conexiones SQLite."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=DB_TIMEOUT,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Crea las tablas si no existen."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Tabla de usuarios
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    pw_hash BLOB NOT NULL,
                    pw_salt BLOB NOT NULL,
                    kdf_params_json TEXT NOT NULL,
                    user_key BLOB NOT NULL,
                    user_key_salt BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    CONSTRAINT username_unique UNIQUE (username)
                )
            """)
            
            # Tabla de nonces (para anti-replay)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    CONSTRAINT nonce_unique UNIQUE (username, nonce)
                )
            """)
            
            # Índice para limpiar nonces antiguos
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nonces_ts 
                ON nonces(ts)
            """)
            
            # Tabla de sesiones
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    session_id TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                )
            """)
            
            # Tabla de transacciones
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    from_account TEXT NOT NULL,
                    to_account TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    raw_message_json TEXT NOT NULL,
                    mac_trunc TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            
            # Tabla de rate limiting
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    ts INTEGER NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_login_attempts_username_ts 
                ON login_attempts(username, ts)
            """)
            
            logger.info(f"Base de datos inicializada en {self.db_path}")
    
    # ==================== USUARIOS ====================
    
    def create_user(
        self,
        username: str,
        password: str,
        user_key: bytes,
        user_key_salt: bytes
    ) -> bool:
        """
        Crea un nuevo usuario.
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            user_key: Clave derivada para HMAC del usuario
            user_key_salt: Salt usado en la derivación
        
        Returns:
            True si se creó correctamente
        
        Raises:
            sqlite3.IntegrityError: Si el usuario ya existe
        """
        pw_hash, pw_salt = hash_password(password)
        kdf_params = {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt_size": len(pw_salt)
        }
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    username, pw_hash, pw_salt, kdf_params_json,
                    user_key, user_key_salt, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                pw_hash,
                pw_salt,
                json.dumps(kdf_params),
                user_key,
                user_key_salt,
                int(datetime.now().timestamp() * 1000)
            ))
            
        logger.info(f"Usuario '{username}' creado exitosamente")
        return True
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene información de un usuario.
        
        Args:
            username: Nombre de usuario
        
        Returns:
            Diccionario con datos del usuario o None si no existe
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, pw_hash, pw_salt, kdf_params_json,
                       user_key, user_key_salt, created_at
                FROM users
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                "id": row["id"],
                "username": row["username"],
                "pw_hash": row["pw_hash"],
                "pw_salt": row["pw_salt"],
                "kdf_params": json.loads(row["kdf_params_json"]),
                "user_key": row["user_key"],
                "user_key_salt": row["user_key_salt"],
                "created_at": row["created_at"]
            }
    
    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe."""
        return self.get_user(username) is not None
    
    # ==================== NONCES ====================
    
    def store_nonce(self, username: str, nonce: str, ts: int) -> bool:
        """
        Almacena un nonce para anti-replay.
        
        Args:
            username: Usuario
            nonce: Nonce en base64
            ts: Timestamp del mensaje
        
        Returns:
            True si se almacenó (False si ya existía = replay)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO nonces (username, nonce, ts, created_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    username,
                    nonce,
                    ts,
                    int(datetime.now().timestamp() * 1000)
                ))
            return True
        except sqlite3.IntegrityError:
            # Nonce ya existe = replay attack
            return False
    
    def cleanup_old_nonces(self, max_age_seconds: int = 600):
        """
        Limpia nonces antiguos (fuera de la ventana de replay).
        
        Args:
            max_age_seconds: Edad máxima en segundos
        """
        cutoff_ts = int((datetime.now().timestamp() - max_age_seconds) * 1000)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM nonces WHERE ts < ?", (cutoff_ts,))
            deleted = cursor.rowcount
            
        if deleted > 0:
            logger.debug(f"Limpiados {deleted} nonces antiguos")
    
    # ==================== SESIONES ====================
    
    def create_session(self, username: str, session_id: str) -> bool:
        """
        Crea una nueva sesión.
        
        Args:
            username: Usuario
            session_id: ID de sesión único
        
        Returns:
            True si se creó correctamente
        """
        now = int(datetime.now().timestamp() * 1000)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (username, session_id, created_at, last_seen)
                VALUES (?, ?, ?, ?)
            """, (username, session_id, now, now))
        
        logger.info(f"Sesión creada para usuario '{username}'")
        return True
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de una sesión."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, session_id, created_at, last_seen
                FROM sessions
                WHERE session_id = ?
            """, (session_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                "id": row["id"],
                "username": row["username"],
                "session_id": row["session_id"],
                "created_at": row["created_at"],
                "last_seen": row["last_seen"]
            }
    
    def update_session_last_seen(self, session_id: str) -> bool:
        """Actualiza el último acceso de una sesión."""
        now = int(datetime.now().timestamp() * 1000)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions
                SET last_seen = ?
                WHERE session_id = ?
            """, (now, session_id))
            
        return cursor.rowcount > 0
    
    def delete_session(self, session_id: str) -> bool:
        """Elimina una sesión (logout)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        
        return cursor.rowcount > 0
    
    # ==================== TRANSACCIONES ====================
    
    def store_transaction(
        self,
        username: str,
        from_account: str,
        to_account: str,
        amount: str,
        ts: int,
        raw_message: str,
        mac_trunc: str
    ) -> int:
        """
        Almacena una transacción.
        
        Args:
            username: Usuario que realiza la transacción
            from_account: Cuenta origen
            to_account: Cuenta destino
            amount: Cantidad
            ts: Timestamp del mensaje
            raw_message: Mensaje JSON completo
            mac_trunc: MAC truncado para log
        
        Returns:
            ID de la transacción
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO transactions (
                    username, from_account, to_account, amount, ts,
                    raw_message_json, mac_trunc, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                from_account,
                to_account,
                amount,
                ts,
                raw_message,
                mac_trunc,
                int(datetime.now().timestamp() * 1000)
            ))
            
            tx_id = cursor.lastrowid
        
        logger.info(f"Transacción {tx_id} registrada para usuario '{username}'")
        return tx_id
    
    def get_user_transactions(self, username: str) -> List[Dict[str, Any]]:
        """Obtiene todas las transacciones de un usuario."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, from_account, to_account, amount, ts, created_at
                FROM transactions
                WHERE username = ?
                ORDER BY ts DESC
            """, (username,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== RATE LIMITING ====================
    
    def record_login_attempt(self, username: str, ip_address: str, success: bool) -> None:
        """
        Registra un intento de login.
        
        Args:
            username: Usuario
            ip_address: Dirección IP
            success: Si el intento fue exitoso
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, success, ts)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                ip_address,
                1 if success else 0,
                int(datetime.now().timestamp() * 1000)
            ))
    
    def get_failed_login_count(self, username: str, window_seconds: int) -> int:
        """
        Obtiene el número de intentos fallidos en una ventana de tiempo.
        
        Args:
            username: Usuario
            window_seconds: Ventana de tiempo en segundos
        
        Returns:
            Número de intentos fallidos
        """
        cutoff_ts = int((datetime.now().timestamp() - window_seconds) * 1000)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM login_attempts
                WHERE username = ? AND success = 0 AND ts > ?
            """, (username, cutoff_ts))
            
            row = cursor.fetchone()
            return row["count"] if row else 0
    
    def cleanup_old_login_attempts(self, max_age_seconds: int = 3600):
        """Limpia intentos de login antiguos."""
        cutoff_ts = int((datetime.now().timestamp() - max_age_seconds) * 1000)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM login_attempts WHERE ts < ?", (cutoff_ts,))
            deleted = cursor.rowcount
        
        if deleted > 0:
            logger.debug(f"Limpiados {deleted} intentos de login antiguos")

    def clear_failed_login_attempts(self, username: str) -> None:
        """
        Elimina los intentos fallidos de un usuario tras login exitoso.
        
        Args:
            username: Usuario cuyos intentos fallidos se limpian
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM login_attempts WHERE username = ? AND success = 0",
                (username,)
            )
            deleted = cursor.rowcount
        
        if deleted > 0:
            logger.debug(f"Limpiados {deleted} intentos fallidos de '{username}'")
