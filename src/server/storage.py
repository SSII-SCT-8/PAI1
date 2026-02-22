"""Capa de almacenamiento con SQLite."""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.crypto import hash_password
from .config import DB_PATH, DB_TIMEOUT

logger = logging.getLogger(__name__)


class Storage:
    """Maneja la persistencia en SQLite."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Context manager para conexiones SQLite."""
        conn = sqlite3.connect(
            str(self.db_path), timeout=DB_TIMEOUT, check_same_thread=False
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    user_key BLOB NOT NULL,
                    user_key_salt BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    CONSTRAINT username_unique UNIQUE (username)
                )
            """)

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

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nonces_ts 
                ON nonces(ts)
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    session_id TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                )
            """)

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

    def create_user(
        self, username: str, password: str, user_key: bytes, user_key_salt: bytes
    ) -> bool:
        """Crea un nuevo usuario."""
        password = hash_password(password)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (
                    username, password,
                    user_key, user_key_salt, created_at
                )
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    username,
                    password,
                    user_key,
                    user_key_salt,
                    int(datetime.now().timestamp() * 1000),
                ),
            )

        logger.info(f"Usuario '{username}' creado exitosamente")
        return True

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de un usuario o None si no existe."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, password,
                       user_key, user_key_salt, created_at
                FROM users
                WHERE username = ?
            """,
                (username,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "id": row["id"],
                "username": row["username"],
                "password": row["password"],
                "user_key": row["user_key"],
                "user_key_salt": row["user_key_salt"],
                "created_at": row["created_at"],
            }

    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe."""
        return self.get_user(username) is not None

    def store_nonce(self, username: str, nonce: str, ts: int) -> bool:
        """Almacena un nonce (retorna False si ya existía = replay)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO nonces (username, nonce, ts, created_at)
                    VALUES (?, ?, ?, ?)
                """,
                    (username, nonce, ts, int(datetime.now().timestamp() * 1000)),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def cleanup_old_nonces(self, max_age_seconds: int = 600):
        """Limpia nonces fuera de la ventana de replay."""
        cutoff_ts = int((datetime.now().timestamp() - max_age_seconds) * 1000)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM nonces WHERE ts < ?", (cutoff_ts,))
            deleted = cursor.rowcount

        if deleted > 0:
            logger.debug(f"Limpiados {deleted} nonces antiguos")

    def create_session(self, username: str, session_id: str) -> bool:
        """Crea una nueva sesión."""
        now = int(datetime.now().timestamp() * 1000)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions (username, session_id, created_at, last_seen)
                VALUES (?, ?, ?, ?)
            """,
                (username, session_id, now, now),
            )

        logger.info(f"Sesión creada para usuario '{username}'")
        return True

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de una sesión."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, session_id, created_at, last_seen
                FROM sessions
                WHERE session_id = ?
            """,
                (session_id,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            return {
                "id": row["id"],
                "username": row["username"],
                "session_id": row["session_id"],
                "created_at": row["created_at"],
                "last_seen": row["last_seen"],
            }

    def update_session_last_seen(self, session_id: str) -> bool:
        """Actualiza el último acceso de una sesión."""
        now = int(datetime.now().timestamp() * 1000)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE sessions
                SET last_seen = ?
                WHERE session_id = ?
            """,
                (now, session_id),
            )

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
        mac_trunc: str,
    ) -> int:
        """Almacena una transacción y retorna su ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO transactions (
                    username, from_account, to_account, amount, ts,
                    raw_message_json, mac_trunc, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    username,
                    from_account,
                    to_account,
                    amount,
                    ts,
                    raw_message,
                    mac_trunc,
                    int(datetime.now().timestamp() * 1000),
                ),
            )

            tx_id = cursor.lastrowid

        logger.info(f"Transacción {tx_id} registrada para usuario '{username}'")
        return tx_id

    def get_user_transactions(self, username: str) -> List[Dict[str, Any]]:
        """Obtiene todas las transacciones de un usuario."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, from_account, to_account, amount, ts, created_at
                FROM transactions
                WHERE username = ?
                ORDER BY ts DESC
            """,
                (username,),
            )

            return [dict(row) for row in cursor.fetchall()]

    def record_login_attempt(
        self, username: str, ip_address: str, success: bool
    ) -> None:
        """Registra un intento de login."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO login_attempts (username, ip_address, success, ts)
                VALUES (?, ?, ?, ?)
            """,
                (
                    username,
                    ip_address,
                    1 if success else 0,
                    int(datetime.now().timestamp() * 1000),
                ),
            )

    def get_failed_login_count(self, username: str, window_seconds: int) -> int:
        """Obtiene el número de intentos fallidos en una ventana de tiempo."""
        cutoff_ts = int((datetime.now().timestamp() - window_seconds) * 1000)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) as count
                FROM login_attempts
                WHERE username = ? AND success = 0 AND ts > ?
            """,
                (username, cutoff_ts),
            )

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
        """Elimina los intentos fallidos de un usuario tras login exitoso."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM login_attempts WHERE username = ? AND success = 0",
                (username,),
            )
            deleted = cursor.rowcount

        if deleted > 0:
            logger.debug(f"Limpiados {deleted} intentos fallidos de '{username}'")
