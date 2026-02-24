"""
Handlers para los diferentes tipos de mensajes del protocolo.
"""
import logging
import secrets
import time
from typing import Dict, Any, Optional

from .storage import Storage
from .security import SecurityManager
from .config import MASTER_KEY_BYTES
from ..common.crypto import (
    verify_password,
    derive_user_key,
    truncate_for_log
)
from ..common.errors import (
    AuthenticationError,
    UserAlreadyExistsError,
    SessionError
)


logger = logging.getLogger(__name__)


class MessageHandler:
    """Maneja los diferentes tipos de mensajes recibidos."""
    
    def __init__(self, storage: Storage, security: SecurityManager):
        self.storage = storage
        self.security = security
    
    def handle_register(
        self,
        username: str,
        payload: Dict[str, Any],
        client_ip: str
    ) -> Dict[str, Any]:
        """Maneja el registro de un nuevo usuario."""
        try:
            password = payload.get("password")
            if not password:
                return {
                    "success": False,
                    "message": "Password requerido"
                }
            
            if self.storage.user_exists(username):
                logger.warning(
                    f"REGISTER fallido: usuario '{username}' ya existe (IP: {client_ip})"
                )
                raise UserAlreadyExistsError(f"El usuario '{username}' ya existe")
            
            user_key, user_key_salt = derive_user_key(MASTER_KEY_BYTES, username)
            self.storage.create_user(username, password, user_key, user_key_salt)
            
            logger.info(f"Usuario '{username}' registrado exitosamente desde {client_ip}")
            
            return {
                "success": True,
                "message": f"Usuario '{username}' registrado exitosamente"
            }
            
        except UserAlreadyExistsError as e:
            return {
                "success": False,
                "message": str(e)
            }
        except Exception as e:
            logger.error(f"Error en REGISTER: {e}", exc_info=True)
            return {
                "success": False,
                "message": "Error interno del servidor"
            }
    
    def handle_login(
        self,
        username: str,
        payload: Dict[str, Any],
        client_ip: str
    ) -> Dict[str, Any]:
        """Maneja el login de un usuario."""
        try:
            self.security.check_rate_limit(username, client_ip)
            
            password = payload.get("password")
            if not password:
                self.security.record_login_attempt(username, client_ip, False)
                return {
                    "success": False,
                    "message": "Password requerido"
                }
            # Obtener usuario
            user = self.storage.get_user(username)
            if not user:
                self.security.record_login_attempt(username, client_ip, False)
                logger.warning(f"LOGIN fallido: usuario '{username}' no existe (IP: {client_ip})")
                return {
                    "success": False,
                    "message": "Credenciales inválidas"
                }
            
            if not verify_password(password, user["pw_hash"], user["pw_salt"]):
                self.security.record_login_attempt(username, client_ip, False)
                logger.warning(f"LOGIN fallido: password incorrecto para '{username}' (IP: {client_ip})")
                return {
                    "success": False,
                    "message": "Credenciales inválidas"
                }
            
            session_id = secrets.token_urlsafe(32)
            self.storage.create_session(username, session_id)
            
            self.security.reset_failed_attempts(username)
            self.security.record_login_attempt(username, client_ip, True)
            
            logger.info(f"LOGIN exitoso: usuario '{username}' desde {client_ip}")
            
            return {
                "success": True,
                "message": "Login exitoso",
                "data": {
                    "session_id": session_id,
                    "username": username
                }
            }
            
        except Exception as e:
            logger.error(f"Error en LOGIN: {e}", exc_info=True)
            return {
                "success": False,
                "message": str(e) if isinstance(e, (AuthenticationError, Exception)) else "Error interno"
            }
    
    def handle_transaction(
        self,
        username: str,
        payload: Dict[str, Any],
        raw_message: str,
        mac_trunc: str,
        ts: int
    ) -> Dict[str, Any]:
        """Maneja una transacción financiera."""
        try:
            from_account = payload.get("from_account")
            to_account = payload.get("to_account")
            amount = payload.get("amount")
            
            if not all([from_account, to_account, amount]):
                return {
                    "success": False,
                    "message": "Faltan campos: from_account, to_account, amount"
                }
            
            # Almacenar transacción
            tx_id = self.storage.store_transaction(
                username=username,
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                ts=ts,
                raw_message=raw_message,
                mac_trunc=mac_trunc
            )
            
            logger.info(
                f"TX {tx_id}: usuario '{username}' - "
                f"{from_account} -> {to_account}: {amount}"
            )
            
            return {
                "success": True,
                "message": "Transferencia realizada con integridad",
                "data": {
                    "transaction_id": tx_id,
                    "from_account": from_account,
                    "to_account": to_account,
                    "amount": amount
                }
            }
            
        except Exception as e:
            logger.error(f"Error en TX: {e}", exc_info=True)
            return {
                "success": False,
                "message": "Error procesando transacción"
            }
    
    def handle_logout(
        self,
        username: str,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Maneja el logout de un usuario."""
        try:
            session_id = payload.get("session_id")
            if session_id:
                self.storage.delete_session(session_id)
            
            logger.info(f"LOGOUT: usuario '{username}'")
            
            return {
                "success": True,
                "message": "Logout exitoso"
            }
            
        except Exception as e:
            logger.error(f"Error en LOGOUT: {e}", exc_info=True)
            return {
                "success": True,
                "message": "Logout completado"
            }
    
    def handle_ping(self, username: str) -> Dict[str, Any]:
        """Maneja un mensaje PING (keep-alive)."""
        return {
            "success": True,
            "message": "PONG",
            "data": {
                "server_time": int(time.time() * 1000)
            }
        }
