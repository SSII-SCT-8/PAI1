"""
Modelos de datos para la comunicación cliente-servidor.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from enum import Enum


class MessageType(Enum):
    """Tipos de mensajes del protocolo."""
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    TX = "TX"
    LOGOUT = "LOGOUT"
    PING = "PING"
    RESPONSE = "RESPONSE"
    ERROR = "ERROR"


@dataclass
class Message:
    """
    Estructura base de un mensaje del protocolo.
    
    Campos:
    - type: tipo de operación
    - ts: timestamp Unix en milisegundos
    - nonce: nonce único en base64 (>=128 bits recomendado)
    - username: identificador del usuario
    - payload: datos específicos del mensaje
    - mac: HMAC-SHA256 en base64 (calculado sobre todos los campos excepto 'mac')
    """
    type: str
    ts: int
    nonce: str
    username: str
    payload: Dict[str, Any] = field(default_factory=dict)
    mac: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el mensaje a diccionario."""
        return {
            "type": self.type,
            "ts": self.ts,
            "nonce": self.nonce,
            "username": self.username,
            "payload": self.payload,
            "mac": self.mac
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Crea un mensaje desde un diccionario."""
        return cls(
            type=data["type"],
            ts=data["ts"],
            nonce=data["nonce"],
            username=data["username"],
            payload=data.get("payload", {}),
            mac=data.get("mac")
        )


@dataclass
class RegisterPayload:
    """Payload para registro de usuario."""
    password: str


@dataclass
class LoginPayload:
    """Payload para login."""
    password: str


@dataclass
class TransactionPayload:
    """
    Payload para transacción financiera.
    
    Formato: Cuenta origen, Cuenta destino, Cantidad transferida
    NO se validan las cuentas ni cantidades; el servidor solo registra.
    """
    from_account: str
    to_account: str
    amount: str  # String para evitar problemas de precisión en JSON


@dataclass
class Response:
    """Respuesta del servidor."""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    code: Optional[str] = None
