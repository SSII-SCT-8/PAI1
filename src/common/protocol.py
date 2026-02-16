"""
Protocolo de comunicación sobre TCP con framing y canonicalización.

FORMATO DEL FRAME:
[4 bytes: longitud big-endian][N bytes: payload JSON UTF-8]

CANONICALIZACIÓN:
Para asegurar que HMAC se calcule de forma determinista, serializamos
el mensaje como JSON con sort_keys=True y separators=(',',':') sin espacios.
El campo 'mac' se excluye del cálculo.
"""
import json
import struct
import socket
from typing import Dict, Any, Optional
from .models import Message
from .errors import ProtocolError


def canonicalize_message(msg_dict: Dict[str, Any]) -> bytes:
    """
    Serializa un mensaje de forma canónica para cálculo de HMAC.
    
    Excluye el campo 'mac' para permitir su cálculo.
    Usa JSON con sort_keys=True y sin espacios.
    
    Args:
        msg_dict: Diccionario del mensaje
    
    Returns:
        Bytes canónicos del mensaje
    """
    # Crear copia sin el campo 'mac'
    canonical_dict = {k: v for k, v in msg_dict.items() if k != 'mac'}
    
    # Serializar con orden determinista
    canonical_json = json.dumps(
        canonical_dict,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    )
    
    return canonical_json.encode('utf-8')


def send_message(sock: socket.socket, data: Dict[str, Any]) -> None:
    """
    Envía un mensaje con framing por TCP.
    
    Formato: [4 bytes length][JSON payload]
    
    Args:
        sock: Socket TCP
        data: Diccionario a enviar
    
    Raises:
        ProtocolError: Si hay error de comunicación
    """
    try:
        # Serializar a JSON
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        
        # Crear frame: 4 bytes longitud (big-endian) + payload
        length = struct.pack('>I', len(payload))
        frame = length + payload
        
        # Enviar todo el frame
        sock.sendall(frame)
    except Exception as e:
        raise ProtocolError(f"Error enviando mensaje: {e}")


def receive_message(sock: socket.socket, timeout: Optional[float] = None) -> Dict[str, Any]:
    """
    Recibe un mensaje con framing por TCP.
    
    Lee primero 4 bytes para obtener la longitud y luego lee el payload completo.
    
    Args:
        sock: Socket TCP
        timeout: Timeout en segundos (None = sin timeout)
    
    Returns:
        Diccionario del mensaje recibido
    
    Raises:
        ProtocolError: Si hay error de comunicación o formato inválido
    """
    try:
        # Configurar timeout si se especifica
        original_timeout = sock.gettimeout()
        if timeout is not None:
            sock.settimeout(timeout)
        
        # Leer 4 bytes de longitud
        length_bytes = _recv_exact(sock, 4)
        if not length_bytes:
            raise ProtocolError("Conexión cerrada por el peer")
        
        # Decodificar longitud (big-endian)
        payload_length = struct.unpack('>I', length_bytes)[0]
        
        # Validar longitud razonable (evitar DoS)
        MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
        if payload_length > MAX_MESSAGE_SIZE:
            raise ProtocolError(f"Mensaje demasiado grande: {payload_length} bytes")
        
        # Leer payload completo
        payload = _recv_exact(sock, payload_length)
        if len(payload) != payload_length:
            raise ProtocolError("Payload incompleto")
        
        # Decodificar JSON
        data = json.loads(payload.decode('utf-8'))
        
        # Restaurar timeout original
        sock.settimeout(original_timeout)
        
        return data
        
    except json.JSONDecodeError as e:
        raise ProtocolError(f"JSON inválido: {e}")
    except socket.timeout:
        raise ProtocolError("Timeout esperando respuesta")
    except Exception as e:
        raise ProtocolError(f"Error recibiendo mensaje: {e}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Recibe exactamente n bytes del socket.
    
    Args:
        sock: Socket TCP
        n: Número de bytes a recibir
    
    Returns:
        Bytes recibidos (puede ser menos si se cierra la conexión)
    """
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break  # Conexión cerrada
        data += chunk
    return data


def create_error_response(code: str, message: str) -> Dict[str, Any]:
    """
    Crea una respuesta de error.
    
    Args:
        code: Código de error
        message: Mensaje descriptivo
    
    Returns:
        Diccionario de respuesta de error
    """
    return {
        "type": "ERROR",
        "code": code,
        "message": message,
        "success": False
    }


def create_success_response(message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Crea una respuesta exitosa.
    
    Args:
        message: Mensaje descriptivo
        data: Datos adicionales
    
    Returns:
        Diccionario de respuesta exitosa
    """
    response = {
        "type": "RESPONSE",
        "message": message,
        "success": True
    }
    if data:
        response["data"] = data
    return response
