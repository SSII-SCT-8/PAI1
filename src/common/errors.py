"""
Excepciones personalizadas para el sistema de verificación de integridad.
"""


class SecurityError(Exception):
    """Error base de seguridad."""

    pass


class InvalidMACError(SecurityError):
    """MAC inválido detectado (posible MITM)."""

    pass


class ReplayAttackError(SecurityError):
    """Nonce repetido detectado (ataque replay)."""

    pass


class RateLimitError(SecurityError):
    """Excedido el límite de intentos permitidos."""

    pass


class InvalidTimestampError(SecurityError):
    """Timestamp fuera del rango permitido."""

    pass


class AuthenticationError(Exception):
    """Error de autenticación."""

    pass


class UserAlreadyExistsError(Exception):
    """Usuario ya existe en el sistema."""

    pass


class SessionError(Exception):
    """Error relacionado con sesiones."""

    pass


class ProtocolError(Exception):
    """Error en el protocolo de comunicación."""

    pass
