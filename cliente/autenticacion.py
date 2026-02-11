"""Client authentication skeleton."""

from typing import Optional


class AutenticacionCliente:
    """Placeholder API for authentication flows."""

    SALT_USUARIO: Optional[str] = None
    SESSION_KEY: Optional[bytes] = None

    @staticmethod
    def enviar_mensaje(mensaje: str) -> str:
        return "TODO: autenticacion skeleton"

    @staticmethod
    def derive_verifier(password: str, salt_hex: str, iterations: int = 100000) -> bytes:
        return b""

    @staticmethod
    def derive_hash(password: str, salt_hex: str, iterations: int = 100000) -> str:
        return ""

    @staticmethod
    def compute_response(verifier, challenge: str) -> str:
        return ""

    @staticmethod
    def derive_key(password: str, salt_hex: str, iterations: int = 100000) -> bytes:
        return b""

    @staticmethod
    def validar_contrasena(password: str) -> bool:
        return True

    @staticmethod
    def iniciar_sesion() -> Optional[str]:
        return None

    @staticmethod
    def registrar_usuario() -> None:
        return None

    @staticmethod
    def cerrar_sesion(usuario: str) -> bool:
        return True