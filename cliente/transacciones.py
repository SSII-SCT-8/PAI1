"""Client transaction skeleton."""

from autenticacion import AutenticacionCliente


class TransaccionesCliente:
    """Placeholder API for transaction flows."""

    @staticmethod
    def generar_nonce() -> str:
        return "nonce-todo"

    @staticmethod
    def derive_hash(password: str, salt_hex: str, iterations: int = 100000) -> str:
        return ""

    @staticmethod
    def compute_mac(mensaje_base: str) -> str:
        _ = AutenticacionCliente.SESSION_KEY
        return ""

    @staticmethod
    def enviar_mensaje(mensaje: str) -> str:
        return "TODO: transacciones skeleton"

    @staticmethod
    def enviar_transaccion(usuario: str) -> None:
        print("TODO: transacciones skeleton")