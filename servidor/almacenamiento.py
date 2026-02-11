"""Server storage skeleton."""


class DatabaseManager:
    def __init__(self, db_name: str = "banco.db") -> None:
        self.db_name = db_name
        self.max_intentos = 5
        self.tiempo_bloqueo = 60
        self.challenge_store = {}

    def inicializar_db(self) -> None:
        return None

    def obtener_id_usuario(self, nombre_usuario: str):
        return None

    def ejecutar_temporizador_bloqueos(self) -> None:
        return None

    def generate_challenge(self) -> str:
        return "challenge-todo"

    def server_login_phase1(self, username: str):
        return None, None

    def compute_response(self, verifier, challenge: str) -> str:
        return ""

    def server_login_phase2(self, username: str, client_response: str) -> str:
        return "TODO: login phase 2 skeleton"

    def server_register_phase1(self, username: str):
        return None, None, "TODO"

    def server_register_phase2(
        self,
        username: str,
        login_hash: str,
        master_hash: str,
        response_login: str,
        response_master: str,
    ) -> str:
        return "TODO: register phase 2 skeleton"

    def registrar_transaccion(
        self,
        usuario: str,
        origen: str,
        destino: str,
        cantidad,
        nonce: str,
        mac_cliente: str,
    ) -> str:
        return "TODO: transaction skeleton"

    def obtener_salt_de_usuario(self, nombre_usuario: str):
        return None


if __name__ == "__main__":
    db = DatabaseManager()
    print("TODO: almacenamiento skeleton", db.db_name)