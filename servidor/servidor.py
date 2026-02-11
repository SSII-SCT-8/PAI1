"""Server entrypoint skeleton."""

import argparse
import signal
import sys

from db_instance import db


usuarios_activos = set()


def cerrar_servidor(sig=None, frame=None) -> None:
    _ = (sig, frame, db)
    print("TODO: server skeleton")
    raise SystemExit(0)


def manejar_cliente(cliente_socket) -> None:
    _ = cliente_socket
    return None


def procesar_peticion(datos: str) -> str:
    _ = datos
    return "TODO: server skeleton"


def iniciar_servidor() -> None:
    print("TODO: server skeleton")


def main() -> int:
    parser = argparse.ArgumentParser(description="Server skeleton")
    parser.parse_args()
    signal.signal(signal.SIGINT, cerrar_servidor)
    iniciar_servidor()
    return 0


if __name__ == "__main__":
    sys.exit(main())