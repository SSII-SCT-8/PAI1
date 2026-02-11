"""Client entrypoint skeleton."""

import argparse
import signal
import sys

from autenticacion import AutenticacionCliente
from transacciones import TransaccionesCliente


def manejar_interrupcion(sig=None, frame=None) -> None:
    print("TODO: client skeleton")
    raise SystemExit(0)


def menu_sesion(usuario: str) -> None:
    _ = (AutenticacionCliente, TransaccionesCliente, usuario)
    print("TODO: client skeleton")


def menu() -> None:
    print("TODO: client skeleton")


def main() -> int:
    parser = argparse.ArgumentParser(description="Client skeleton")
    parser.parse_args()
    signal.signal(signal.SIGINT, manejar_interrupcion)
    menu()
    return 0


if __name__ == "__main__":
    sys.exit(main())