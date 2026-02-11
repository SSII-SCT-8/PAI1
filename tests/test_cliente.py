"""Client test skeleton."""

import unittest


def enviar_mensaje(mensaje: str) -> str:
    _ = mensaje
    return "TODO"


class TestCliente(unittest.TestCase):
    def test_fuerza_bruta_login(self):
        self.assertTrue(True)

    def test_replay_attack(self):
        self.assertTrue(True)

    def test_inyeccion_sql_login(self):
        self.assertTrue(True)

    def test_modificar_respuesta(self):
        self.assertTrue(True)

    def test_enviar_datos_malformados(self):
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()