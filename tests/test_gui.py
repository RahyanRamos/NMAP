"""Testes da lógica não visual da interface gráfica.

Os widgets em si não são exercitados aqui: o objetivo é cobrir as partes da
GUI que contêm decisão de programa — o adaptador de cancelamento e a leitura
validada dos campos do formulário.

O módulo é ignorado quando o Tkinter não está instalado, situação comum em
servidores sem ambiente gráfico.
"""
import threading
import unittest

try:
    import tkinter  # noqa: F401

    from redescan.gui import CancellableProber, RedeScanGUI

    GUI_DISPONIVEL = True
except ImportError:  # pragma: no cover - depende do ambiente
    GUI_DISPONIVEL = False

from redescan.models import PortState, Protocol


class ProberFalso:
    """Prober de mentira que registra as chamadas recebidas."""

    def __init__(self) -> None:
        self.chamadas: list[tuple[str, int]] = []

    def tcp(self, target: str, port: int) -> tuple[PortState, str]:
        self.chamadas.append((target, port))
        return PortState.OPEN, "simulado"

    def udp(self, target: str, port: int) -> tuple[PortState, str]:
        self.chamadas.append((target, port))
        return PortState.CLOSED, "simulado"


class _VarFalsa:
    """Substituto de tkinter.StringVar para os testes."""

    def __init__(self, valor: str) -> None:
        self._valor = valor

    def get(self) -> str:
        return self._valor


@unittest.skipUnless(GUI_DISPONIVEL, "Tkinter não está disponível neste ambiente")
class TestCancellableProber(unittest.TestCase):
    def setUp(self) -> None:
        self.evento = threading.Event()
        self.interno = ProberFalso()
        self.prober = CancellableProber(self.interno, self.evento)

    def test_delega_quando_nao_cancelado(self) -> None:
        estado, motivo = self.prober.tcp("127.0.0.1", 80)
        self.assertEqual(estado, PortState.OPEN)
        self.assertEqual(motivo, "simulado")
        self.assertEqual(self.interno.chamadas, [("127.0.0.1", 80)])

    def test_tcp_nao_toca_na_rede_apos_cancelamento(self) -> None:
        self.evento.set()
        estado, motivo = self.prober.tcp("127.0.0.1", 80)
        self.assertEqual(estado, PortState.FILTERED)
        self.assertIn("cancelado", motivo)
        self.assertEqual(self.interno.chamadas, [])

    def test_udp_nao_toca_na_rede_apos_cancelamento(self) -> None:
        self.evento.set()
        estado, _ = self.prober.udp("127.0.0.1", 53)
        self.assertEqual(estado, PortState.FILTERED)
        self.assertEqual(self.interno.chamadas, [])


@unittest.skipUnless(GUI_DISPONIVEL, "Tkinter não está disponível neste ambiente")
class TestLeituraDeOpcoes(unittest.TestCase):
    """Valida _read_options sem instanciar a janela.

    A leitura dos campos não depende de nenhum widget, apenas dos valores das
    variáveis de controle. Criar a instância sem chamar __init__ evita exigir
    um servidor gráfico durante os testes.
    """

    def _gui(self, **campos):
        gui = RedeScanGUI.__new__(RedeScanGUI)
        padroes = {
            "var_targets": "127.0.0.1",
            "var_ports": "80",
            "var_protocol": "tcp",
            "var_method": "connect",
            "var_timeout": "1.0",
            "var_retries": "1",
            "var_workers": "10",
        }
        padroes.update(campos)
        for nome, valor in padroes.items():
            setattr(gui, nome, _VarFalsa(valor))
        return gui

    def test_le_opcoes_validas(self) -> None:
        opcoes = self._gui(var_ports="80,443", var_protocol="both")._read_options()
        self.assertEqual(opcoes["targets"], ["127.0.0.1"])
        self.assertEqual(opcoes["ports"], [80, 443])
        self.assertEqual(opcoes["protocols"], [Protocol.TCP, Protocol.UDP])
        self.assertEqual(opcoes["total"], 4)

    def test_aceita_alvos_separados_por_virgula(self) -> None:
        opcoes = self._gui(var_targets="127.0.0.1, 127.0.0.2")._read_options()
        self.assertEqual(opcoes["targets"], ["127.0.0.1", "127.0.0.2"])

    def test_aceita_virgula_decimal_no_timeout(self) -> None:
        self.assertEqual(self._gui(var_timeout="1,5")._read_options()["timeout"], 1.5)

    def test_rejeita_alvo_vazio(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_targets="   ")._read_options()

    def test_rejeita_timeout_zero(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_timeout="0")._read_options()

    def test_rejeita_valor_nao_numerico(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_workers="muitas")._read_options()

    def test_rejeita_quantidade_invalida_de_threads(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_workers="0")._read_options()

    def test_rejeita_porta_fora_da_faixa(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_ports="70000")._read_options()

    def test_rejeita_escopo_excessivo(self) -> None:
        with self.assertRaises(ValueError):
            self._gui(var_targets="10.0.0.0/8", var_ports="1-100")._read_options()


if __name__ == "__main__":
    unittest.main()
