import unittest
from redescan.models import PortState, Protocol
from redescan.scanner import Scanner

class FakeProber:
    def tcp(self, target, port):
        if port == 22:
            return PortState.OPEN, "SYN-ACK recebido"
        return PortState.CLOSED, "RST recebido"

    def udp(self, target, port):
        return PortState.OPEN_OR_FILTERED, "sem resposta"

class ScannerTests(unittest.TestCase):
    def test_combines_targets_ports_and_protocols(self):
        results = Scanner(FakeProber(), workers=2).scan(
            ["192.0.2.1"], [22, 80], [Protocol.TCP, Protocol.UDP]
        )

        self.assertEqual(
            [(item.port, item.protocol, item.state) for item in results],
            [
                (22, Protocol.TCP, PortState.OPEN),
                (80, Protocol.TCP, PortState.CLOSED),
                (22, Protocol.UDP, PortState.OPEN_OR_FILTERED),
                (80, Protocol.UDP, PortState.OPEN_OR_FILTERED),
            ],
        )

    def test_rejects_invalid_worker_count(self):
        with self.assertRaisesRegex(ValueError, "workers"):
            Scanner(FakeProber(), workers=0)

if __name__ == "__main__":
    unittest.main()
