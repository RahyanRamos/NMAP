import errno
import unittest
from unittest.mock import MagicMock, patch
from redescan.models import PortState
from redescan.probes import SocketProber

class SocketProberTests(unittest.TestCase):
    def setUp(self):
        self.socket = MagicMock()
        self.context = self.socket.__enter__.return_value
        self.patch = patch("redescan.probes.socket.socket", return_value=self.socket)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.prober = SocketProber(timeout=0.1, retries=0)

    def test_tcp_open_when_connection_is_accepted(self):
        self.context.connect.return_value = None

        state, reason = self.prober.tcp("192.0.2.1", 80)

        self.assertEqual(state, PortState.OPEN)
        self.assertIn("aceita", reason)

    def test_tcp_closed_when_connection_is_refused(self):
        self.context.connect.side_effect = ConnectionRefusedError(
            errno.ECONNREFUSED, "connection refused"
        )

        state, reason = self.prober.tcp("192.0.2.1", 80)

        self.assertEqual(state, PortState.CLOSED)
        self.assertIn("recusada", reason)

    def test_tcp_filtered_on_timeout(self):
        self.context.connect.side_effect = TimeoutError("timed out")

        state, reason = self.prober.tcp("192.0.2.1", 80)

        self.assertEqual(state, PortState.FILTERED)
        self.assertIn("timeout", reason)

    def test_udp_open_when_a_response_arrives(self):
        self.context.recv.return_value = b"response"

        state, reason = self.prober.udp("192.0.2.1", 53)

        self.assertEqual(state, PortState.OPEN)
        self.assertIn("UDP", reason)

    def test_udp_closed_after_connection_reset(self):
        self.context.recv.side_effect = ConnectionResetError(10054, "reset")

        state, reason = self.prober.udp("192.0.2.1", 53)

        self.assertEqual(state, PortState.CLOSED)
        self.assertIn("inalcançável", reason)

    def test_udp_open_or_filtered_on_timeout(self):
        self.context.recv.side_effect = TimeoutError("timed out")

        state, reason = self.prober.udp("192.0.2.1", 53)

        self.assertEqual(state, PortState.OPEN_OR_FILTERED)
        self.assertIn("sem resposta", reason)

if __name__ == "__main__":
    unittest.main()
