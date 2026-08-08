"""Sondagens de rede implementadas com Scapy ou sockets do sistema."""
import errno
import socket
from typing import Any
from redescan.models import PortState

FILTERED_ICMP_CODES = {1, 2, 9, 10, 13}

class ScapyProber:
    """Envia pacotes SYN TCP e datagramas UDP sem completar conexões TCP."""

    def __init__(self, timeout: float, retries: int) -> None:
        try:
            from scapy.all import ICMP, IP, TCP, UDP, RandInt, RandShort, send, sr1
        except ImportError as exc:
            raise RuntimeError(
                "a dependência Scapy não está instalada; execute "
                "'python -m pip install -r requirements.txt'"
            ) from exc

        self.timeout = timeout
        self.retries = retries
        self.ICMP = ICMP
        self.IP = IP
        self.TCP = TCP
        self.UDP = UDP
        self.RandInt = RandInt
        self.RandShort = RandShort
        self._send = send
        self._sr1 = sr1

    def tcp(self, target: str, port: int) -> tuple[PortState, str]:
        packet = self.IP(dst=target) / self.TCP(
            sport=int(self.RandShort()),
            dport=port,
            seq=int(self.RandInt()),
            flags="S",
        )
        response = self._probe(packet)
        if response is None:
            return PortState.FILTERED, "sem resposta"

        if response.haslayer(self.TCP):
            flags = int(response[self.TCP].flags)
            if flags & 0x12 == 0x12:  # SYN + ACK
                # Encerra a tentativa sem completar o three-way handshake.
                reset = self.IP(dst=target) / self.TCP(
                    dport=port,
                    sport=response[self.TCP].dport,
                    seq=response[self.TCP].ack,
                    flags="R",
                )
                self._send(reset, verbose=0)
                return PortState.OPEN, "SYN-ACK recebido"
            if flags & 0x04:  # RST
                return PortState.CLOSED, "RST recebido"

        if response.haslayer(self.ICMP):
            icmp = response[self.ICMP]
            if int(icmp.type) == 3 and int(icmp.code) in FILTERED_ICMP_CODES | {3}:
                return PortState.FILTERED, f"ICMP inalcançável (código {int(icmp.code)})"

        return PortState.FILTERED, "resposta inesperada"

    def udp(self, target: str, port: int) -> tuple[PortState, str]:
        packet = self.IP(dst=target) / self.UDP(sport=int(self.RandShort()), dport=port)
        response = self._probe(packet)
        if response is None:
            return PortState.OPEN_OR_FILTERED, "sem resposta"

        if response.haslayer(self.UDP):
            return PortState.OPEN, "resposta UDP recebida"

        if response.haslayer(self.ICMP):
            icmp = response[self.ICMP]
            if int(icmp.type) == 3 and int(icmp.code) == 3:
                return PortState.CLOSED, "ICMP porta inalcançável"
            if int(icmp.type) == 3:
                return PortState.FILTERED, f"ICMP inalcançável (código {int(icmp.code)})"

        return PortState.FILTERED, "resposta inesperada"

    def _probe(self, packet: Any) -> Any | None:
        response = None
        for _ in range(self.retries + 1):
            response = self._sr1(packet, timeout=self.timeout, verbose=0)
            if response is not None:
                break
        return response

class SocketProber:
    """Sonda portas com a API de sockets, sem exigir pacotes raw ou administrador."""

    _CLOSED_ERRORS = {errno.ECONNREFUSED, 10054, 10061}
    _FILTERED_ERRORS = {
        errno.EACCES,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
        10013,  # WSAEACCES
        10051,  # WSAENETUNREACH
        10060,  # WSAETIMEDOUT
        10065,  # WSAEHOSTUNREACH
    }

    def __init__(self, timeout: float, retries: int) -> None:
        self.timeout = timeout
        self.retries = retries

    def tcp(self, target: str, port: int) -> tuple[PortState, str]:
        last_error: int | str = errno.ETIMEDOUT
        for attempt in range(self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(self.timeout)
                    connection.connect((target, port))
                return PortState.OPEN, "conexão TCP aceita"
            except ConnectionRefusedError as exc:
                code = _socket_error_code(exc)
                return PortState.CLOSED, f"conexão recusada (código {code})"
            except TimeoutError:
                last_error = errno.ETIMEDOUT
                if attempt < self.retries:
                    continue
                return PortState.FILTERED, "sem resposta (timeout)"
            except OSError as exc:
                code = _socket_error_code(exc)
                if code in self._CLOSED_ERRORS:
                    return PortState.CLOSED, f"conexão recusada (código {code})"
                last_error = code
                if attempt < self.retries:
                    continue

        if last_error in self._FILTERED_ERRORS:
            return PortState.FILTERED, f"sem acesso ou resposta (código {last_error})"
        return PortState.FILTERED, f"erro de socket (código {last_error})"

    def udp(self, target: str, port: int) -> tuple[PortState, str]:
        for attempt in range(self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                    datagram.settimeout(self.timeout)
                    datagram.connect((target, port))
                    datagram.send(b"")
                    datagram.recv(4096)
                return PortState.OPEN, "resposta UDP recebida"
            except (ConnectionRefusedError, ConnectionResetError) as exc:
                code = _socket_error_code(exc)
                return PortState.CLOSED, f"ICMP porta inalcançável (código {code})"
            except TimeoutError:
                if attempt == self.retries:
                    return PortState.OPEN_OR_FILTERED, "sem resposta"
            except OSError as exc:
                code = _socket_error_code(exc)
                if code in self._CLOSED_ERRORS:
                    return PortState.CLOSED, f"porta inalcançável (código {code})"
                return PortState.FILTERED, f"erro de rede (código {code})"

        return PortState.OPEN_OR_FILTERED, "sem resposta"

def _socket_error_code(error: OSError) -> int | str:
    """Obtém o código POSIX ou Winsock preservado pela exceção."""
    return getattr(error, "winerror", None) or error.errno or "desconhecido"
