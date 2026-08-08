"""Motor concorrente de varredura."""

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Protocol as TypingProtocol

from redescan.models import PortState, Protocol, ScanResult


class Prober(TypingProtocol):
    def tcp(self, target: str, port: int) -> tuple[PortState, str]: ...

    def udp(self, target: str, port: int) -> tuple[PortState, str]: ...


class Scanner:
    def __init__(self, prober: Prober, workers: int = 100) -> None:
        if workers < 1:
            raise ValueError("workers deve ser maior que zero")
        self.prober = prober
        self.workers = workers

    def scan(
        self,
        targets: Iterable[str],
        ports: Iterable[int],
        protocols: Iterable[Protocol],
        on_result: Callable[[ScanResult], None] | None = None,
    ) -> list[ScanResult]:
        jobs = [
            (target, port, protocol)
            for target in targets
            for protocol in protocols
            for port in ports
        ]
        results: list[ScanResult] = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            pending = {
                executor.submit(self._scan_one, target, port, protocol): (
                    target,
                    port,
                    protocol,
                )
                for target, port, protocol in jobs
            }
            for future in as_completed(pending):
                result = future.result()
                results.append(result)
                if on_result is not None:
                    on_result(result)

        return sorted(results, key=lambda item: (item.target, item.protocol.value, item.port))

    def _scan_one(self, target: str, port: int, protocol: Protocol) -> ScanResult:
        if protocol is Protocol.TCP:
            state, reason = self.prober.tcp(target, port)
        else:
            state, reason = self.prober.udp(target, port)
        return ScanResult(target, port, protocol, state, reason)
