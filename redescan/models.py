"""Tipos compartilhados pelo scanner."""
from dataclasses import dataclass
from enum import Enum

class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_OR_FILTERED = "open|filtered"

@dataclass(frozen=True, slots=True)
class ScanResult:
    target: str
    port: int
    protocol: Protocol
    state: PortState
    reason: str
