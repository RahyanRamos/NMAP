"""Validação de alvos e intervalos de portas."""
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

MAX_PORT = 65_535

def parse_ports(expression: str) -> list[int]:
    """Converte ``22,53,80,8000-8010`` em uma lista ordenada e sem repetições."""
    if not expression or not expression.strip():
        raise ValueError("a lista de portas não pode estar vazia")

    ports: set[int] = set()
    for raw_part in expression.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("item vazio na lista de portas")

        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValueError(f"intervalo de portas inválido: {part!r}")
            start = _parse_port(bounds[0])
            end = _parse_port(bounds[1])
            if start > end:
                raise ValueError(f"intervalo invertido: {part!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(part))

    return sorted(ports)

def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"porta inválida: {value!r}") from exc
    if not 1 <= port <= MAX_PORT:
        raise ValueError(f"porta fora do intervalo 1-{MAX_PORT}: {port}")
    return port

def expand_targets(expressions: Iterable[str]) -> list[str]:
    """Expande IPv4 individuais e redes CIDR, preservando a ordem informada."""
    targets: list[str] = []
    seen: set[IPv4Address] = set()

    for expression in expressions:
        try:
            if "/" in expression:
                network = ip_network(expression, strict=False)
                if not isinstance(network, IPv4Network):
                    raise ValueError("IPv6 ainda não é suportado")
                addresses = network.hosts()
            else:
                address = ip_address(expression)
                if not isinstance(address, IPv4Address):
                    raise ValueError("IPv6 ainda não é suportado")
                addresses = (address,)
        except ValueError as exc:
            raise ValueError(f"alvo inválido {expression!r}: {exc}") from exc

        for address in addresses:
            if address not in seen:
                seen.add(address)
                targets.append(str(address))

    if not targets:
        raise ValueError("nenhum host utilizável foi encontrado")
    return targets
