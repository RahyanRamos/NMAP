"""Interface de linha de comando do RedeScan."""
import argparse
import json
import platform
import sys
from collections import Counter
from dataclasses import asdict
from redescan.models import Protocol, ScanResult
from redescan.parsing import expand_targets, parse_ports
from redescan.probes import ScapyProber, SocketProber
from redescan.scanner import Scanner

DEFAULT_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080"
MAX_JOBS_WITHOUT_CONFIRMATION = 65_536

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redescan",
        description="Scanner educacional de portas TCP e UDP para IPv4.",
        epilog="Use somente em sistemas e redes para os quais você possui autorização.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="ALVO",
        help="um ou mais IPv4/CIDRs (ex.: 192.168.1.10 192.168.1.0/24)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        metavar="PORTAS",
        help=f"portas separadas por vírgula ou intervalo (padrão: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "-P",
        "--protocol",
        choices=("tcp", "udp", "both"),
        default="both",
        help="protocolo a verificar (padrão: both)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="espera por resposta em segundos"
    )
    parser.add_argument(
        "-r", "--retries", type=int, default=1, help="novas tentativas após timeout"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100, help="máximo de sondagens concorrentes"
    )
    parser.add_argument(
        "-m",
        "--method",
        choices=("auto", "raw", "connect"),
        default="auto",
        help="método: raw (SYN/Scapy), connect (sockets) ou auto (padrão)",
    )
    parser.add_argument("--json", action="store_true", help="emite o resultado em JSON")
    parser.add_argument(
        "--only-active",
        action="store_true",
        help="exibe apenas estados open e open|filtered",
    )
    parser.add_argument(
        "--allow-large-scan",
        action="store_true",
        help=f"permite mais de {MAX_JOBS_WITHOUT_CONFIRMATION} sondagens",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="abre a interface gráfica em vez de executar no terminal",
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # A flag da interface gráfica é tratada antes do parser porque o argumento
    # posicional de alvos é obrigatório na linha de comando, mas na janela os
    # alvos são informados pelo usuário depois que a aplicação já está aberta.
    if "--gui" in argv:
        from redescan.gui import main as gui_main

        return gui_main()

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        _validate_options(args)
        targets = expand_targets(args.targets)
        ports = parse_ports(args.ports)
        protocols = _protocols(args.protocol)
    except ValueError as exc:
        parser.error(str(exc))

    job_count = len(targets) * len(ports) * len(protocols)
    if job_count > MAX_JOBS_WITHOUT_CONFIRMATION and not args.allow_large_scan:
        parser.error(
            f"a varredura geraria {job_count:,} sondagens; revise o escopo ou use "
            "--allow-large-scan se possuir autorização"
        )

    try:
        method = _resolve_method(args.method)
        scanner = Scanner(_create_prober(method, args.timeout, args.retries), args.workers)
        results = scanner.scan(targets, ports, protocols)
    except PermissionError:
        print(
            "erro: permissão insuficiente para enviar pacotes raw; execute com sudo "
            "ou conceda CAP_NET_RAW ao interpretador Python",
            file=sys.stderr,
        )
        return 2
    except RuntimeError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"erro de rede: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nvarredura interrompida pelo usuário", file=sys.stderr)
        return 130

    visible = _filter_results(results, args.only_active)
    if args.json:
        _print_json(visible)
    else:
        _print_table(visible, results, job_count, method)
    return 0

def _validate_options(args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        raise ValueError("timeout deve ser maior que zero")
    if args.retries < 0:
        raise ValueError("retries não pode ser negativo")
    if not 1 <= args.workers <= 1_000:
        raise ValueError("workers deve estar entre 1 e 1000")

def _protocols(value: str) -> list[Protocol]:
    if value == "both":
        return [Protocol.TCP, Protocol.UDP]
    return [Protocol(value)]

def _resolve_method(value: str) -> str:
    if value != "auto":
        return value
    return "connect" if platform.system() == "Windows" else "raw"

def _create_prober(method: str, timeout: float, retries: int):
    if method == "raw":
        return ScapyProber(timeout, retries)
    return SocketProber(timeout, retries)

def _filter_results(results: list[ScanResult], only_active: bool) -> list[ScanResult]:
    if not only_active:
        return results
    return [result for result in results if result.state.value in {"open", "open|filtered"}]

def _print_json(results: list[ScanResult]) -> None:
    data = []
    for result in results:
        item = asdict(result)
        item["protocol"] = result.protocol.value
        item["state"] = result.state.value
        data.append(item)
    print(json.dumps(data, indent=2, ensure_ascii=False))

def _print_table(
    visible: list[ScanResult],
    all_results: list[ScanResult],
    job_count: int,
    method: str,
) -> None:
    print(f"\nMétodo: {method}")
    print(f"\n{'ALVO':<15} {'PORTA':>5}  {'PROTOCOLO':<9} {'ESTADO':<14} MOTIVO")
    print("-" * 78)
    for result in visible:
        print(
            f"{result.target:<15} {result.port:>5}  {result.protocol.value:<9} "
            f"{result.state.value:<14} {result.reason}"
        )

    counts = Counter(result.state.value for result in all_results)
    summary = ", ".join(f"{state}: {count}" for state, count in sorted(counts.items()))
    noun = "sondagem" if job_count == 1 else "sondagens"
    print(f"\nConcluído: {job_count} {noun} ({summary}).")

if __name__ == "__main__":
    raise SystemExit(main())
