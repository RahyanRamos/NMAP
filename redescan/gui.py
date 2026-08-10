"""Interface gráfica do RedeScan construída com Tkinter.

A janela apenas coleta parâmetros, aciona o mesmo núcleo utilizado pela CLI
(parsing, probes e scanner) e apresenta os resultados. Nenhuma lógica de
varredura é reimplementada aqui.

A varredura roda em uma thread separada para não congelar a janela. Como o
Tkinter não é seguro para uso concorrente, os resultados produzidos pelas
threads do scanner são depositados em uma fila e consumidos pela thread
principal através de ``widget.after``.

Execução:
    python -m redescan.gui
"""
import csv
import ipaddress
import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from redescan.cli import (
    DEFAULT_PORTS,
    MAX_JOBS_WITHOUT_CONFIRMATION,
    _create_prober,
    _protocols,
    _resolve_method,
)
from redescan.models import PortState, ScanResult
from redescan.parsing import expand_targets, parse_ports
from redescan.scanner import Scanner

POLL_INTERVAL_MS = 100


def _estimate_hosts(alvos: list[str]) -> int:
    """Conta os endereços de uma lista de alvos sem expandi-los na memória."""
    total = 0
    for alvo in alvos:
        try:
            rede = ipaddress.ip_network(alvo, strict=False)
        except ValueError:
            total += 1  # entrada inválida: o parser oficial reportará o erro
            continue
        total += max(rede.num_addresses - (2 if rede.prefixlen < 31 else 0), 1)
    return total


STATE_COLORS = {
    PortState.OPEN.value: "#1d7a33",
    PortState.CLOSED.value: "#8a1f1f",
    PortState.FILTERED.value: "#8a6d1f",
    PortState.OPEN_OR_FILTERED.value: "#1f5f8a",
}


class CancellableProber:
    """Envolve um prober e interrompe as sondagens quando o evento é acionado.

    O motor de varredura não possui cancelamento nativo. Em vez de alterá-lo,
    este adaptador verifica um ``threading.Event`` antes de cada sondagem: se a
    parada foi solicitada, devolve o resultado imediatamente sem tocar na rede.
    """

    def __init__(self, prober, stop_event: threading.Event) -> None:
        self._prober = prober
        self._stop_event = stop_event

    def tcp(self, target: str, port: int) -> tuple[PortState, str]:
        if self._stop_event.is_set():
            return PortState.FILTERED, "cancelado pelo usuário"
        return self._prober.tcp(target, port)

    def udp(self, target: str, port: int) -> tuple[PortState, str]:
        if self._stop_event.is_set():
            return PortState.FILTERED, "cancelado pelo usuário"
        return self._prober.udp(target, port)


class RedeScanGUI:
    """Janela principal da aplicação."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RedeScan - varredura de portas TCP e UDP")
        self.root.minsize(880, 560)

        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.results: list[ScanResult] = []
        self.total_jobs = 0
        self.completed = 0

        self._build_widgets()
        self._poll_queue()

    # ------------------------------------------------------------------
    # Construção da interface
    # ------------------------------------------------------------------
    def _build_widgets(self) -> None:
        container = ttk.Frame(self.root, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        aviso = ttk.Label(
            container,
            text=(
                "Use somente em equipamentos e redes próprios ou com autorização "
                "expressa do responsável."
            ),
            foreground="#8a1f1f",
            wraplength=840,
        )
        aviso.pack(anchor=tk.W, pady=(0, 8))

        self._build_form(container)
        self._build_actions(container)
        self._build_table(container)
        self._build_status(container)

    def _build_form(self, parent: ttk.Frame) -> None:
        form = ttk.LabelFrame(parent, text="Parâmetros da varredura", padding=10)
        form.pack(fill=tk.X)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Alvos:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.var_targets = tk.StringVar(value="127.0.0.1")
        ttk.Entry(form, textvariable=self.var_targets).grid(
            row=0, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=3
        )
        ttk.Label(form, text="IPv4 ou CIDR, separados por espaço").grid(
            row=0, column=4, sticky=tk.W, padx=5
        )

        ttk.Label(form, text="Portas:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.var_ports = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(form, textvariable=self.var_ports).grid(
            row=1, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=3
        )
        ttk.Label(form, text="Ex.: 22,80,8000-8100").grid(
            row=1, column=4, sticky=tk.W, padx=5
        )

        ttk.Label(form, text="Protocolo:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.var_protocol = tk.StringVar(value="both")
        protos = ttk.Frame(form)
        protos.grid(row=2, column=1, sticky=tk.W, padx=5)
        for texto, valor in (("TCP", "tcp"), ("UDP", "udp"), ("Ambos", "both")):
            ttk.Radiobutton(
                protos, text=texto, value=valor, variable=self.var_protocol
            ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(form, text="Método:").grid(row=2, column=2, sticky=tk.E, pady=3)
        self.var_method = tk.StringVar(value="auto")
        ttk.Combobox(
            form,
            textvariable=self.var_method,
            values=("auto", "raw", "connect"),
            state="readonly",
            width=10,
        ).grid(row=2, column=3, sticky=tk.W, padx=5)

        avancado = ttk.Frame(form)
        avancado.grid(row=3, column=0, columnspan=5, sticky=tk.W, pady=(8, 0))

        ttk.Label(avancado, text="Timeout (s):").pack(side=tk.LEFT)
        self.var_timeout = tk.StringVar(value="1.0")
        ttk.Entry(avancado, textvariable=self.var_timeout, width=6).pack(
            side=tk.LEFT, padx=(4, 14)
        )

        ttk.Label(avancado, text="Tentativas:").pack(side=tk.LEFT)
        self.var_retries = tk.StringVar(value="1")
        ttk.Entry(avancado, textvariable=self.var_retries, width=6).pack(
            side=tk.LEFT, padx=(4, 14)
        )

        ttk.Label(avancado, text="Threads:").pack(side=tk.LEFT)
        self.var_workers = tk.StringVar(value="100")
        ttk.Entry(avancado, textvariable=self.var_workers, width=6).pack(
            side=tk.LEFT, padx=(4, 14)
        )

        self.var_only_active = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            avancado,
            text="Exibir apenas portas abertas",
            variable=self.var_only_active,
        ).pack(side=tk.LEFT)

    def _build_actions(self, parent: ttk.Frame) -> None:
        acoes = ttk.Frame(parent)
        acoes.pack(fill=tk.X, pady=8)

        self.btn_start = ttk.Button(acoes, text="Iniciar", command=self.start_scan)
        self.btn_start.pack(side=tk.LEFT)

        self.btn_stop = ttk.Button(
            acoes, text="Parar", command=self.stop_scan, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        ttk.Button(acoes, text="Limpar", command=self.clear_results).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(acoes, text="Exportar CSV", command=self.export_csv).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(acoes, text="Exportar JSON", command=self.export_json).pack(
            side=tk.LEFT, padx=5
        )

        self.progress = ttk.Progressbar(acoes, mode="determinate", length=220)
        self.progress.pack(side=tk.RIGHT)

    def _build_table(self, parent: ttk.Frame) -> None:
        moldura = ttk.Frame(parent)
        moldura.pack(fill=tk.BOTH, expand=True)

        colunas = ("alvo", "porta", "protocolo", "estado", "motivo")
        self.tree = ttk.Treeview(moldura, columns=colunas, show="headings")
        larguras = {
            "alvo": 130,
            "porta": 70,
            "protocolo": 90,
            "estado": 120,
            "motivo": 340,
        }
        for coluna in colunas:
            self.tree.heading(coluna, text=coluna.capitalize())
            self.tree.column(coluna, width=larguras[coluna], anchor=tk.W)

        barra = ttk.Scrollbar(moldura, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=barra.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        barra.pack(side=tk.RIGHT, fill=tk.Y)

        for estado, cor in STATE_COLORS.items():
            self.tree.tag_configure(estado, foreground=cor)

    def _build_status(self, parent: ttk.Frame) -> None:
        self.var_status = tk.StringVar(value="Pronto.")
        ttk.Label(parent, textvariable=self.var_status, anchor=tk.W).pack(
            fill=tk.X, pady=(6, 0)
        )

    # ------------------------------------------------------------------
    # Validação e disparo
    # ------------------------------------------------------------------
    def _read_options(self) -> dict:
        """Valida os campos da janela reutilizando os parsers do projeto."""
        alvos = self.var_targets.get().replace(",", " ").split()
        if not alvos:
            raise ValueError("informe ao menos um alvo")

        ports = parse_ports(self.var_ports.get())
        protocols = _protocols(self.var_protocol.get())

        # A expansão de CIDR materializa a lista inteira de endereços, o que
        # travaria a janela por minutos em faixas grandes como 10.0.0.0/8.
        # Por isso o tamanho é estimado antes de expandir de fato.
        estimativa = _estimate_hosts(alvos) * len(ports) * len(protocols)
        if estimativa > MAX_JOBS_WITHOUT_CONFIRMATION:
            raise ValueError(
                f"a varredura geraria cerca de {estimativa:,} sondagens; "
                "reduza o escopo"
            )

        targets = expand_targets(alvos)

        try:
            timeout = float(self.var_timeout.get().replace(",", "."))
            retries = int(self.var_retries.get())
            workers = int(self.var_workers.get())
        except ValueError as exc:
            raise ValueError("timeout, tentativas e threads devem ser números") from exc

        if timeout <= 0:
            raise ValueError("timeout deve ser maior que zero")
        if retries < 0:
            raise ValueError("tentativas não pode ser negativo")
        if not 1 <= workers <= 1000:
            raise ValueError("threads deve estar entre 1 e 1000")

        total = len(targets) * len(ports) * len(protocols)

        return {
            "targets": targets,
            "ports": ports,
            "protocols": protocols,
            "timeout": timeout,
            "retries": retries,
            "workers": workers,
            "method": _resolve_method(self.var_method.get()),
            "total": total,
        }

    def start_scan(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return

        try:
            opcoes = self._read_options()
        except ValueError as exc:
            messagebox.showerror("Parâmetros inválidos", str(exc))
            return

        self.clear_results()
        self.stop_event.clear()
        self.total_jobs = opcoes["total"]
        self.progress.configure(maximum=self.total_jobs, value=0)
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.var_status.set(
            f"Varrendo com método {opcoes['method']}: 0 de {self.total_jobs} sondagens."
        )

        self.worker = threading.Thread(
            target=self._run_scan, args=(opcoes,), daemon=True
        )
        self.worker.start()

    def stop_scan(self) -> None:
        if self.worker is None or not self.worker.is_alive():
            return
        self.stop_event.set()
        self.var_status.set("Cancelando as sondagens pendentes...")
        self.btn_stop.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Execução em segundo plano
    # ------------------------------------------------------------------
    def _run_scan(self, opcoes: dict) -> None:
        """Roda na thread de trabalho: nunca toca em widgets, apenas na fila."""
        try:
            prober = _create_prober(
                opcoes["method"], opcoes["timeout"], opcoes["retries"]
            )
            scanner = Scanner(
                CancellableProber(prober, self.stop_event), opcoes["workers"]
            )
            scanner.scan(
                opcoes["targets"],
                opcoes["ports"],
                opcoes["protocols"],
                on_result=lambda resultado: self.queue.put(("resultado", resultado)),
            )
            self.queue.put(("fim", None))
        except PermissionError:
            self.queue.put(
                (
                    "erro",
                    "Permissão insuficiente para pacotes raw. Execute com sudo ou "
                    "selecione o método connect.",
                )
            )
        except (RuntimeError, OSError) as exc:
            self.queue.put(("erro", str(exc)))

    def _poll_queue(self) -> None:
        """Roda na thread principal: consome a fila e atualiza a janela."""
        try:
            while True:
                tipo, carga = self.queue.get_nowait()
                if tipo == "resultado":
                    self._add_result(carga)
                elif tipo == "fim":
                    self._finish_scan()
                elif tipo == "erro":
                    self._finish_scan()
                    messagebox.showerror("Falha na varredura", carga)
        except queue.Empty:
            pass
        self.root.after(POLL_INTERVAL_MS, self._poll_queue)

    def _add_result(self, resultado: ScanResult) -> None:
        self.results.append(resultado)
        self.completed += 1
        self.progress.configure(value=self.completed)

        ativo = resultado.state in (PortState.OPEN, PortState.OPEN_OR_FILTERED)
        if not self.var_only_active.get() or ativo:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    resultado.target,
                    resultado.port,
                    resultado.protocol.value,
                    resultado.state.value,
                    resultado.reason,
                ),
                tags=(resultado.state.value,),
            )

        self.var_status.set(
            f"Varrendo: {self.completed} de {self.total_jobs} sondagens."
        )

    def _finish_scan(self) -> None:
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)

        contagem: dict[str, int] = {}
        for resultado in self.results:
            chave = resultado.state.value
            contagem[chave] = contagem.get(chave, 0) + 1
        resumo = ", ".join(f"{k}: {v}" for k, v in sorted(contagem.items()))

        rotulo = "cancelada" if self.stop_event.is_set() else "concluída"
        self.var_status.set(
            f"Varredura {rotulo}: {len(self.results)} sondagens ({resumo})."
        )

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def clear_results(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.completed = 0
        self.progress.configure(value=0)
        self.var_status.set("Pronto.")

    def export_csv(self) -> None:
        caminho = self._ask_path(".csv", [("Arquivo CSV", "*.csv")])
        if not caminho:
            return

        def escrever(arquivo) -> None:
            escritor = csv.writer(arquivo)
            escritor.writerow(["alvo", "porta", "protocolo", "estado", "motivo"])
            for r in self.results:
                escritor.writerow(
                    [r.target, r.port, r.protocol.value, r.state.value, r.reason]
                )

        self._salvar(caminho, escrever, newline="")

    def export_json(self) -> None:
        caminho = self._ask_path(".json", [("Arquivo JSON", "*.json")])
        if not caminho:
            return

        dados = [
            {
                "target": r.target,
                "port": r.port,
                "protocol": r.protocol.value,
                "state": r.state.value,
                "reason": r.reason,
            }
            for r in self.results
        ]
        self._salvar(caminho, lambda arquivo: json.dump(
            dados, arquivo, indent=2, ensure_ascii=False
        ))

    def _salvar(self, caminho: str, escritor, newline: str | None = None) -> None:
        """Grava o arquivo transformando falhas de disco em mensagem na tela.

        Sem este tratamento, uma pasta sem permissão de escrita faria a exceção
        estourar dentro do laço de eventos do Tkinter: o usuário não veria nem
        confirmação nem erro, apenas um botão que aparentemente não faz nada.
        """
        try:
            with open(caminho, "w", newline=newline, encoding="utf-8") as arquivo:
                escritor(arquivo)
        except OSError as exc:
            messagebox.showerror(
                "Falha ao exportar",
                f"Não foi possível gravar em {caminho}.\n\n{exc.strerror}.",
            )
            return
        messagebox.showinfo("Exportação", f"Resultados salvos em {caminho}")

    def _ask_path(self, extensao: str, tipos: list) -> str:
        if not self.results:
            messagebox.showwarning("Exportação", "Não há resultados para exportar.")
            return ""
        return filedialog.asksaveasfilename(
            defaultextension=extensao,
            filetypes=tipos,
            initialdir=str(Path.home()),
        )


def main() -> int:
    root = tk.Tk()
    RedeScanGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
