# RedeScan

Ferramenta educacional em Python para varredura de portas IPv4 em **Linux e Windows**. Aceita um ou mais endereços IP, redes CIDR e intervalos de portas, executando sondagens TCP e UDP de forma concorrente.

> Use somente em equipamentos e redes próprios ou para os quais você tenha autorização expressa. Uma varredura sem permissão pode violar políticas e leis aplicáveis.

## Métodos de varredura

A opção `--method` disponibiliza três modos:

| Método | Comportamento | Privilégios |
|---|---|---|
| `auto` | Usa `raw` no Linux e `connect` no Windows | Depende do sistema |
| `raw` | Pacotes TCP SYN e UDP construídos com Scapy | `sudo`/`CAP_NET_RAW` no Linux; Npcap e terminal elevado no Windows |
| `connect` | Usa sockets TCP/UDP do sistema operacional | Usuário comum |

### TCP no modo raw

O scanner envia um pacote com a flag `SYN`, sem abrir uma conexão TCP completa:

- `SYN-ACK`: porta `open`, seguida de um `RST` para encerrar a tentativa;
- `RST`: porta `closed`;
- resposta ICMP de bloqueio ou ausência de resposta: porta `filtered`.

### TCP no modo connect

O sistema operacional tenta realizar uma conexão TCP normal:

- conexão aceita: porta `open`;
- conexão recusada: porta `closed`;
- timeout ou erro de acesso/rota: porta `filtered`.

Esse modo completa o handshake TCP quando a porta está aberta. Ele é menos discreto que o SYN raw, mas funciona no Windows sem drivers extras ou permissão de administrador.

### UDP

Nos dois métodos é enviado um datagrama UDP vazio:

- resposta UDP: porta `open`;
- ICMP *port unreachable*: porta `closed`;
- outro erro de destino ou acesso: porta `filtered`;
- ausência de resposta: `open|filtered`.

O estado `open|filtered` é uma limitação natural da varredura UDP: muitos serviços UDP só respondem a mensagens específicas, enquanto firewalls podem descartar o pacote silenciosamente.

## Requisitos

- Python 3.10 ou superior;
- Linux ou Windows;
- Scapy 2.5 ou superior somente para o modo `raw`.

O modo `connect` utiliza apenas a biblioteca padrão do Python.

## Executar no Windows

Abra o PowerShell na pasta do projeto e confira se o Python está instalado:

```powershell
python --version
```

Em algumas instalações do Windows também existe o launcher `py`, mas ele não é obrigatório. Os comandos abaixo usam diretamente `python` para funcionar mesmo quando o launcher não está instalado. A opção `-3` pertence exclusivamente ao comando `py` e não deve ser passada para `python`.

O modo padrão no Windows é `connect` e utiliza somente a biblioteca padrão. Portanto, é possível executar imediatamente, sem instalar pacotes ou criar ambiente virtual:

```powershell
python -m redescan 127.0.0.1 -p 80,443 -P tcp
python -m redescan 192.168.1.1 -p 22,53,80,443 -P both
```

### Ambiente virtual opcional

O ambiente virtual é recomendado para instalar dependências do modo raw, mas não é necessário para o modo `connect`:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Se a criação for interrompida durante a etapa `ensurepip`, o ambiente pode ficar sem `pip`. Deixe o primeiro comando terminar ou complete o ambiente parcial com:

```powershell
.\.venv\Scripts\python.exe -m ensurepip --upgrade
```

Para instalar o comando `redescan` no ambiente virtual:

```powershell
python -m pip install -e .
redescan 192.168.1.1 -p 1-1024 -P tcp
```

### SYN raw opcional no Windows

O modo raw também pode ser usado no Windows, mas requer:

1. instalar o driver Npcap com suporte compatível com WinPcap;
2. instalar o Scapy com `python -m pip install -r requirements.txt`;
3. abrir o PowerShell como administrador;
4. executar com `--method raw`.

```powershell
python -m redescan 192.168.1.1 -p 22,80,443 -P tcp --method raw
```

Para validar o envio de SYN raw de forma controlada, abra dois PowerShells. No primeiro, inicie um servidor HTTP local:

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

No segundo, aberto como administrador, escaneie a porta `8000`:

```powershell
python -m redescan 127.0.0.1 -p 8000 -P tcp --method raw -t 2 -r 1
```

Com o servidor ativo, o resultado esperado é `open`, com o motivo `SYN-ACK recebido`.

Se o Npcap não capturar corretamente o tráfego de loopback, descubra o IPv4 do computador:

```powershell
ipconfig
```

Inicie o servidor em todas as interfaces e substitua `SEU_IPV4` pelo endereço encontrado:

```powershell
# PowerShell 1
python -m http.server 8000 --bind 0.0.0.0

# PowerShell 2, executado como administrador
python -m redescan SEU_IPV4 -p 8000 -P tcp --method raw -t 2 -r 1
```

## Instalação no Linux

No Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

O modo `auto` seleciona SYN raw no Linux:

```bash
sudo .venv/bin/python -m redescan 192.168.1.10 -p 22,53,80,443 -P both
```

Para executar sem `sudo`, selecione sockets explicitamente:

```bash
python -m redescan 192.168.1.10 -p 22,53,80,443 -P both --method connect
```

## Exemplos de uso

Sem `--ports`, são verificadas portas comuns. Sem `--protocol`, TCP e UDP são verificados.

```powershell
# Portas específicas em um host, somente TCP
python -m redescan 192.168.1.10 -p 22,80,443 -P tcp

# Intervalo de portas TCP e UDP
python -m redescan 192.168.1.10 -p 1-1024 -P both

# Mais de um IP
python -m redescan 192.168.1.10 192.168.1.20 -p 53,80 -P both

# Todos os hosts utilizáveis de uma sub-rede /24, somente UDP
python -m redescan 192.168.1.0/24 -p 53,67,68,123,161 -P udp

# Mostrar apenas portas abertas ou possivelmente abertas
python -m redescan 192.168.1.10 -p 1-1024 --only-active

# Resultado estruturado para processamento por outra ferramenta
python -m redescan 192.168.1.10 -p 22,53,80 --json
```

Use `python -m redescan --help` para consultar todas as opções:

| Opção | Função |
|---|---|
| `ALVO [ALVO ...]` | Um ou mais IPv4 ou blocos CIDR |
| `-p`, `--ports` | Lista e/ou intervalos, como `22,80,8000-8100` |
| `-P`, `--protocol` | `tcp`, `udp` ou `both` |
| `-m`, `--method` | `auto`, `raw` ou `connect` |
| `-t`, `--timeout` | Segundos de espera por tentativa (padrão: `1.0`) |
| `-r`, `--retries` | Repetições após timeout (padrão: `1`) |
| `-w`, `--workers` | Sondagens concorrentes (padrão: `100`) |
| `--only-active` | Omite portas fechadas e filtradas |
| `--json` | Emite JSON em vez da tabela |
| `--allow-large-scan` | Libera explicitamente mais de 65.536 sondagens |

## Exemplo de saída no Windows

```text
Método: connect

ALVO            PORTA  PROTOCOLO ESTADO         MOTIVO
------------------------------------------------------------------------------
192.168.1.10       22  tcp       open           conexão TCP aceita
192.168.1.10       80  tcp       closed         conexão recusada (código 10061)
192.168.1.10       53  udp       open            resposta UDP recebida
192.168.1.10      161  udp       open|filtered   sem resposta

Concluído: 4 sondagens (closed: 1, open: 2, open|filtered: 1).
```

## Testes

Os testes unitários não enviam pacotes para a rede. Eles validam os parsers, o motor e a seleção automática do método:

```powershell
python -m unittest discover -v
```

Para um teste funcional seguro no próprio Windows, inicie temporariamente um servidor HTTP local:

```powershell
# Terminal 1
python -m http.server 8000 --bind 127.0.0.1

# Terminal 2
python -m redescan 127.0.0.1 -p 7999-8001 -P tcp
```

A porta `8000` deve aparecer como `open`; as portas vizinhas aparecerão como `closed` ou `filtered`, conforme as regras do Firewall do Windows.

## Estrutura

```text
redescan/
├── __main__.py   # entrada para python -m redescan
├── cli.py        # argumentos, método automático e apresentação
├── models.py     # protocolos, estados e resultados
├── parsing.py    # validação de portas, IPs e CIDRs
├── probes.py     # sondagens Scapy raw e sockets multiplataforma
└── scanner.py    # concorrência e coordenação da varredura
tests/            # testes unitários sem tráfego de rede
```

## Limitações conhecidas

- somente IPv4;
- o modo TCP `connect` completa a conexão quando encontra uma porta aberta;
- sondas UDP usam payload vazio e podem não provocar resposta do serviço;
- firewalls, latência, perda de pacotes e limitação de ICMP afetam os resultados;
- a ferramenta não identifica versões de serviços nem sistemas operacionais;
- mais de 65.536 sondagens exigem `--allow-large-scan`.


----------------------------------------------------------------------

## Interface gráfica

Além da linha de comando, o RedeScan possui uma interface gráfica construída
com Tkinter (biblioteca padrão do Python), sem dependências adicionais.

### Execução

```bash
python -m redescan --gui
# ou, equivalente:
python -m redescan.gui
```

No Linux, o Tkinter costuma vir em um pacote separado:

```bash
sudo apt install python3-tk
```

Para o método `raw` (SYN scan), a janela precisa ser aberta com privilégios:

```bash
sudo .venv/bin/python -m redescan.gui
```

### Recursos

- Resultados exibidos em tempo real, coloridos por estado
- Barra de progresso e contagem de sondagens concluídas
- Cancelamento de varredura em andamento
- Filtro para exibir apenas portas abertas
- Exportação dos resultados em CSV e JSON
- Bloqueio de escopos excessivos antes de iniciar a varredura

### Arquitetura

A janela não reimplementa nenhuma lógica de varredura: ela reutiliza
`parsing`, `probes` e `scanner`, exatamente como a CLI faz.

A varredura roda em uma thread separada para não bloquear o laço de eventos
do Tkinter. Como o `scanner` executa sondagens em paralelo e o Tkinter não é
seguro para uso concorrente, os resultados são depositados em uma
`queue.Queue` pelas threads de trabalho e consumidos pela thread principal a
cada 100 ms via `widget.after`. Nenhum widget é acessado fora da thread
principal.

O cancelamento é implementado pela classe `CancellableProber`, que envolve o
prober original e verifica um `threading.Event` antes de cada sondagem. Isso
adiciona a funcionalidade sem alterar o motor de varredura.

