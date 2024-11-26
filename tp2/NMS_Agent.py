import socket
import psutil
import time
import platform
import threading
import json
import struct
import subprocess

# CONFIG:
HOST = '10.2.2.1'   # IP do SERVER
UDP_PORT = 24       # Porta UDP do SERVER
TCP_PORT = 64       # Porta TCP do SERVER

# Identificação única do agente
AGENT_ID = f"{platform.node()}"

# Variáveis globais
task = {}
alert_conditions = {}
alerts_sent = {"cpu_usage": False, "ram_usage": False, "latency": False}
sequence_number = 0
ack_received = threading.Event()
udp_lock = threading.Lock()

# SOCKETS:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.settimeout(5)

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Funções de codificação/decodificação
def encode_message(flags, seq, ack, payload):
    payload_bytes = payload.encode() if isinstance(payload, str) else b""
    length = len(payload_bytes)
    header = struct.pack("!BHHH", flags, seq, ack, length)
    return header + payload_bytes

def decode_message(message):
    header = message[:7]
    flags, seq, ack, length = struct.unpack("!BHHH", header)
    payload = message[7:7 + length]
    return flags, seq, ack, payload.decode() if payload else ""

# HANDSHAKE:
def udp_handshake():
    initial_seq = 1
    syn_message = encode_message(0b00, initial_seq, 0, AGENT_ID)
    retransmissions = 0
    max_retransmissions = 5
    timeout = 2  # Timeout em segundos

    while retransmissions < max_retransmissions:
        try:
            udp_socket.sendto(syn_message, (HOST, UDP_PORT))
            print(f"[HANDSHAKE] Enviado SYN (tentativa {retransmissions + 1})")

            udp_socket.settimeout(timeout)
            data, addr = udp_socket.recvfrom(1024)
            flags, seq, ack, payload = decode_message(data)
            print(f"[HANDSHAKE] Recebido: flags={flags}, seq={seq}, ack={ack}, payload={payload}")

            if flags == 0b01 and ack == initial_seq + 1:  # SYN-ACK
                print("[HANDSHAKE] Recebido SYN-ACK válido")

                # Enviar ACK final
                ack_message = encode_message(0b01, seq + 1, seq + 1, "")
                udp_socket.sendto(ack_message, (HOST, UDP_PORT))
                print(f"[HANDSHAKE] Enviado ACK")
                return True

        except socket.timeout:
            print("[HANDSHAKE] Timeout, retransmissão...")
            retransmissions += 1

    print("[HANDSHAKE] O Handshake falhou após o nr máximo de retransmissões.")
    return False

# Coleta e verificação de métricas
def collect_and_check_metrics():
    """Coleta métricas e verifica thresholds para alertas."""
    metric_data = {}
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})

    # CPU Usage
    if "cpu_usage" in device_metrics:
        cpu_usage = psutil.cpu_percent(interval=1)
        metric_data["cpu_usage"] = cpu_usage
        if "cpu_usage" in alert_conditions and cpu_usage > alert_conditions["cpu_usage"]:
            if not alerts_sent["cpu_usage"]:
                send_alert(f"CPU_USAGE excedido: {cpu_usage}%")
                alerts_sent["cpu_usage"] = True

    # RAM Usage
    if "ram_usage" in device_metrics:
        ram_usage = psutil.virtual_memory().percent
        metric_data["ram_usage"] = ram_usage
        if "ram_usage" in alert_conditions and ram_usage > alert_conditions["ram_usage"]:
            if not alerts_sent["ram_usage"]:
                send_alert(f"RAM_USAGE excedido: {ram_usage}%")
                alerts_sent["ram_usage"] = True

    # Latency
    if "latency" in link_metrics:
        latency = get_ping()
        metric_data["latency"] = latency
        if "latency" in alert_conditions and latency and latency > alert_conditions["latency"]:
            if not alerts_sent["latency"]:
                send_alert(f"LATENCY excedido: {latency} ms")
                alerts_sent["latency"] = True

    return metric_data

# Monitoramento de Alertas
def monitor_alerts():
    while True:
        if task:
            # Apenas coleta e verifica alertas
            collect_and_check_metrics()
        time.sleep(5)  # Frequência de monitoramento

# Envio de métricas periódicas
def send_metrics():
    global sequence_number
    frequency = task.get('frequency', 20)
    max_retransmissions = 5
    timeout = 5

    while True:
        if task:
            # Coleta as métricas atuais
            metric_data = collect_and_check_metrics()

            # Cria payload e envia métricas
            payload = json.dumps({
                "agent_id": AGENT_ID,
                "timestamp": time.time(),
                "metric_data": metric_data
            })

            attempts = 0
            ack_received.clear()

            while attempts < max_retransmissions and not ack_received.is_set():
                flags = 0b10 if attempts == 0 else 0b11
                message = encode_message(flags, sequence_number, 0, payload)

                with udp_lock:
                    udp_socket.sendto(message, (HOST, UDP_PORT))
                    print(f"[METRIC] Métricas enviadas (tentativa {attempts + 1}): {metric_data}")
                attempts += 1

                try:
                    udp_socket.settimeout(timeout)
                    data, addr = udp_socket.recvfrom(1024)
                    flags, seq, ack, _ = decode_message(data)
                    if flags == 0b01 and ack == sequence_number:
                        ack_received.set()
                        sequence_number += 1
                        print("[METRIC] ACK recebido do servidor")
                except socket.timeout:
                    print("[METRIC] Timeout ao esperar pelo ACK, retransmitindo...")

            if not ack_received.is_set():
                print("[METRIC] Falha no envio de métricas após máximo de retransmissões.")

            # Reset de alertas após envio periódico
            for key in alerts_sent:
                alerts_sent[key] = False

            time.sleep(frequency)
        else:
            time.sleep(1)

# Função para obter ping
def get_ping():
    try:
        result = subprocess.run(
            ["ping", "-c", "4", HOST],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        for line in result.stdout.split("\n"):
            if "min/avg/max" in line:
                avg_rtt = float(line.split("/")[4])  # RTT médio (ms)
                return avg_rtt
    except Exception as e:
        print(f"Erro ao obter ping: {e}")
    return None

# Envio de alertas
def send_alert(alert_message):
    try:
        tcp_socket.sendall(f"ALERT:{AGENT_ID}:{alert_message}".encode())
        print(f"[ALERT] Enviado: {alert_message}")
    except Exception as e:
        print(f"[ALERT] Erro ao enviar alerta: {e}")

# Conectar ao servidor via TCP
def tcp_connect():
    try:
        tcp_socket.connect((HOST, TCP_PORT))
        print("[TCP] Conectado ao servidor.")
    except Exception as e:
        print(f"[TCP] Erro ao conectar: {e}")

# Receber tarefa do servidor
def receive_task():
    global task, alert_conditions
    try:
        udp_socket.settimeout(10)
        data, addr = udp_socket.recvfrom(4096)
        _, _, _, payload = decode_message(data)
        task = json.loads(payload)
        alert_conditions = task.get('alertflow_conditions', {})
        print(f"[TASK] Tarefa recebida: {task}")
    except Exception as e:
        print(f"[TASK] Erro ao receber tarefa: {e}")
        task = {}
        alert_conditions = {}

# Programa principal
def start_agent():
    try:
        print(f"[AGENT] O meu ID é: {AGENT_ID}")

        if not udp_handshake():
            raise ConnectionError("[HANDSHAKE] Falha ao conectar com o servidor!")

        print("[HANDSHAKE] Conexão estabelecida com o servidor.")
        receive_task()
        tcp_connect()

        # Thread para envio periódico de métricas
        threading.Thread(target=send_metrics, daemon=True).start()

        # Thread para monitoramento de alertas
        threading.Thread(target=monitor_alerts, daemon=True).start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[AGENT] Agente interrompido manualmente.")
    finally:
        udp_socket.close()
        tcp_socket.close()

if __name__ == "__main__":
    start_agent()
