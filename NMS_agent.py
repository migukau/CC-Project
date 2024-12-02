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

def encode_message(flags, seq, ack, payload):
    payload_bytes = payload.encode() if isinstance(payload, str) else b""
    length = len(payload_bytes)
    
    # Header com bitwise shifts
    header = (flags << 48) | (seq << 32) | (ack << 16) | length
    header_bytes = header.to_bytes(7, 'big')  # 7 bytes: 1 byte flags + 2 seq + 2 ack + 2 length

    return header_bytes + payload_bytes


def decode_message(message):
    header = int.from_bytes(message[:7], 'big')
    
    # Extração dos campos com bitwise shifts
    flags = (header >> 48) & 0xFF
    seq = (header >> 32) & 0xFFFF
    ack = (header >> 16) & 0xFFFF
    length = header & 0xFFFF

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
# Lista global de métricas
metric_list = []

# Função para coletar e verificar métricas
def collect_and_check_metrics():
    global metric_list  # Usar a lista global

    metric_data = {}
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})

    # CPU Usage
    if "cpu_usage" in device_metrics:
        cpu_usage = psutil.cpu_percent(interval=1)
        metric_data["cpu_usage"] = cpu_usage
        metric_list.append({"cpu_usage": cpu_usage})  # Adiciona à lista de métricas
        if "cpu_usage" in alert_conditions and cpu_usage > alert_conditions["cpu_usage"]:
            if not alerts_sent["cpu_usage"]:
                send_alert("cpu_usage", cpu_usage)
                alerts_sent["cpu_usage"] = True
        elif "cpu_usage" in alert_conditions and cpu_usage < alert_conditions["cpu_usage"]:
            alerts_sent["cpu_usage"] = False

    # RAM Usage
    if "ram_usage" in device_metrics:
        ram_usage = psutil.virtual_memory().percent
        metric_data["ram_usage"] = ram_usage
        metric_list.append({"ram_usage": ram_usage})  # Adiciona à lista de métricas
        if "ram_usage" in alert_conditions and ram_usage > alert_conditions["ram_usage"]:
            if not alerts_sent["ram_usage"]:
                send_alert("ram_usage", ram_usage)
                alerts_sent["ram_usage"] = True
        elif "ram_usage" in alert_conditions and ram_usage < alert_conditions["ram_usage"]:
            alerts_sent["ram_usage"] = False

    # Latency
    if "latency" in link_metrics:
        latency = get_ping()
        metric_data["latency"] = latency
        metric_list.append({"latency": latency})  # Adiciona à lista de métricas
        if "latency" in alert_conditions and latency and latency > alert_conditions["latency"]:
            if not alerts_sent["latency"]:
                send_alert("latency", latency)
                alerts_sent["latency"] = True
        elif "latency" in alert_conditions and latency and latency < alert_conditions["latency"]:
            alerts_sent["latency"] = False

    return metric_data

# Função que calcula a média das métricas
def mean_metrics():
    global metric_list  # Usar a lista global

    # Dicionário para armazenar as somas das métricas
    summed_metrics = {"cpu_usage": 0, "ram_usage": 0, "latency": 0}
    count = 0

    # Calcular a soma das métricas
    for metrics in metric_list:
        for key, value in metrics.items():
            if key in summed_metrics:
                summed_metrics[key] += value
        count += 1

    # Calcular a média das métricas
    if count > 0:
        mean_data = {key: summed_metrics[key] / count for key in summed_metrics}
    else:
        mean_data = {}

    metric_list.clear()
    return mean_data

# Função para monitorar alertas
def monitor_alerts():
    while True:
        if task:
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
            # Média das métricas dos ultimos n segundos passados
            metric_data = mean_metrics()

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
def send_alert(alert_type, value):
    global sequence_number
    max_retransmissions = 5
    retransmissions = 0
    ack_received = False
    alert_timestamp = int(time.time())

    # Escolher a flag baseada no tipo de alerta
    if alert_type == "cpu_usage":
        flags = 0x01  # CPU
    elif alert_type == "ram_usage":
        flags = 0x02  # RAM
    elif alert_type == "latency":
        flags = 0x03  # Latência
    else:
        print("[ALERT] Tipo de alerta desconhecido.")
        return

    # Payload: agent_id + valor da métrica + timestamp
    payload = f"{AGENT_ID}:{value}:{alert_timestamp}"

    while retransmissions < max_retransmissions and not ack_received:
        try:
            # Codificar mensagem
            message = encode_message(flags, sequence_number, 0, payload)
            tcp_socket.sendall(message)
            print(f"[ALERT] Enviado (tentativa {retransmissions + 1}): {alert_type} = {value} do Agente {AGENT_ID}")

            # Aguardar ACK
            tcp_socket.settimeout(5)
            data = tcp_socket.recv(4096)
            ack_flags, seq_recv, _, _ = decode_message(data)

            if ack_flags == 0x01 and seq_recv == sequence_number:  # Verifica ACK
                ack_received = True
                print("[ALERT] ACK recebido.")
        except socket.timeout:
            print("[ALERT] Timeout, retransmitindo alerta...")
            retransmissions += 1
        except Exception as e:
            print(f"[ALERT] Erro ao enviar alerta: {e}")
            retransmissions += 1

    if not ack_received:
        print("[ALERT] Falha ao enviar alerta após múltiplas tentativas.")
    else:
        sequence_number += 1  # Incrementar número de sequência para o próximo envio.


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
