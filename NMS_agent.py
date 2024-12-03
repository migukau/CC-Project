import socket
import psutil
import time
import platform
import threading
import json
import struct
import subprocess

# CONFIG:
HOST = '10.0.3.10'   # IP do SERVER
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
metric_list_lock = threading.Lock()

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
# Function to only collect metrics for reporting
def collect_metrics(store=True):
    global metric_list

    global metric_data
    metric_data = {}
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})

    # Collect CPU Usage
    if "cpu_usage" in device_metrics:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        metric_data["cpu_usage"] = cpu_usage
        if store:
            metric_list.append({"cpu_usage": cpu_usage})

    # Collect RAM Usage
    if "ram_usage" in device_metrics:
        ram_usage = psutil.virtual_memory().percent
        metric_data["ram_usage"] = ram_usage
        if store:
            metric_list.append({"ram_usage": ram_usage})

    # Collect Latency
    if "latency" in link_metrics:
        ping_target = task.get('ping_target', HOST)
        latency = get_ping(ping_target)
        metric_data["latency"] = latency
        if store:
            metric_list.append({"latency": latency})

    return metric_data


def check_for_alerts():
    global alerts_sent

    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})
    
    # CPU Usage
    if "cpu_usage" in device_metrics and device_metrics["cpu_usage"]:
        if "cpu_usage" in alert_conditions and "cpu_usage" in metric_data and metric_data["cpu_usage"] > alert_conditions["cpu_usage"]:
            if not alerts_sent["cpu_usage"]:
                send_alert("cpu_usage", metric_data["cpu_usage"])

    # RAM Usage
    if "ram_usage" in device_metrics:
        if "ram_usage" in alert_conditions and "ram_usage" in device_metrics and device_metrics["ram_usage"] > alert_conditions["ram_usage"]:
            if not alerts_sent["ram_usage"]:
                send_alert("ram_usage", device_metrics["ram_usage"])

    # Latency (Ping to another agent)
    if "latency" in link_metrics:
        ping_target = task.get('ping_target', HOST)  # Default ping target to server if not set
        if  "latency" in alert_conditions and "latency" in metric_data and metric_data["latency"] > alert_conditions["latency"]:
            if not alerts_sent["latency"]:
                send_alert("latency", metric_data["latency"])
 


# Função que calcula a média das métricas
def mean_metrics():
    global metric_list  # Usar a lista global

    if not metric_list:
        return []

    # Dicionário para armazenar as somas das métricas e contagem dos valores válidos
    summed_metrics = {"cpu_usage": 0, "ram_usage": 0, "latency": 0}
    count = {"cpu_usage": 0, "ram_usage": 0, "latency": 0}

    # Calcular a soma das métricas
    for metrics in metric_list:
        for key, value in metrics.items():
            if key in summed_metrics:
                # Se o valor da métrica for negativo, atribuímos -1
                if value < 0:
                    summed_metrics[key] = -1
                    count[key] = 1  # Para garantir que será marcado como -1
                else:
                    summed_metrics[key] += value
                    count[key] += 1

    # Calcular a média das métricas, considerando que métricas negativas resultam em -1
    mean_data = {}
    for key in summed_metrics:
        if count[key] > 0:
            # Se houver métricas válidas para a chave, calcular a média
            mean_data[key] = summed_metrics[key] / count[key] if summed_metrics[key] != -1 else -1
        else:
            # Se não houver métricas válidas, definimos como -1
            mean_data[key] = -1

    # Limpar a lista de métricas após o cálculo da média
    metric_list.clear()

    print(f'{metric_list}')
    return mean_data

# Função para monitorar alertas
def monitor_alerts():
    while True:
        if task:
            check_for_alerts()
        time.sleep(5)  




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
            # /!\ 
            if not metric_data:
                metric_data = collect_metrics(False)

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
                    if flags == 0b01 and ack == sequence_number and seq == sequence_number + 1:
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
def get_ping(target_ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "4", target_ip],
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
        ping_target = task.get('ping_target')
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
        
        threading.Thread(target=collect_metrics, daemon=True).start()
        time.sleep(0.1)
        
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
