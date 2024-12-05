import socket
import psutil
import time
import platform
import threading
import json
import struct
import subprocess
import sys

# CONFIG:
UDP_PORT = 24       # Porta UDP do SERVER
TCP_PORT = 64       # Porta TCP do SERVER

# Identificação única do agente
AGENT_ID = f"{platform.node()}"

# Variáveis globais
task = {}
alert_conditions = {}
alerts_sent = {"cpu_usage": False, "ram_usage": False, "latency": False}

# Apenas um contador de sequência para métricas (UDP) agora
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
    header = (flags << 48) | (seq << 32) | (ack << 16) | length
    header_bytes = header.to_bytes(7, 'big')
    return header_bytes + payload_bytes

def decode_message(message):
    header = int.from_bytes(message[:7], 'big')
    flags = (header >> 48) & 0xFF
    seq = (header >> 32) & 0xFFFF
    ack = (header >> 16) & 0xFFFF
    length = header & 0xFFFF
    payload = message[7:7 + length]
    return flags, seq, ack, payload.decode() if payload else ""

# HANDSHAKE:
def udp_handshake():
    initial_seq = 0
    syn_message = encode_message(0b00, initial_seq, 0, AGENT_ID)
    retransmissions = 0
    max_retransmissions = 5
    timeout = 2

    while retransmissions < max_retransmissions:
        try:
            udp_socket.sendto(syn_message, (HOST, UDP_PORT))
            print(f"[HANDSHAKE] Enviado SYN (tentativa {retransmissions + 1})")

            udp_socket.settimeout(timeout)
            data, addr = udp_socket.recvfrom(1024)
            flags, seq, ack, payload = decode_message(data)
            print(f"[HANDSHAKE] Recebido: flags={flags}, seq={seq}, ack={ack}, payload={payload}")

            # Espera-se SYN-ACK com ack = initial_seq + 1
            if flags == 0b01 and ack == initial_seq + 1:
                print("[HANDSHAKE] Recebido SYN-ACK válido")

                # Enviar ACK final
                ack_message = encode_message(0b01, seq + 1, seq + 1, "")
                udp_socket.sendto(ack_message, (HOST, UDP_PORT))
                print("[HANDSHAKE] Enviado ACK final")
                return True

        except socket.timeout:
            print("[HANDSHAKE] Timeout, retransmissão do SYN...")
            retransmissions += 1

    print("[HANDSHAKE] O Handshake falhou após o número máximo de retransmissões.")
    return False

# Lista global de métricas
metric_list = []

def collect_metrics(store=True):
    global metric_data
    metric_data = {}
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})

    if "cpu_usage" in device_metrics:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        metric_data["cpu_usage"] = cpu_usage
        if store:
            metric_list.append({"cpu_usage": cpu_usage})

    if "ram_usage" in device_metrics:
        ram_usage = psutil.virtual_memory().percent
        metric_data["ram_usage"] = ram_usage
        if store:
            metric_list.append({"ram_usage": ram_usage})

    if "latency" in link_metrics:
        ping_target = task.get('ping_target', HOST)
        latency = get_ping(ping_target)
        metric_data["latency"] = latency if latency is not None else -1
        if store:
            metric_list.append({"latency": metric_data["latency"]})

    return metric_data

def check_for_alerts():
    global alerts_sent
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})
    
    # CPU Usage
    if "cpu_usage" in device_metrics and "cpu_usage" in alert_conditions and "cpu_usage" in metric_data:
        if metric_data["cpu_usage"] > alert_conditions["cpu_usage"]:
            if not alerts_sent["cpu_usage"]:
                send_alert("cpu_usage", metric_data["cpu_usage"])
                alerts_sent["cpu_usage"] = True

    # RAM Usage
    if "ram_usage" in device_metrics and "ram_usage" in alert_conditions and "ram_usage" in metric_data:
        if metric_data["ram_usage"] > alert_conditions["ram_usage"]:
            if not alerts_sent["ram_usage"]:
                send_alert("ram_usage", metric_data["ram_usage"])
                alerts_sent["ram_usage"] = True

    # Latência
    if "latency" in link_metrics and "latency" in alert_conditions and "latency" in metric_data:
        if metric_data["latency"] > alert_conditions["latency"]:
            if not alerts_sent["latency"]:
                send_alert("latency", metric_data["latency"])
                alerts_sent["latency"] = True

def mean_metrics():
    global metric_list

    if not metric_list:
        return {}

    summed_metrics = {"cpu_usage": 0, "ram_usage": 0, "latency": 0}
    count = {"cpu_usage": 0, "ram_usage": 0, "latency": 0}

    for metrics in metric_list:
        for key, value in metrics.items():
            if key in summed_metrics:
                if value < 0:
                    summed_metrics[key] = -1
                    count[key] = 1
                else:
                    if summed_metrics[key] != -1:
                        summed_metrics[key] += value
                        count[key] += 1

    mean_data = {}
    for key in summed_metrics:
        if count[key] > 0:
            mean_data[key] = summed_metrics[key] / count[key] if summed_metrics[key] != -1 else -1
        else:
            mean_data[key] = -1

    metric_list.clear()
    return mean_data

def monitor_alerts():
    while True:
        if task:
            check_for_alerts()
        time.sleep(5)

def send_metrics():
    global sequence_number
    frequency = task.get('frequency', 20)
    max_retransmissions = 5
    timeout = 5

    while True:
        if task:
            metric_data_avg = mean_metrics()
            if not metric_data_avg:
                metric_data_avg = collect_metrics(False)

            payload = json.dumps({
                "agent_id": AGENT_ID,
                "timestamp": time.time(),
                "metric_data": metric_data_avg
            })

            attempts = 0
            ack_received.clear()

            while attempts < max_retransmissions and not ack_received.is_set():
                flags = 0b10 if attempts == 0 else 0b11
                message = encode_message(flags, sequence_number, 0, payload)

                with udp_lock:
                    udp_socket.sendto(message, (HOST, UDP_PORT))
                    print(f"[METRIC] Métricas enviadas (tentativa {attempts + 1}): {metric_data_avg}")
                attempts += 1

                try:
                    udp_socket.settimeout(timeout)
                    data, addr = udp_socket.recvfrom(1024)
                    flags_r, seq_r, ack_r, _ = decode_message(data)
                    if flags_r == 0b01 and ack_r == sequence_number and seq_r == sequence_number + 1:
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
                avg_rtt = float(line.split("/")[4])
                return avg_rtt
    except Exception as e:
        print(f"Erro ao obter ping: {e}")
    return -1

def send_alert(alert_type, value):
    # Agora não há controle de sequência para TCP. Seq será sempre 0 no envio.
    alert_timestamp = int(time.time())

    if alert_type == "cpu_usage":
        flags = 0x01
    elif alert_type == "ram_usage":
        flags = 0x02
    elif alert_type == "latency":
        flags = 0x03
    else:
        print("[ALERT] Tipo de alerta desconhecido.")
        return

    payload = f"{AGENT_ID}:{value}:{alert_timestamp}"

    try:
        # Envia alerta sem sequência, seq=0
        message = encode_message(flags, 0, 0, payload)
        tcp_socket.sendall(message)
        print(f"[ALERT] Alerta enviado: {alert_type} = {value}")

        tcp_socket.settimeout(5)
        data = tcp_socket.recv(4096)
        ack_flags, _, _, _ = decode_message(data)

        # Verificar se recebemos um ACK (flags 0x01) - número de sequência não é mais verificado
        if ack_flags == 0x01:
            print("[ALERT] ACK recebido do servidor.")
        else:
            print("[ALERT] ACK não correspondeu ao esperado (sem controle de sequência).")

    except socket.timeout:
        print("[ALERT] Timeout ao aguardar ACK do alerta.")
    except Exception as e:
        print(f"[ALERT] Erro ao enviar alerta: {e}")

def tcp_connect():
    try:
        tcp_socket.connect((HOST, TCP_PORT))
        print("[TCP] Conectado ao servidor.")
    except Exception as e:
        print(f"[TCP] Erro ao conectar: {e}")

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

def start_agent():
    global sequence_number
    try:
        print(f"[AGENT] Meu ID: {AGENT_ID}")

        if not udp_handshake():
            raise ConnectionError("[HANDSHAKE] Falha ao conectar com o servidor!")

        print("[HANDSHAKE] Conexão estabelecida com o servidor.")
        # Após o handshake bem sucedido, seq para métricas em 0
        sequence_number = 0

        receive_task()
        tcp_connect()
        
        # Thread para envio periódico de métricas
        threading.Thread(target=send_metrics, daemon=True).start()

        # Thread para monitorar alertas
        threading.Thread(target=monitor_alerts, daemon=True).start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[AGENT] Agente interrompido manualmente.")
    finally:
        udp_socket.close()
        tcp_socket.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("É necessário o IP do servidor: python3 NMS_agent.py <IP_DO_SERVIDOR>")
        sys.exit(1)

    HOST = sys.argv[1]  # IP do servidor
    start_agent()
