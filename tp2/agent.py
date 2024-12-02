import socket
import psutil
import time
import platform
import subprocess
import threading
import json

# CONFIG:
HOST = '10.0.3.10'   # IP do SERVER
UDP_PORT = 24       # Porta UDP do SERVER
TCP_PORT = 64       # Porta TCP do SERVER

# Identificação única do agente
AGENT_ID = f"{platform.node()}"

# Variáveis globais
task = {}
alert_conditions = {}
sequence_number = 0
ack_received = threading.Event()
udp_lock = threading.Lock()

# SOCKETS:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.settimeout(5)

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# HANDSHAKE:
def udp_handshake():
    initial_seq = 1
    syn_message = f"SEQ:{initial_seq}|ACK:0|FLAGS:SYN|AGENT_ID:{AGENT_ID}"
    retransmissions = 0
    max_retransmissions = 5
    timeout = 2  # Timeout em segundos

    while retransmissions < max_retransmissions:
        try:
            udp_socket.sendto(syn_message.encode(), (HOST, UDP_PORT))
            print(f"[HANDSHAKE] Enviado SYN (tentativa {retransmissions + 1}): {syn_message}")

            udp_socket.settimeout(timeout)
            data, addr = udp_socket.recvfrom(1024)
            message = data.decode()
            print(f"[HANDSHAKE] Recebido: {message}")

            if "FLAGS:SYN-ACK" in message:
                # Parse SYN-ACK
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                if int(parts["ACK"]) == initial_seq + 1:
                    server_seq = int(parts["SEQ"])
                    print("[HANDSHAKE] Recebido SYN-ACK válido")

                    # Enviar ACK final
                    ack_message = f"SEQ:{server_seq + 1}|ACK:{server_seq + 1}|FLAGS:ACK|AGENT_ID:{AGENT_ID}"
                    udp_socket.sendto(ack_message.encode(), (HOST, UDP_PORT))
                    print(f"[HANDSHAKE] Enviado ACK: {ack_message}")
                    return True

        except socket.timeout:
            print("[HANDSHAKE] Timeout, retransmitindo...")
            retransmissions += 1

    print("[HANDSHAKE] Handshake falhou após máximo de retransmissões.")
    return False

# Receber tarefa do servidor
def receive_task():
    global task, alert_conditions
    try:
        udp_socket.settimeout(10)
        data, addr = udp_socket.recvfrom(4096)
        message = data.decode()
        print(f"[TASK] Tarefa recebida: {message}")
        task = json.loads(message)
        alert_conditions = task.get('alertflow_conditions', {})
    except Exception as e:
        print(f"[TASK] Erro ao receber tarefa: {e}")
        task = {}
        alert_conditions = {}

# Coleta de métricas conforme a tarefa
def collect_metrics():
    metric_data = {}
    device_metrics = task.get('device_metrics', {})
    link_metrics = task.get('link_metrics', {})

    if device_metrics.get('cpu_usage'):
        cpu_usage = psutil.cpu_percent(interval=1)
        metric_data['cpu_usage'] = cpu_usage
        # Verificar condições de alerta
        cpu_threshold = alert_conditions.get('cpu_usage')
        if cpu_threshold and cpu_usage > cpu_threshold:
            send_alert(f"CPU_USAGE excedido: {cpu_usage}%")

    if device_metrics.get('ram_usage'):
        ram_usage = psutil.virtual_memory().percent
        metric_data['ram_usage'] = ram_usage
        # Verificar condições de alerta
        ram_threshold = alert_conditions.get('ram_usage')
        if ram_threshold and ram_usage > ram_threshold:
            send_alert(f"RAM_USAGE excedido: {ram_usage}%")

    if link_metrics.get('latency'):
        ping_value = get_ping()
        metric_data['latency'] = ping_value
        # Verificar condições de alerta
        latency_threshold = alert_conditions.get('latency')
        if latency_threshold and ping_value > latency_threshold:
            send_alert(f"LATENCY excedido: {ping_value} ms")

    # Outras métricas podem ser adicionadas aqui

    return metric_data

# Envio de métricas para o servidor com sequência e ACKs
def send_metrics():
    global sequence_number
    frequency = task.get('frequency', 20)
    max_retransmissions = 5
    timeout = 5  # Timeout para ACK

    while True:
        if task:
            metric_data = collect_metrics()
            metric_message = {
                'sequence_number': sequence_number,
                'agent_id': AGENT_ID,
                'timestamp': time.time(),
                'metric_data': metric_data
            }
            message = json.dumps(metric_message)
            attempts = 0
            ack_received.clear()

            while attempts < max_retransmissions and not ack_received.is_set():
                with udp_lock:
                    udp_socket.sendto(message.encode(), (HOST, UDP_PORT))
                    print(f"[METRIC] Métricas enviadas: {metric_data} (tentativa {attempts + 1})")
                attempts += 1

                try:
                    udp_socket.settimeout(timeout)
                    data, addr = udp_socket.recvfrom(1024)
                    ack_msg = data.decode()
                    if ack_msg == f"ACK:{sequence_number}":
                        ack_received.set()
                        sequence_number += 1
                        print("[METRIC] ACK recebido do servidor")
                except socket.timeout:
                    print("[METRIC] Timeout esperando ACK, retransmitindo...")

            if not ack_received.is_set():
                print("[METRIC] Falha no envio de métricas após máximo de retransmissões.")
                # Opcional: adicionar lógica para lidar com a falha

            time.sleep(frequency)
        else:
            time.sleep(1)

# Enviar alertas via TCP
def send_alert(alert_message):
    try:
        tcp_socket.sendall(f"ALERT:{AGENT_ID}:{alert_message}".encode())
        print(f"[ALERT] Enviado: {alert_message}")
    except Exception as e:
        print(f"[ALERT] Erro ao enviar alerta: {e}")

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

# Conectar ao servidor via TCP
def tcp_connect():
    try:
        tcp_socket.connect((HOST, TCP_PORT))
        print("[TCP] Conectado ao servidor para envio de alertas.")
    except Exception as e:
        print(f"[TCP] Erro ao conectar: {e}")

# Programa principal do agente
def start_agent():
    try:
        print(f"[AGENT] Meu ID é: {AGENT_ID}")

        # Realiza o handshake UDP
        if not udp_handshake():
            raise ConnectionError("[HANDSHAKE] Falha na conexão com o servidor!")

        print("[HANDSHAKE] Conexão estabelecida com o servidor!")

        # Receber tarefa do servidor
        receive_task()

        # Conectar via TCP para envio de alertas
        tcp_connect() 

        # Iniciar thread para envio de métricas
        threading.Thread(target=send_metrics, daemon=True).start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[AGENT] Agente interrompido manualmente.")

    finally:
        udp_socket.close()
        tcp_socket.close()

if __name__ == "__main__":
    start_agent()
