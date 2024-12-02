import socket
import time
import threading
import json
import csv

# CONFIG:
HOST = '10.2.2.1'   # IP do servidor
UDP_PORT = 24       # Porta UDP
TCP_PORT = 64       # Porta TCP
SEND_INTERVAL = 20  # Intervalo para monitoramento de agentes

# Dict para gerir os agentes
agents = {}
agents_lock = threading.Lock()

# Armazenamento de métricas
metrics_data = {}
metrics_lock = threading.Lock()

# Armazenamento das tasks
tasks = {}
tasks_lock = threading.Lock()

# SOCKETS:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((HOST, UDP_PORT))

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind((HOST, TCP_PORT))



# Funções de codificação/decodificação

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



# Leitura das tasks do JSON
def load_tasks():
    try:
        with open('tasks.json', 'r') as file:
            data = json.load(file)
        with tasks_lock:
            for device in data['devices']:
                agent_id = device['device_id']
                tasks[agent_id] = {
                    'task_id': data['task_id'],
                    'frequency': data['frequency'],
                    'device_metrics': device.get('device_metrics', {}),
                    'link_metrics': device.get('link_metrics', {}),
                    'alertflow_conditions': device.get('alertflow_conditions', {})
                }
        print("[SERVER] Tarefas carregadas com sucesso.")
    except FileNotFoundError:
        print("[SERVER] tasks.json não encontrado.")
    except json.JSONDecodeError as e:
        print(f"[SERVER] Erro ao decodificar tasks.json: {e}")
    except Exception as e:
        print(f"[SERVER] Erro ao carregar tarefas: {e}")


# Envia as tasks ao agente correspondente
def send_task_to_agent(agent_id, addr):
    with tasks_lock:
        task = tasks.get(agent_id)
    if task:
        task_message = json.dumps(task)
        udp_socket.sendto(encode_message(0b10, 0, 0, task_message), addr)
        print(f"[SERVER] Tarefa enviada para {agent_id}")
    else:
        print(f"[SERVER] Nenhuma tarefa encontrada para {agent_id}")


# UDP Handshake e Comunicação
def udp_listener():
    print("[UDP] Servidor está à espera de mensagens...")
    while True:
        try:
            # Receber mensagem do cliente
            data, addr = udp_socket.recvfrom(4096)
            flags, seq, ack, payload = decode_message(data)

            if flags == 0b00:  # SYN
                print(f"[HANDSHAKE] Recebido SYN de {addr}: seq={seq}, payload={payload}")
                agent_id = payload

                # Atualizar lista de agentes com lock
                with agents_lock:
                    agents[agent_id] = {"address": addr, "last_seen": time.time()}
                
                # Enviar SYN-ACK
                syn_ack_message = encode_message(0b01, seq + 1, seq + 1, "")
                udp_socket.sendto(syn_ack_message, addr)
                print(f"[HANDSHAKE] Enviado SYN-ACK para {agent_id}")

            elif flags == 0b01:  # ACK
                print(f"[HANDSHAKE] ACK recebido de {addr}: seq={seq}, ack={ack}")

                # Enviar tarefa correspondente ao agente
                send_task_to_agent(agent_id, addr)

            elif flags == 0b10 or flags == 0b11:  # DATA ou Retransmissão
                # Processar métricas recebidas
                process_metric_message(data, addr)

        except Exception as e:
            print(f"[UDP] Erro: {e}")



# Processar métricas recebidas e enviar ACK
def process_metric_message(data, addr):
    try:
        flags, seq, ack, payload = decode_message(data)
        metric_message = json.loads(payload)
        agent_id = metric_message["agent_id"]
        metrics = metric_message["metric_data"]
        timestamp = metric_message["timestamp"]

        # Enviar ACK
        ack_message = encode_message(0b01, seq + 1, seq, "")
        udp_socket.sendto(ack_message, addr)

        # Armazenar métricas
        with metrics_lock:
            if agent_id not in metrics_data:
                metrics_data[agent_id] = []
            log_metrics_to_csv(agent_id, {
                "timestamp": timestamp,
                "metrics": metrics
            })

        if flags == 0b10:
            print(f"[METRIC] Métricas recebidas de {agent_id}: {metrics}")
        elif flags == 0b11:
            print(f"[METRIC] Retransmissão recebida de {agent_id}: {metrics}")

        # Atualizar último visto
        with agents_lock:
            if agent_id in agents:
                agents[agent_id]["last_seen"] = time.time()

    except Exception as e:
        print(f"[METRIC] Erro ao processar métricas: {e}")


# TCP Comunicação para alertas
def handle_tcp_connection(conn, addr):
    print(f"[TCP] Conexão estabelecida com {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                continue

            flags, seq, ack, payload = decode_message(data)

            # Decodificar payload no formato {AGENT_ID}:{valor}:{timestamp}
            agent_id, value, alert_timestamp = payload.split(":")
            alert_type = "Desconhecido"

            # Identificar o tipo de alerta baseado na flag
            if flags == 0x01:
                alert_type = "CPU"
            elif flags == 0x02:
                alert_type = "RAM"
            elif flags == 0x03:
                alert_type = "Latência"

            print(f"[ALERT] Recebido alerta de {alert_type} do agente {agent_id} com valor {value} em {alert_timestamp}")

            # log do alerta
            log_alerts_to_csv(agent_id, f"{alert_type}:{value}:{alert_timestamp}")

            # Enviar ACK ao cliente
            ack_message = encode_message(0x01, seq, 0, "")
            conn.sendall(ack_message)

    except Exception as e:
        print(f"[TCP] Erro: {e}")
    finally:
        conn.close()



# Thread principal do TCP
def tcp_main_thread():
    tcp_socket.listen()
    print("[TCP] Servidor está à espera de conexões...")
    while True:
        try:
            conn, addr = tcp_socket.accept()
            print(f"[TCP] Conexão recebida de {addr}")
            threading.Thread(target=handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[TCP] Erro no thread principal: {e}")
            break

# Monitorar inatividade dos agentes
def monitor_agents():
    while True:
        time.sleep(5)
        now = time.time()
        with agents_lock:
            for agent_id, info in list(agents.items()):
                if now - info["last_seen"] > 2 * SEND_INTERVAL + 2:
                    print(f"[MONITOR] Agente {agent_id} removido por inatividade")
                    del agents[agent_id]

# Funções de log
def log_metrics_to_csv(agent_id, metrics):
    with open('metrics_log.csv', 'a', newline='') as csvfile:
        fieldnames = ['agent_id', 'timestamp', 'metrics']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'agent_id': agent_id, 'timestamp': metrics["timestamp"], 'metrics': metrics["metrics"]})

def log_alerts_to_csv(agent_id, alert_message):
    # Extrair o timestamp do alert_message
    alert_type, value, alert_timestamp = alert_message.split(":")
    
    # Concatenar o tipo de alerta e o valor na forma "alert_type:value"
    alert_combined = f"{alert_type}: {value}"

    # Abrir o arquivo CSV no modo append
    with open('alerts_log.csv', 'a', newline='') as csvfile:
        fieldnames = ['agent_id', 'timestamp', 'alert']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Escrever o log com o formato desejado
        writer.writerow({
            'agent_id': agent_id,
            'timestamp': alert_timestamp,
            'alert': alert_combined
        })


# Iniciar o servidor
def start_server():
    # Load do JSON
    load_tasks()

    # Iniciar threads para UDP e TCP
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=tcp_main_thread, daemon=True).start()

    # Monitorar agentes
    monitor_agents()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("[SERVER] Servidor interrompido manualmente.")
    finally:
        udp_socket.close()
        tcp_socket.close()
        print("[SERVER] Sockets fechados")

