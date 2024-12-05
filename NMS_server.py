import socket
import time
import threading
import json
import csv
import questionary
import os
import sys
from datetime import datetime

# CONFIG:
HOST = '10.0.4.10'   # IP do servidor
UDP_PORT = 24       # Porta UDP
TCP_PORT = 64       # Porta TCP
SEND_INTERVAL = 20  # Intervalo para monitoramento de agentes

# Dict para gerir os agentes
agents = {}
agents_lock = threading.Lock()

# Armazenamento de métricas
metrics_data = {}
metrics_lock = threading.Lock()

# Armazenamento de alertas
alerts = {}
alerts_lock = threading.Lock()

# Armazenamento das tasks
tasks = {}
tasks_lock = threading.Lock()

# Sequência esperada para cada agente
expected_sequence = {}
expected_sequence_lock = threading.Lock()  # Lock for thread-safe access

# SOCKETS:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((HOST, UDP_PORT))

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_socket.bind((HOST, TCP_PORT))

# Flag para mostra o menu de erros
show_errors = False

# Array para armazenar mensagens de erros ou alertas
errors = []

# Array para armazenar logs de conexões do servidor
logs = []
logs_lock = threading.Lock()

# Evento de controlo para encerrar o servidor
shutdown_event = threading.Event()

# Funções de codificação/decodificação
def encode_message(flags, seq, ack, payload):
    payload_bytes = payload.encode() if isinstance(payload, str) else b""
    length = len(payload_bytes)
    header = (flags << 48) | (seq << 32) | (ack << 16) | length
    header_bytes = header.to_bytes(7, 'big')  # 7 bytes: 1 byte flags + 2 seq + 2 ack + 2 length
    return header_bytes + payload_bytes

def decode_message(message):
    header = int.from_bytes(message[:7], 'big')
    flags = (header >> 48) & 0xFF
    seq = (header >> 32) & 0xFFFF
    ack = (header >> 16) & 0xFFFF
    length = header & 0xFFFF
    payload = message[7:7 + length]
    return flags, seq, ack, payload.decode() if payload else ""

# Function to log messages with timestamps
def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with logs_lock:
        logs.append(f"[{timestamp}] {message}")

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
                    'alertflow_conditions': device.get('alertflow_conditions', {}),
                    'ping_target': device.get('ping_target', '')
                }
        
        log_message("[SERVER] Tasks loaded successfully.")
    except FileNotFoundError:
        errors.append("[SERVER] tasks.json not found.")
    except json.JSONDecodeError as e:
        errors.append(f"[SERVER] Error decoding tasks.json: {e}")
    except Exception as e:
        errors.append(f"[SERVER] Error loading tasks: {e}")

# Envia as tasks ao agente correspondente
def send_task_to_agent(agent_id, addr):
    with tasks_lock:
        task = tasks.get(agent_id)
    if task:
        ping_target = task.get("ping_target", "")
        task_message = json.dumps(task)
        udp_socket.sendto(encode_message(0b10, 0, 0, task_message), addr)
        log_message(f"[SERVER] Task sent to {agent_id} with ping_target {ping_target}")
    else:
        errors.append(f"[SERVER] No task found for {agent_id}")

# UDP Handshake e Comunicação
def udp_listener():
    log_message("[UDP] Server is waiting for messages...")
    while True:
        try:
            # Receber mensagem do cliente
            data, addr = udp_socket.recvfrom(4096)
            flags, seq, ack, payload = decode_message(data)

            if flags == 0b00:  # SYN
                agent_id = payload.strip()

                # Atualizar lista de agentes
                with agents_lock:
                    agents[agent_id] = {"address": addr, "last_seen": time.time(), "task_sent": False}

                # Reset ao numero de sequência esperado
                with expected_sequence_lock:
                    expected_sequence[agent_id] = 0

                # Send SYN-ACK
                syn_ack_message = encode_message(0b01, seq + 1, seq + 1, "")
                udp_socket.sendto(syn_ack_message, addr)
                log_message(f"[HANDSHAKE] SYN-ACK sent to {agent_id}")

            elif flags == 0b01:  # ACK
                log_message(f"[HANDSHAKE] ACK received from {addr}: seq={seq}, ack={ack}")

                # Enviar tarefa ao agente correspondente
                with agents_lock:
                    agent_id = next((aid for aid, info in agents.items() if info["address"] == addr), None)
                    if agent_id and not agents[agent_id]["task_sent"]:
                        send_task_to_agent(agent_id, addr)
                        agents[agent_id]["task_sent"] = True

            elif flags == 0b10 or flags == 0b11:  # DATA or Retransmission
                process_metric_message(data, addr)

        except Exception as e:
            log_message(f"[UDP] Unexpected error: {e}")


def process_metric_message(data, addr):
    try:
        flags, seq, ack, payload = decode_message(data)
        metric_message = json.loads(payload)
        agent_id = metric_message["agent_id"]
        metrics = metric_message["metric_data"]
        timestamp = datetime.fromtimestamp(metric_message["timestamp"]).strftime("%Y/%m/%d %H:%M:%S")

        # Inicializar seq esperado para o agente, se necessário
        with expected_sequence_lock:
            if agent_id not in expected_sequence:
                expected_sequence[agent_id] = 0
            expected_seq = expected_sequence[agent_id]

        if seq == expected_seq:
            # Process metrics
            expected_sequence[agent_id] += 1

            with metrics_lock:
                metrics_data[agent_id] = {
                    "timestamp": timestamp,
                    "metrics": metrics
                }
            # Escrever as métricas no arquivo CSV
            log_message(f"[METRIC] Metrics received from {agent_id}: {metrics}")
            log_metrics_to_csv(agent_id, {"timestamp": timestamp, "metrics": metrics})

            # Send ACK
            ack_message = encode_message(0b01, seq + 1, seq, "")
            udp_socket.sendto(ack_message, addr)

        elif seq < expected_seq:
             # Pacote duplicado (retransmissão)
            ack_message = encode_message(0b01, expected_seq, seq, "")
            udp_socket.sendto(ack_message, addr)
            log_message(f"[METRIC] Duplicate packet from {agent_id}: seq={seq}, expected={expected_seq}")

        else:
            # Pacote fora do ordem
            log_message(f"[METRIC] Out-of-order packet from {agent_id}: seq={seq}, expected={expected_seq}")
            
        # Atualizar último visto
        with agents_lock:
            if agent_id in agents:
                agents[agent_id]["last_seen"] = time.time()

    except Exception as e:
        log_message(f"[METRIC] Error processing metrics: {e}")

# NetTask - Comunicação para alertas
def handle_tcp_connection(conn, addr):
    log_message(f"[TCP] Connection established with {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                continue

            flags, seq, ack, payload = decode_message(data)

            # Decode payload in the format {AGENT_ID}:{value}:{timestamp}
            agent_id, value, alert_timestamp = payload.split(":")
            alert_type = "Unknown"
            try:
                alert_timestamp = int(alert_timestamp)
                formatted_time = datetime.fromtimestamp(alert_timestamp).strftime("%Y/%m/%d %H:%M:%S")
            except ValueError:
                formatted_time = alert_timestamp

            # Identify alert type based on the flag
            if flags == 0x01:
                alert_type = "CPU"
            elif flags == 0x02:
                alert_type = "RAM"
            elif flags == 0x03:
                alert_type = "Latency"

            log_message(f"[ALERT] Received {alert_type} alert from agent {agent_id} with value {value} at {formatted_time}")

            # Log the alert
            log_alerts_to_csv(agent_id, f"{formatted_time};{alert_type};{value}")
            
            with alerts_lock:
                if agent_id not in alerts:
                    alerts[agent_id] = []
                alerts[agent_id].append(f"{formatted_time}; {alert_type}: {value}")

            # Send ACK to the client
            ack_message = encode_message(0x01, seq, 0, "")
            conn.sendall(ack_message)

    except Exception as e:
        errors.append(f"[TCP] Error: {e}")
    finally:
        conn.close()

# Thread principal do TCP
def tcp_main_thread():
    tcp_socket.listen()
    log_message("[TCP] Server is waiting for connections...")
    while True:
        try:
            conn, addr = tcp_socket.accept()
            threading.Thread(target=handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            errors.append(f"[TCP] Error in main thread: {e}")
            break

# Monitorar inatividade dos agentes
def monitor_agents():
    while True:
        time.sleep(5)
        now = time.time()
        with agents_lock:
            for agent_id, info in list(agents.items()):
                if now - info["last_seen"] > 2 * SEND_INTERVAL + 2:
                    log_message(f"[MONITOR] Agent {agent_id} removed due to inactivity")
                    del agents[agent_id]
                    with metrics_lock:
                        if agent_id in metrics_data:
                            del metrics_data[agent_id]
                    with expected_sequence_lock:
                        if agent_id in expected_sequence:
                            del expected_sequence[agent_id]

# Funções de log
def log_metrics_to_csv(agent_id, metrics):
    if metrics_data[agent_id]:
        with open('metrics_log.csv', 'a', newline='') as csvfile:
            fieldnames = ['agent_id', 'timestamp', 'metrics']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'agent_id': agent_id, 'timestamp': metrics["timestamp"], 'metrics': metrics["metrics"]})

def log_alerts_to_csv(agent_id, alert_message):
    alert_timestamp, alert_type, value  = alert_message.split(";")
    alert_combined = f"{alert_type}: {value}"
    with open('alerts_log.csv', 'a', newline='') as csvfile:
        fieldnames = ['agent_id', 'timestamp', 'alert']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({
            'agent_id': agent_id,
            'timestamp': alert_timestamp,
            'alert': alert_combined
        })

def clear_terminal():
    sys.stdout.write('\033c')  # ANSI escape code para limpar o terminal
    sys.stdout.flush()

# Mostrar menu de agentes (com questionary)
def show_agents_menu():
    global show_errors
     
    while not shutdown_event.is_set():
        # Mostrar a lista de agentes conectados
        clear_terminal()
        print("Agentes conectados ao servidor:\n")
        if metrics_data == {}:
            print("Nenhum agente conectado no momento.\n")
        else:
            for agente_id,metricas in metrics_data.items():
                print(f"{agente_id}: {metricas['metrics']}\n")
        
        if show_errors:
            print("Erros:")
            if errors == []:
                print("Não existem erros.\n")
            else:
                for message in errors:
                    print(message)

        # Mostrar as opções no menu
        option = questionary.select(
            "Escolha uma opção:",
            choices=["Atualizar lista de agentes","Toggle Erros", "Mostrar Alertas","Mostrar logs do servidor","Sair"]
        ).ask() # a thread da lock aqui

        if option == "Atualizar lista de agentes":
            # Atualiza o menu
            continue
        elif option == "Toggle Erros":
            show_errors = not show_errors
            continue
        elif option == "Mostrar Alertas":
            show_alerts_menu()
        elif option == "Mostrar logs do servidor":
            show_logs_menu()
        elif option == "Sair":
            clear_terminal()
            print("Encerrando menu de agentes...")
            shutdown_event.set()
            break

        time.sleep(5)
            
def show_alerts_menu():
    while not shutdown_event.is_set():
        clear_terminal()
        print("Alertas recebido:\n")

        if alerts == {}:
            print("Nenhum alerta.\n")
        else:
            for agente_id in alerts:
                print(f"{agente_id}:\n")
                for alert in alerts[agente_id]:
                    print(f"    {alert}\n")
  
        # Mostrar as opções no menu
        option = questionary.select(
            "Escolha uma opção:",
               choices=["Atualizar lista de alertas", "Voltar"]
        ).ask()
    
        if option == "Atualizar lista de alertas":
            continue
        elif option == "Voltar":
            show_agents_menu()

def show_logs_menu():
    while not shutdown_event.is_set():
        clear_terminal()
        print("Logs:\n")

        if logs == []:
            print("Não existem logs.\n")
        else:
            for message in logs:
                print(message)
  
        # Mostrar as opções no menu
        option = questionary.select(
            "Escolha uma opção:",
               choices=["Atualizar lista de logs", "Apagar lista de logs", "Voltar"]
        ).ask()
    
        if option == "Atualizar lista de logs":
            continue
        elif option == "Apagar lista de logs":
            with logs_lock:
                logs.clear()
        elif option == "Voltar":
            show_agents_menu()

def create_log_files():
    if os.path.exists("alerts_log.csv"):
        os.remove("alerts_log.csv")
    open("alerts_log.csv", 'w')

    if os.path.exists("metrics_log.csv"):
        os.remove("metrics_log.csv")
    open("metrics_log.csv", 'w')
        
# Start the server
def start_server():
    # Load tasks from JSON
    load_tasks()
    
    # Create log files
    create_log_files()
    
    # Start threads
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=tcp_main_thread, daemon=True).start()
    threading.Thread(target=show_agents_menu, daemon=True).start()
    threading.Thread(target=monitor_agents, daemon=True).start()

    try:
        while not shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("[SERVER] Server manually interrupted")
    finally:
        udp_socket.close()
        tcp_socket.close()
        print("[SERVER] Sockets closed")

if __name__ == "__main__":
    start_server()
