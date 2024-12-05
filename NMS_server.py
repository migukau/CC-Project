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
HOST = '10.0.3.10'   # IP do servidor
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

# Guardar numeros de sequencia recebidos 
sequence_numbers = {}
sequence_numbers_lock = threading.Lock()

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
errors_lock = threading.Lock()

# Array para armazenar logs de conexões do servidor
logs = []
logs_lock = threading.Lock()

# Evento de controlo para encerrar o servidor
shutdown_event = threading.Event()

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
                    'alertflow_conditions': device.get('alertflow_conditions', {}),
                    'ping_target': device.get('ping_target', '')  # Incluindo o ping_target aqui
                }
        
        with logs_lock:
            logs.append("[SERVER] Tarefas carregadas com sucesso.")
    except FileNotFoundError:
        with errors_lock:
            errors.append("[SERVER] tasks.json não encontrado.")
    except json.JSONDecodeError as e:
        with errors_lock:
            errors.append(f"[SERVER] Erro ao decodificar tasks.json: {e}")
    except Exception as e:
        with errors_lock:
            errors.append(f"[SERVER] Erro ao carregar tarefas: {e}")

# Envia as tasks ao agente correspondente
def send_task_to_agent(agent_id, addr):
    with tasks_lock:
        task = tasks.get(agent_id)
    if task:
        # Adiciona o IP do outro agente que o agente deve monitorar para o ping
        ping_target = task.get("ping_target", "")
        task_message = json.dumps(task)
        udp_socket.sendto(encode_message(0b10, 0, 0, task_message), addr)
        with logs_lock:
            logs.append(f"[SERVER] Tarefa enviada para {agent_id} com o ping_target {ping_target}")
    else:
        with errors_lock:
            errors.append(f"[SERVER] Nenhuma tarefa encontrada para {agent_id}")

# UDP Handshake e Comunicação
def udp_listener():
    with logs_lock:
        logs.append("[UDP] Servidor está à espera de mensagens...")
    while True:
        try:
            # Receber mensagem do cliente
            data, addr = udp_socket.recvfrom(4096)
            flags, seq, ack, payload = decode_message(data)

            if flags == 0b00:  # SYN
                with logs_lock:
                    logs.append(f"[HANDSHAKE] Recebido SYN de {addr}: seq={seq}, payload={payload}")
                agent_id = payload

                # Atualizar lista de agentes com lock
                with agents_lock:
                    agents[agent_id] = {"address": addr, "last_seen": time.time()}
                
                # Enviar SYN-ACK
                syn_ack_message = encode_message(0b01, seq + 1, seq + 1, "")
                udp_socket.sendto(syn_ack_message, addr)
                with logs_lock:
                    logs.append(f"[HANDSHAKE] Enviado SYN-ACK para {agent_id}")

            elif flags == 0b01:  # ACK
                with logs_lock:
                    logs.append(f"[HANDSHAKE] ACK recebido de {addr}: seq={seq}, ack={ack}")

                # Enviar tarefa correspondente ao agente
                send_task_to_agent(agent_id, addr)

            elif flags == 0b10 or flags == 0b11:  # DATA ou Retransmissão
                # Processar métricas recebidas
                process_metric_message(data, addr)

        except Exception as e:
            with errors_lock:
                errors.append(f"[UDP] Erro: {e}")

# Processar métricas recebidas e enviar ACK
def process_metric_message(data, addr):
    try:
        flags, seq, ack, payload = decode_message(data)
        metric_message = json.loads(payload)
        agent_id = metric_message["agent_id"]
        metrics = metric_message["metric_data"]
        timestamp = datetime.fromtimestamp(metric_message["timestamp"]).strftime("%Y/%m/%d %H:%M:%S")

        # Enviar ACK
        ack_message = encode_message(0b01, seq + 1, seq, "")
        udp_socket.sendto(ack_message, addr)

        if agent_id in sequence_numbers and seq in sequence_numbers[agent_id]:
            with errors_lock:
                errors.append(f"Mensagem duplicada recebida de {agent_id} com o número de sequência")
        else:    
            # Guardar Sequence number
            with sequence_numbers_lock:
                if agent_id not in sequence_numbers:
                    sequence_numbers[agent_id] = []
                sequence_numbers[agent_id].append(seq)
            
            # Armazenar métricas
            with metrics_lock:
                if agent_id not in metrics_data:
                    metrics_data[agent_id] = []
                metrics_data[agent_id] = ({
                    "timestamp": timestamp,
                    "metrics": metrics
                })
                log_metrics_to_csv(agent_id, {
                    "timestamp": timestamp,
                    "metrics": metrics
                })

            if flags == 0b10:
                with logs_lock:
                    logs.append(f"[METRIC] Métricas recebidas de {agent_id}: {metrics}")
            elif flags == 0b11:
                with logs_lock:
                    logs.append(f"[METRIC] Retransmissão recebida de {agent_id}: {metrics}")

            # Atualizar último visto
            with agents_lock:
                if agent_id in agents:
                    agents[agent_id]["last_seen"] = time.time()

    except Exception as e:
        with errors_lock:
            errors.append(f"[METRIC] Erro ao processar métricas: {e}")

# TCP Comunicação para alertas
def handle_tcp_connection(conn, addr):
    with logs_lock:
        logs.append(f"[TCP] Conexão estabelecida com {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                continue

            flags, seq, ack, payload = decode_message(data)

            # Decodificar payload no formato {AGENT_ID}:{valor}:{timestamp}
            agent_id, value, alert_timestamp = payload.split(":")
            alert_type = "Desconhecido"
            try:
                alert_timestamp = int(alert_timestamp)  # Converte primeiro para float e depois para int
                formatted_time = datetime.fromtimestamp(alert_timestamp).strftime("%Y/%m/%d %H:%M:%S")
            except ValueError:
                formatted_time = alert_timestamp  # Caso falhe, usa o timestamp original (não formatado)

            # Identificar o tipo de alerta baseado na flag
            if flags == 0x01:
                alert_type = "CPU"
            elif flags == 0x02:
                alert_type = "RAM"
            elif flags == 0x03:
                alert_type = "Latência"

            with logs_lock:
                logs.append(f"[ALERT] Recebido alerta de {alert_type} do agente {agent_id} com valor {value} em {alert_timestamp}")

            # log do alerta
            log_alerts_to_csv(agent_id, f"{formatted_time};{alert_type};{value}")
            
            with alerts_lock:
                if agent_id not in alerts:
                    alerts[agent_id] = []
                alerts[agent_id].append(f"{formatted_time}; {alert_type}: {value}")

            # Enviar ACK ao cliente
            ack_message = encode_message(0x01, seq, 0, "")
            conn.sendall(ack_message)

    except Exception as e:
        errors.append(f"[TCP] Erro: {e}")
    finally:
        conn.close()

# Thread principal do TCP
def tcp_main_thread():
    tcp_socket.listen()
    with logs_lock:
        logs.append("[TCP] Servidor está à espera de conexões...")
    while True:
        try:
            conn, addr = tcp_socket.accept()
            threading.Thread(target=handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            errors.append(f"[TCP] Erro no thread principal: {e}")
            break

# Monitorar inatividade dos agentes
def monitor_agents():
    while True:
        time.sleep(5)
        now = time.time()
        with agents_lock:
            for agent_id, info in list(agents.items()):
                if now - info["last_seen"] > 2 * SEND_INTERVAL + 2:
                    with logs_lock:
                        logs.append(f"[MONITOR] Agente {agent_id} removido por inatividade")
                    del agents[agent_id]
                    del metrics_data[agent_id]

# Funções de log
def log_metrics_to_csv(agent_id, metrics):
    if metrics_data[agent_id]:
        with open('metrics_log.csv', 'a', newline='') as csvfile:
            fieldnames = ['agent_id', 'timestamp', 'metrics']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'agent_id': agent_id, 'timestamp': metrics["timestamp"], 'metrics': metrics["metrics"]})

def log_alerts_to_csv(agent_id, alert_message):
    # Extrair o timestamp do alert_message
    alert_timestamp, alert_type, value  = alert_message.split(";")
    
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
               choices=["Atualizar lista de logs", "Voltar"]
        ).ask()
    
        if option == "Atualizar lista de logs":
            continue
        elif option == "Voltar":
            show_agents_menu()

def create_log_files():
    if os.path.exists("alerts_log.csv"):
        os.remove("alerts_log.csv")
    
    open("alerts_log.csv", 'w')

    if os.path.exists("metrics_log.csv"):
        os.remove("metrics_log.csv")
    
    open("metrics_log.csv", 'w')
    
# Iniciar o servidor
def start_server():
    # Load do JSON
    load_tasks()
    
    # Cria os ficheiros de log
    create_log_files()
    
    # Iniciar threads
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=tcp_main_thread, daemon=True).start()
    threading.Thread(target=show_agents_menu, daemon=True).start()
    threading.Thread(target=monitor_agents, daemon=True).start()

    try:
        while not shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("[SERVER] Servidor interrompido manualmente")
    finally:
        udp_socket.close()
        tcp_socket.close()
        print("[SERVER] Sockets fechados")

if __name__ == "__main__":
    start_server()
