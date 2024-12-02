import socket
import time
import threading
import json
import questionary
import os

# CONFIG:
HOST = '127.0.0.1'  # IP local para testes
UDP_PORT = 5000     # Porta UDP alterada
TCP_PORT = 5001     # Porta TCP alterada

SEND_INTERVAL = 20  # Intervalo de envio de métricas em segundos
# ___________________________________

# SOCKETS:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((HOST, UDP_PORT))

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind((HOST, TCP_PORT))
# ___________________________________

# Gerenciamento de agentes:
agents = {}
agents_lock = threading.Lock()

# Armazenamento de métricas:
metrics_data = {}
metrics_lock = threading.Lock()

# Armazenamento de tarefas:
tasks = {}
tasks_lock = threading.Lock()
# ___________________________________

# Evento de controlo para encerrar o servidor
shutdown_event = threading.Event()

# Leitura de tarefas do arquivo JSON
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
    except Exception as e:
        print(f"[SERVER] Erro ao carregar tarefas: {e}")

# Envio da tarefa ao agente
def send_task_to_agent(agent_id, addr):
    with tasks_lock:
        task = tasks.get(agent_id)
    if task:
        task_message = json.dumps(task)
        udp_socket.sendto(task_message.encode(), addr)
        print(f"[SERVER] Tarefa enviada para {agent_id}")
    else:
        print(f"[SERVER] Nenhuma tarefa encontrada para {agent_id}")

# UDP Handshake e Comunicação
def udp_listener():
    print("[UDP] Servidor aguardando mensagens...")
    while not shutdown_event.is_set():
        try:
            data, addr = udp_socket.recvfrom(4096)
            message = data.decode()
            print(f"[UDP] Recebido: {message} de {addr}")

            if "FLAGS:SYN" in message:
                # Responder com SYN-ACK
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                seq = int(parts["SEQ"])
                agent_id = parts.get("AGENT_ID", f"Agent_{addr[0]}_{addr[1]}")
                syn_ack_message = f"SEQ:{seq + 1}|ACK:{seq + 1}|FLAGS:SYN-ACK"
                udp_socket.sendto(syn_ack_message.encode(), addr)
                print(f"[HANDSHAKE] Enviado: {syn_ack_message}")

            elif "FLAGS:ACK" in message:
                # Completar o handshake
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                agent_id = parts.get("AGENT_ID", f"Agent_{addr[0]}_{addr[1]}")
                with agents_lock:
                    agents[agent_id] = {
                        "address": addr,
                        "last_seen": time.time()
                    }
                print(f"[HANDSHAKE] Handshake completo para {agent_id}")

                # Enviar tarefa ao agente
                send_task_to_agent(agent_id, addr)

            else:
                # Processar métricas recebidas
                process_metric_message(message, addr)

        except Exception as e:
            print(f"[UDP] Erro: {e}")

# Processar métricas recebidas e enviar ACK
def process_metric_message(message, addr):
    try:
        metric_message = json.loads(message)
        agent_id = metric_message['agent_id']
        seq_num = metric_message['sequence_number']
        metric_data_info = metric_message['metric_data']
        timestamp = metric_message['timestamp']

        # Enviar ACK
        ack_message = f"ACK:{seq_num}"
        udp_socket.sendto(ack_message.encode(), addr)

        # Armazenar métricas
        with metrics_lock:
            if agent_id not in metrics_data:
                metrics_data[agent_id] = []
            metrics_data[agent_id].append({
                'timestamp': timestamp,
                'metrics': metric_data_info
            })

        print(f"[METRIC] Métricas recebidas de {agent_id}: {metric_data_info}")

        # Atualizar último visto
        with agents_lock:
            if agent_id in agents:
                agents[agent_id]["last_seen"] = time.time()

    except Exception as e:
        print(f"[METRIC] Erro ao processar métricas: {e}")

# TCP Comunicação
def handle_tcp_connection(conn, addr):
    print(f"[TCP] Conexão estabelecida com {addr}")
    try:
        while not shutdown_event.is_set():
            data = conn.recv(4096).decode()
            if not data:
                continue

            if data.startswith("ALERT:"):
                parts = data.split(":", 2)
                agent_id = parts[1].strip()
                alert_message = parts[2]
                print(f"[ALERT] Recebido de {agent_id}: {alert_message}")
                # Aqui, podemos armazenar ou processar o alerta conforme necessário

    except Exception as e:
        print(f"[TCP] Erro: {e}")

    finally:
        conn.close()

def tcp_main_thread():
    tcp_socket.listen()
    print("[TCP] Servidor aguardando conexões...")
    while not shutdown_event.is_set():
        try:
            conn, addr = tcp_socket.accept()
            print(f"[TCP] Conexão recebida de {addr}")
            threading.Thread(target=handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[TCP] Erro no thread principal: {e}")
            break

# Monitoramento de atividade dos agentes
def monitor_agents():
    while not shutdown_event.is_set():
        time.sleep(5)
        now = time.time()
        with agents_lock:
            for agent_id, info in list(agents.items()):
                if now - info["last_seen"] > 2 * SEND_INTERVAL + 2:
                    print(f"[MONITOR] Agente {agent_id} removido por inatividade")
                    del agents[agent_id]

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# Mostrar menu de agentes (com questionary)
def show_agents_menu():
    while not shutdown_event.is_set():
        # Obter lista de agentes conectados
        with agents_lock:
            connected_agents = [
                f"{agent_id} ({info['address'][0]}:{info['address'][1]})"
                for agent_id, info in agents.items()
            ]

        # Mostrar a lista de agentes conectados
        clear_terminal()
        print("Agentes conectados ao servidor:\n")
        print("\n".join(connected_agents) if connected_agents else "Nenhum agente conectado no momento.")
        print("\n")  # Separação visual

        # Mostrar as opções no menu
        option = questionary.select(
            "Escolha uma opção:",
            choices=["Atualizar lista de agentes", "Sair"]
        ).ask()

        if option == "Atualizar lista de agentes":
            # Atualiza o menu
            continue
        elif option == "Sair":
            clear_terminal()
            print("Encerrando menu de agentes...")
            shutdown_event.set()
            break

# Início do servidor
def start_server():
    # Carregar tarefas do arquivo JSON
    load_tasks()

    # Iniciar threads para UDP, TCP, menu e monitoramento de agentes
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=tcp_main_thread, daemon=True).start()
    threading.Thread(target=show_agents_menu, daemon=True).start()
    threading.Thread(target=monitor_agents, daemon=True).start()

    # Manter o servidor ativo enquanto as threads daemon estão rodando
    try:
        while not shutdown_event.is_set():
            time.sleep(1)  # Aguarde sem bloquear
    except KeyboardInterrupt:
        print("[SERVER] Servidor interrompido manualmente")
    finally:
        
        udp_socket.close()
        tcp_socket.close()
        print("[SERVER] Sockets fechados")

if __name__ == "__main__":
    start_server()
