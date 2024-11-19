# IMPORTS:
import socket
import time
import threading

# CONFIG:
HOST = '10.2.2.1'   # IP do servidor
UDP_PORT = 24       # Porta UDP
TCP_PORT = 64       # Porta TCP
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

# ___________________________________

# UDP Handshake e Comunicação
def udp_handshake():
    print("[UDP] Servidor aguardando mensagens...")
    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            message = data.decode()
            print(f"[UDP] Recebido: {message} de {addr}")

            if "SEQ" in message and "FLAGS:SYN" in message:
                # Responder com SYN-ACK
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                seq = int(parts["SEQ"])
                syn_ack_message = f"SEQ:{seq + 1}|ACK:{seq + 1}|FLAGS:SYN-ACK"
                udp_socket.sendto(syn_ack_message.encode(), addr)
                print(f"[HANDSHAKE] Enviado: {syn_ack_message}")

            elif "SEQ" in message and "FLAGS:ACK" in message:
                # Completar o handshake
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                agent_id = f"Agent_{addr[0]}_{addr[1]}"
                with agents_lock:
                    agents[agent_id] = {
                        "address": addr,
                        "last_seen": time.time()
                    }
                udp_socket.sendto("HANDSHAKE_COMPLETE".encode(), addr)
                print(f"[HANDSHAKE] Handshake completo para {agent_id}")
                
                # Iniciar thread de agente
                threading.Thread(target=handle_agent, args=(agent_id, addr), daemon=True).start()

        except Exception as e:
            print(f"[HANDSHAKE] Erro: {e}")


def handle_agent(agent_id, addr):
    print(f"[THREAD] Iniciada para o agente {agent_id} ({addr})")
    while True:
        try:
            data, address = udp_socket.recvfrom(1024)
            if address != addr:
                continue

            message = data.decode()
            print(f"[{agent_id}] Recebido: {message}")

            with agents_lock:
                agents[agent_id]["last_seen"] = time.time()

            if "METRIC" in message:
                print(f"[{agent_id}] Métrica recebida: {message}")

        except Exception as e:
            print(f"[{agent_id}] Erro: {e}")
            break

    print(f"[THREAD] Finalizada para o agente {agent_id}")


# TCP Comunicação
def handle_tcp_connection(conn, addr):
    print(f"[TCP] Conexão estabelecida com {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                continue

            if data.startswith("ALERT:"):
                parts = data.split(":")
                agent_id = parts[1].strip()
                alert_message = ":".join(parts[2:])
                print(f"[ALERT] Recebido de {agent_id}: {alert_message}")

    except Exception as e:
        print(f"[TCP] Erro: {e}")

    finally:
        conn.close()


def tcp_main_thread():
    tcp_socket.listen()
    print("[TCP] Servidor aguardando conexões...")
    while True:
        try:
            conn, addr = tcp_socket.accept()
            print(f"[TCP] Conexão recebida de {addr}")
            threading.Thread(target=handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[TCP] Erro no thread principal: {e}")
            break


# Monitoramento de atividade dos agentes
def monitor_agents():
    while True:
        time.sleep(5)
        now = time.time()
        with agents_lock:
            for agent_id, info in list(agents.items()):
                if now - info["last_seen"] > 2 * SEND_INTERVAL + 2:
                    print(f"[MONITOR] Agente {agent_id} removido por inatividade")
                    del agents[agent_id]


# Início do Servidor
try:
    # Iniciar threads para UDP e TCP
    threading.Thread(target=udp_handshake, daemon=True).start()
    threading.Thread(target=tcp_main_thread, daemon=True).start()

    # Monitorar agentes
    monitor_agents()

except KeyboardInterrupt:
    print("[SERVER] Servidor interrompido manualmente")

finally:
    udp_socket.close()
    tcp_socket.close()
    print("[SERVER] Sockets fechados")
