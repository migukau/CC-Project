# IMPORTS:
import socket
import psutil
import time
import platform
import subprocess
#______________________________

# CONFIG:
# Configuracao estática do AGENT:
HOST = '10.2.2.1'   # IP do SERVER
UDP_PORT = 24 		# Porta UDP do SERVER
TCP_PORT = 64		# Porta TCP do SERVER

SEND_INTERVAL = 20	# Intervalo de envio de metricas regular (em segundos)
CPU_THRESHOLD = 50	# Limite de uso de CPU(%) para ativar o alert
PING_THRESHOLD = 100 # Limite do Round Trip Time médio(ms)

# Identificação única do agente
AGENT_ID = f"{platform.node()}" 

# SOCKETS:
# Cria a socket UDP para envio de mensagens regulares:
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Cria a socket TCP para envio de alertas:
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#_________________________________


# HANDSHAKE:
def udp_handshake():
    initial_seq = 1
    syn_message = f"SEQ:{initial_seq}|ACK:0|FLAGS:SYN"
    retransmissions = 0
    max_retransmissions = 5
    timeout = 2  # Timeout in seconds

    while retransmissions < max_retransmissions:
        try:
            udp_socket.sendto(syn_message.encode(), (HOST, UDP_PORT))
            print(f"[HANDSHAKE] Sent SYN (attempt {retransmissions + 1}): {syn_message}")

            udp_socket.settimeout(timeout)
            data, addr = udp_socket.recvfrom(1024)
            message = data.decode()
            print(f"[HANDSHAKE] Received: {message}")

            if "FLAGS:SYN-ACK" in message:
                # Parse SYN-ACK
                parts = {kv.split(":")[0]: kv.split(":")[1] for kv in message.split("|")}
                if int(parts["ACK"]) == initial_seq + 1:
                    server_seq = int(parts["SEQ"])
                    print("[HANDSHAKE] Received valid SYN-ACK")
                    
                    # Send final ACK
                    ack_message = f"SEQ:{server_seq + 1}|ACK:{server_seq + 1}|FLAGS:ACK"
                    udp_socket.sendto(ack_message.encode(), (HOST, UDP_PORT))
                    print(f"[HANDSHAKE] Sent ACK: {ack_message}")

                    # Wait for server confirmation
                    udp_socket.settimeout(timeout)
                    data, addr = udp_socket.recvfrom(1024)
                    if data.decode() == "HANDSHAKE_COMPLETE":
                        print("[HANDSHAKE] Handshake complete!")
                        return True

        except socket.timeout:
            print("[HANDSHAKE] Timeout, retransmitting...")
            retransmissions += 1

    print("[HANDSHAKE] Handshake failed after maximum retransmissions.")
    return False


# OBTENCAO DE MÉTRICAS:

# PING
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
			if "rtt" in line or "min/avg/max" in line:
				avg_rtt = float(line.split("/")[4]) # RTT medio (ms)
				return avg_rtt
	except Exception as e:
		print(f"Erro ao obter ping: {e}")

	return None


# IPERF():
def get_iperf():
	try:
		result = subprocess.run(
			["iperf3", "-c", HOST, "-t", "10"],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			timeout=15
		)

		for line in result.stdout.split("\n"):
			if "sender" in line and "Mbits/sec" in line:
				bandwidth = float(line.split()[-2])
				return bandwidth

	except Exception as e:
		print(f"Erro ao obter iperf: {e}")

	return None


# AGENT PROGRAM:
try:
    print(f"My agent id is: {AGENT_ID}")
    last_sent_time = time.time()

    # Realiza o handshake UDP antes de iniciar a conexão TCP
    if not udp_handshake():
        raise ConnectionError("[HANDSHAKE] Connection with the server failed!")
    
    print("[HANDSHAKE] Connection established with server!")
    
    # Estabelece a conexão TCP após o handshake
    tcp_socket.connect((HOST, TCP_PORT))
    print("[TCP] Connected to the server.")


    # Loop principal do agente
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)  # Obtem uso de CPU
        ping_value = get_ping()  # Obtem o RTT médio via ping
        iperf_value = get_iperf()  # Obtem a largura de banda via iperf

        # Verifica limites e envia alertas se necessário
        if cpu_usage > CPU_THRESHOLD:
            alert_message = f"ALERT:{AGENT_ID}: CPU THRESHOLD EXCEEDED: {cpu_usage}%"
            tcp_socket.sendall(alert_message.encode())
            print(f"[ALERT] Sent: {alert_message}")

        if ping_value and ping_value > PING_THRESHOLD:
            alert_message = f"ALERT:{AGENT_ID}: PING THRESHOLD EXCEEDED: {ping_value}ms"
            tcp_socket.sendall(alert_message.encode())
            print(f"[ALERT] Sent: {alert_message}")

        # Envia métricas regulares a cada SEND_INTERVAL segundos
        if time.time() - last_sent_time >= SEND_INTERVAL:
            update_message = f"METRIC:{AGENT_ID}: CPU: {cpu_usage}%"
            udp_socket.sendto(update_message.encode(), (HOST, UDP_PORT))
            print(f"[METRIC] Sent: {update_message}")
            last_sent_time = time.time()

except KeyboardInterrupt:
    print("Agent interrupted manually.")
    
finally:
    udp_socket.close()
    tcp_socket.close()
