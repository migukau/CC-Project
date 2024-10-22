import socket
import time

# Endereço do NMS_Server para enviar métricas (UDP) e alertas (TCP)
udp_server_address = ('10.0.0.2', 12345)  # IP do servidor, porta 12345 (UDP)
tcp_server_address = ('10.0.0.2', 54321)  # IP do servidor, porta 54321 (TCP)

# Criando sockets
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Socket para UDP
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Socket para TCP

# Função para enviar métricas via UDP
def send_metric():
    metric_data = "cpu_usage=75%"  # Exemplo de métrica
    udp_socket.sendto(metric_data.encode(), udp_server_address)
    print(f"[Métrica Enviada] {metric_data}")

# Função para enviar alertas via TCP
def send_alert():
    try:
        tcp_socket.connect(tcp_server_address)  # Conectar ao servidor
        alert_message = "Alerta: CPU ultrapassou 90%"
        tcp_socket.sendall(alert_message.encode())
        print(f"[Alerta Enviado] {alert_message}")
    except Exception as e:
        print(f"Erro ao enviar alerta: {e}")
    finally:
        tcp_socket.close()  # Fechar a conexão TCP

# Simulando o monitoramento de métricas
def monitor_metrics():
    cpu_usage = 75  # Valor de CPU inicial
    while True:
        # Envia métricas periodicamente via UDP
        send_metric()
        
        # Verifica se o uso de CPU excede 90% e envia alerta via TCP
        if cpu_usage > 90:
            send_alert()
        
        # Simular o aumento de uso de CPU ao longo do tempo
        cpu_usage += 5
        
        # Pausa de 5 segundos antes de enviar a próxima métrica
        time.sleep(5)

# Executa a monitorização das métricas
if __name__ == "__main__":
    monitor_metrics()
