import socket
import time
import psutil

# Endereço do NMS_Server para enviar métricas (UDP) e alertas (TCP)
udp_server_address = ('10.0.3.10', 1234)  # IP do servidor, porta 12345 (UDP)
tcp_server_address = ('10.0.3.10', 4321)  # IP do servidor, porta 54321 (TCP)

# Criando sockets
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Socket para UDP
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Socket para TCP

# Função para enviar métricas via UDP
def send_metric(metrics):
    try:
        # Convertendo o dicionário de métricas para uma string
        metric_data = f"cpu_usage={metrics['cpu_usage']}%, memory_usage={metrics['memory_usage']}%, disk_usage={metrics['disk_usage']}%, network_io_sent={metrics['network_io'].bytes_sent}, network_io_recv={metrics['network_io'].bytes_recv}"
        udp_socket.sendto(metric_data.encode(), udp_server_address)
        print(f"[Métricas Enviadas]")
        display_metrics(metrics)
        
    except Exception as e:
        print(f"Erro ao enviar métrica: {e}")

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

#Coleta as metricas do agente
def collect_network_metrics():
    metrics = {
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_io': psutil.net_io_counters()
    }
    return metrics

# Simulando o monitoramento de métricas
def monitor_metrics():
    metrics = collect_network_metrics()
    cpu_usage = metrics['cpu_usage']  # Valor de CPU inicial
    memory_usage = metrics['memory_usage']  # Valor de memória inicial
    disk_usage = metrics['disk_usage']  # Valor de disco inicial
    network_io = metrics['network_io']  # Valor de E/S de rede inicial

    while True:
        # Envia métricas periodicamente via UDP
        send_metric(metrics)
        
        # Verifica se o uso de CPU excede 90% e envia alerta via TCP
        if cpu_usage > 90:
            send_alert()
        
        # Simular o aumento de uso de CPU ao longo do tempo
        cpu_usage += 5
        
        # Pausa de 5 segundos antes de enviar a próxima métrica
        time.sleep(5)

def display_metrics(metrics):
     print("CPU Usage: {}%".format(metrics['cpu_usage']))
     print("Memory Usage: {}%".format(metrics['memory_usage']))
     print("Disk Usage: {}%".format(metrics['disk_usage']))
     print("Network IO: Sent = {} bytes, Received = {} bytes".format(
        metrics['network_io'].bytes_sent, metrics['network_io'].bytes_recv))

# Executa a monitorização das métricas
if __name__ == "__main__":
    monitor_metrics()
