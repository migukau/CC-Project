import socket
import threading
import json 

def udp_server():
    server_address = ('0.0.0.0', 12345)  # Porta para métricas
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(server_address)
    print("NMS_Server (UDP) escutando por métricas...")

    while True:
        data, address = udp_socket.recvfrom(4096)
        print(f"[Métrica Recebida] {data.decode()} de {address}")

def tcp_server():
    server_address = ('0.0.0.0', 54321)  # Porta para alertas
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(server_address)
    tcp_socket.listen(5)
    print("NMS_Server (TCP) escutando por alertas...")

    while True:
        connection, client_address = tcp_socket.accept()
        try:
            print(f"[Conexão TCP] {client_address} conectou-se")
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                print(f"[Alerta Recebido] {data.decode()}")
        finally:
            connection.close()

# Função para carregar e interpretar o arquivo JSON
def load_task_file(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"Arquivo JSON {file_path} não encontrado.")
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar o arquivo JSON: {e}")
        return None

# Função para atribuir tarefas aos agentes com base no arquivo JSON
def assign_tasks(task_data):
    if not task_data:
        return

    for task in task_data['tasks']:
        agent = task['agent']
        metric = task['metric']
        limit = task['limit']
        print(f"Atribuindo tarefa ao agente {agent}: Monitorar {metric} com limite de {limit}%")
        send_task_to_agent(agent, metric, limit)

# Função para enviar tarefas ao agente (usando UDP como exemplo)
def send_task_to_agent(agent_ip, metric, limit):
    message = f"Tarefa: Monitorar {metric}, Limite: {limit}%"
    server_address = (agent_ip, 12345)  # Porta do agente UDP (ajustar conforme necessário)
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.sendto(message.encode(), server_address)
        print(f"[Tarefa Enviada] {message} para o agente {agent_ip}")
    except Exception as e:
        print(f"Erro ao enviar tarefa para o agente {agent_ip}: {e}")
    finally:
        udp_socket.close()

# Função para carregar e interpretar o arquivo JSON
def parse_task_file(file_path):
    # Carrega o conteúdo do arquivo JSON
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    # Extrai informações principais
    task_id = data.get("task_id")
    frequency = data.get("frequency")
    
    print(f"Task ID: {task_id}")
    print(f"Frequency: {frequency} seconds")
    
    # Itera pelos dispositivos listados
    devices = data.get("devices", [])
    for device in devices:
        device_id = device.get("device_id") #agent_id
        device_metrics = device.get("device_metrics", {}) #
        link_metrics = device.get("link_metrics", {})
        alertflow_conditions = device.get("alertflow_conditions", {})
        
        print(f"\nDevice ID: {device_id}")
        
        # Device metrics
        cpu_usage = device_metrics.get("cpu_usage")
        ram_usage = device_metrics.get("ram_usage")
        #interface_stats = device_metrics.get("interface_stats", [])
        
        print(f"  CPU Usage Monitoring: {cpu_usage}")
        print(f"  RAM Usage Monitoring: {ram_usage}")
       # print(f"  Interface Stats: {', '.join(interface_stats) if interface_stats else 'None'}")
        
        # Link metrics
        for metric_name, metric in link_metrics.items():
            print(f"  Link Metric: {metric_name.capitalize()}")
            if metric_name == "bandwidth":
                iperf_role = metric.get("iperf_role")
                server_ip = metric.get("server_ip")
                duration = metric.get("duration")
                transport = metric.get("transport")
                link_frequency = metric.get("frequency")
                
                print(f"    - Role: {iperf_role}")
                print(f"    - Server IP: {server_ip}")
                print(f"    - Duration: {duration} seconds")
                print(f"    - Transport: {transport}")
                print(f"    - Frequency: {link_frequency} seconds")
                
            elif metric_name in ["jitter", "packet_loss"]:
                enabled = metric.get("enabled")
                iperf_role = metric.get("iperf_role")
                server_ip = metric.get("server_ip")
                link_frequency = metric.get("frequency")
                
                print(f"    - Enabled: {enabled}")
                print(f"    - Role: {iperf_role}")
                print(f"    - Server IP: {server_ip}")
                print(f"    - Frequency: {link_frequency} seconds")
                
            elif metric_name == "latency":
                ping_destination = metric.get("ping_destination")
                count = metric.get("count")
                link_frequency = metric.get("frequency")
                
                print(f"    - Ping Destination: {ping_destination}")
                print(f"    - Count: {count}")
                print(f"    - Frequency: {link_frequency} seconds")
        
        # Alertflow conditions
        print("  Alertflow Conditions:")
        cpu_alert = alertflow_conditions.get("cpu_usage")
        ram_alert = alertflow_conditions.get("ram_usage")
        interface_alerts = alertflow_conditions.get("interface_stats", {})
        packet_loss_alert = alertflow_conditions.get("packet_loss")
        jitter_alert = alertflow_conditions.get("jitter")
        
        print(f"    - CPU Usage Alert if above: {cpu_alert}%")
        print(f"    - RAM Usage Alert if above: {ram_alert}%")
        for interface, threshold in interface_alerts.items():
            print(f"    - {interface} Bandwidth Alert if above: {threshold} Mbps")
        print(f"    - Packet Loss Alert if above: {packet_loss_alert}%")
        print(f"    - Jitter Alert if above: {jitter_alert} ms")
    
    print("\nParsing completed.")
# Executa as duas funções de servidor (UDP e TCP) em threads separadas
# Integração do módulo de JSON com o servidor
if __name__ == "__main__":
    # Carregar e atribuir tarefas aos agentes
    json_file = "config.json"
    task_data = load_task_file(json_file)
    assign_tasks(task_data)

    udp_thread = threading.Thread(target=udp_server)
    tcp_thread = threading.Thread(target=tcp_server)

    parse_task_file(json_file)
    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()
