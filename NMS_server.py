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
    try:
        # Carrega o conteúdo do arquivo JSON
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Erro: Arquivo {file_path} não encontrado.")
        return None
    except json.JSONDecodeError:
        print(f"Erro: O arquivo {file_path} não contém um JSON válido.")
        return None
    except Exception as e:
        print(f"Erro ao ler o arquivo: {str(e)}")
        return None

    # Validação de campos obrigatórios
    required_fields = ["task_id", "frequency", "devices"]
    for field in required_fields:
        if field not in data:
            print(f"Erro: Campo obrigatório '{field}' não encontrado no JSON.")
            return None
    
    # Extrai informações principais
    task_id = data.get("task_id")
    frequency = data.get("frequency")
    
    # Validação de frequency
    if not isinstance(frequency, (int, float)) or frequency <= 0:
        print("Erro: 'frequency' deve ser um número positivo.")
        return None
    
    print(f"Task ID: {task_id}")
    print(f"Frequency: {frequency} seconds")
    
    # Itera pelos dispositivos listados
    devices = data.get("devices", [])
    if not devices:
        print("Aviso: Nenhum dispositivo encontrado no arquivo de tarefas.")
        return None
    
    for device in devices:
        # Validação de campos obrigatórios do dispositivo
        if "device_id" not in device:
            print("Erro: Dispositivo sem 'device_id'")
            continue
            
        device_id = device.get("device_id")
        device_metrics = device.get("device_metrics", {})
        link_metrics = device.get("link_metrics", {})
        alertflow_conditions = device.get("alertflow_conditions", {})
        
        print(f"\nDevice ID: {device_id}")
        
        # Device metrics
        cpu_usage = device_metrics.get("cpu_usage")
        ram_usage = device_metrics.get("ram_usage")
        
        # Validação de métricas
        if cpu_usage is not None and not isinstance(cpu_usage, bool):
            print(f"Aviso: CPU usage para dispositivo {device_id} deve ser boolean")
        if ram_usage is not None and not isinstance(ram_usage, bool):
            print(f"Aviso: RAM usage para dispositivo {device_id} deve ser boolean")
        
        print(f"  CPU Usage Monitoring: {cpu_usage}")
        print(f"  RAM Usage Monitoring: {ram_usage}")
        
        # Link metrics
        for metric_name, metric in link_metrics.items():
            print(f"  Link Metric: {metric_name.capitalize()}")
            if metric_name == "bandwidth":
                required_bandwidth_fields = ["iperf_role", "server_ip", "duration", "transport", "frequency"]
                if not all(field in metric for field in required_bandwidth_fields):
                    print(f"Aviso: Campos obrigatórios ausentes na métrica bandwidth para {device_id}")
                    continue
                    
                iperf_role = metric.get("iperf_role")
                server_ip = metric.get("server_ip")
                duration = metric.get("duration")
                transport = metric.get("transport")
                link_frequency = metric.get("frequency")
                
                # Validação de valores
                if duration <= 0:
                    print(f"Aviso: duration deve ser positivo para {device_id}")
                if transport not in ["tcp", "udp"]:
                    print(f"Aviso: transport deve ser 'tcp' ou 'udp' para {device_id}")
                if link_frequency <= 0:
                    print(f"Aviso: frequency deve ser positivo para {device_id}")
                
                print(f"    - Role: {iperf_role}")
                print(f"    - Server IP: {server_ip}")
                print(f"    - Duration: {duration} seconds")
                print(f"    - Transport: {transport}")
                print(f"    - Frequency: {link_frequency} seconds")
                
            elif metric_name in ["jitter", "packet_loss"]:
                required_fields = ["enabled", "iperf_role", "server_ip", "frequency"]
                if not all(field in metric for field in required_fields):
                    print(f"Aviso: Campos obrigatórios ausentes na métrica {metric_name} para {device_id}")
                    continue
                    
                enabled = metric.get("enabled")
                iperf_role = metric.get("iperf_role")
                server_ip = metric.get("server_ip")
                link_frequency = metric.get("frequency")
                
                # Validação de valores
                if not isinstance(enabled, bool):
                    print(f"Aviso: enabled deve ser boolean para {metric_name} em {device_id}")
                if link_frequency <= 0:
                    print(f"Aviso: frequency deve ser positivo para {metric_name} em {device_id}")
                
                print(f"    - Enabled: {enabled}")
                print(f"    - Role: {iperf_role}")
                print(f"    - Server IP: {server_ip}")
                print(f"    - Frequency: {link_frequency} seconds")
                
            elif metric_name == "latency":
                required_fields = ["ping_destination", "count", "frequency"]
                if not all(field in metric for field in required_fields):
                    print(f"Aviso: Campos obrigatórios ausentes na métrica latency para {device_id}")
                    continue
                    
                ping_destination = metric.get("ping_destination")
                count = metric.get("count")
                link_frequency = metric.get("frequency")
                
                # Validação de valores
                if count <= 0:
                    print(f"Aviso: count deve ser positivo para latency em {device_id}")
                if link_frequency <= 0:
                    print(f"Aviso: frequency deve ser positivo para latency em {device_id}")
                
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
        
        # Validação de alertas
        if cpu_alert is not None and (not isinstance(cpu_alert, (int, float)) or cpu_alert < 0 or cpu_alert > 100):
            print(f"Aviso: CPU alert deve ser uma porcentagem válida (0-100) para {device_id}")
        if ram_alert is not None and (not isinstance(ram_alert, (int, float)) or ram_alert < 0 or ram_alert > 100):
            print(f"Aviso: RAM alert deve ser uma porcentagem válida (0-100) para {device_id}")
        if packet_loss_alert is not None and (not isinstance(packet_loss_alert, (int, float)) or packet_loss_alert < 0 or packet_loss_alert > 100):
            print(f"Aviso: Packet loss alert deve ser uma porcentagem válida (0-100) para {device_id}")
        if jitter_alert is not None and (not isinstance(jitter_alert, (int, float)) or jitter_alert < 0):
            print(f"Aviso: Jitter alert deve ser um valor positivo para {device_id}")
        
        print(f"    - CPU Usage Alert if above: {cpu_alert}%")
        print(f"    - RAM Usage Alert if above: {ram_alert}%")
        for interface, threshold in interface_alerts.items():
            if not isinstance(threshold, (int, float)) or threshold < 0:
                print(f"Aviso: Interface alert threshold deve ser um valor positivo para {interface} em {device_id}")
            print(f"    - {interface} Bandwidth Alert if above: {threshold} Mbps")
        print(f"    - Packet Loss Alert if above: {packet_loss_alert}%")
        print(f"    - Jitter Alert if above: {jitter_alert} ms")
    
    print("\nParsing completed.")
    return data

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
