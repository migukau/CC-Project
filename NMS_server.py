import socket
import threading

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


# Executa as duas funções de servidor (UDP e TCP) em threads separadas
# Integração do módulo de JSON com o servidor
if __name__ == "__main__":
    # Carregar e atribuir tarefas aos agentes
    json_file = "config.json"
    task_data = load_task_file(json_file)
    assign_tasks(task_data)

    udp_thread = threading.Thread(target=udp_server)
    tcp_thread = threading.Thread(target=tcp_server)

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()
