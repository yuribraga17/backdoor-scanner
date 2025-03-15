import os
import re
import json
import hashlib
import requests
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv
from ttkthemes import ThemedTk

# Carrega variáveis de ambiente
load_dotenv()

# Configurações
LOG_FILE = "scan_report.html"
ERROR_LOG = "error_log.html"
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt", ".py", ".php", ".html"]
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
AUTHOR = "Yuri Braga"
GITHUB_PROFILE = "https://github.com/yuribraga17"
AVATAR_URL = "https://i.imgur.com/Io94kCm.jpeg"
BACKUP_DIR = "backups"

# Lista de hashes maliciosos conhecidos (exemplo)
MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

# Lista de padrões suspeitos (carregados de um arquivo externo)
def load_suspicious_patterns():
    """Carrega padrões suspeitos de um arquivo JSON."""
    try:
        with open("suspicious_patterns.json", "r") as f:
            return json.load(f).get("patterns", [])
    except Exception as e:
        print(f"[ERRO] Falha ao carregar padrões suspeitos: {e}")
        return []

PATTERNS = load_suspicious_patterns()

# Função para enviar notificações ao Discord
def send_to_discord(file_path, line, pattern, malware_found):
    """Envia uma notificação ao Discord em formato Embed."""
    if DISCORD_WEBHOOK:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        embed = {
            "title": "Backdoor Scanner",
            "description": "Resultado da varredura",
            "color": 0xFF0000 if malware_found else 0x00FF00,
            "fields": [
                {"name": "Arquivo", "value": file_path, "inline": False},
                {"name": "Linha", "value": line, "inline": False},
                {"name": "Padrão Detectado", "value": pattern, "inline": False},
                {"name": "Status", "value": "Backdoor encontrado!" if malware_found else "Nenhum backdoor encontrado.", "inline": False},
                {"name": "Data e Hora", "value": timestamp, "inline": False}
            ],
            "footer": {"text": f"Autor: {AUTHOR} | Github: {GITHUB_PROFILE}"}
        }
        message = {
            "username": "Backdoor Scanner",
            "avatar_url": AVATAR_URL,
            "embeds": [embed]
        }
        try:
            requests.post(DISCORD_WEBHOOK, json=message)
        except Exception as e:
            print(f"[ERRO] Falha ao enviar mensagem para o Discord: {e}")

# Função para verificar hash com VirusTotal
def check_hash_with_virustotal(file_hash):
    """Verifica um hash com a API do VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                return f"[ALERTA] Hash malicioso detectado: {file_hash}"
    except Exception as e:
        return f"[ERRO] Falha ao verificar hash: {e}"
    return None

# Função para criar backup de arquivos suspeitos
def create_backup(file_path):
    """Cria um backup de um arquivo suspeito."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
    shutil.copy(file_path, backup_path)
    return backup_path

# Função para escanear um arquivo
def scan_file(file_path):
    """Escaneia um arquivo em busca de padrões suspeitos."""
    log_entries = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
            # Verificação de hash
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            if file_hash in MALICIOUS_HASHES:
                log_entries.append(f"[ALERTA] Hash malicioso detectado: {file_hash} no arquivo {file_path}")
                create_backup(file_path)  # Cria backup do arquivo suspeito
            
            # Verificação com VirusTotal
            virustotal_result = check_hash_with_virustotal(file_hash)
            if virustotal_result:
                log_entries.append(virustotal_result)
                create_backup(file_path)  # Cria backup do arquivo suspeito
            
            # Verificação de padrões suspeitos
            for pattern in PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line = content.splitlines()[content[:match.start()].count('\n')]
                    log_entry = (
                        f"[ALERTA] Padrão suspeito encontrado: {pattern}\n"
                        f"Arquivo: {file_path}\n"
                        f"Linha: {content[:match.start()].count('\n') + 1}\n"
                        f"Código: {line.strip()}\n"
                    )
                    log_entries.append(log_entry)
                    create_backup(file_path)  # Cria backup do arquivo suspeito
                    send_to_discord(file_path, line, pattern, True)  # Envia notificação para o Discord
    except Exception as e:
        return f"[ERRO] Falha ao ler o arquivo {file_path}: {e}"
    return log_entries

# Função para escanear múltiplos arquivos em paralelo
def scan_files_parallel(directory, progress_bar, log_area, root):
    """Escaneia todos os arquivos em um diretório usando threads."""
    malware_found = False
    log_entries = []
    error_entries = []

    files_to_scan = []
    for root_dir, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                files_to_scan.append(os.path.join(root_dir, file))

    total_files = len(files_to_scan)
    log_area.insert(tk.END, f"[INFO] Total de arquivos a serem escaneados: {total_files}\n")

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_file, file): file for file in files_to_scan}
        for future in as_completed(futures):
            file = futures[future]
            try:
                result = future.result()
                if isinstance(result, list):
                    log_entries.extend(result)
                    if result:
                        malware_found = True
                else:
                    error_entries.append(result)
            except Exception as e:
                error_entries.append(f"[ERRO] Falha ao escanear o arquivo {file}: {e}")

    generate_html_report(log_entries, error_entries, malware_found, total_files, len(log_entries), total_files - len(log_entries))
    if error_entries:
        with open(ERROR_LOG, "w", encoding="utf-8") as error_log:
            error_log.write("[ERROS] Ocorreram erros durante a varredura:\n")
            error_log.write("\n".join(error_entries))

    return malware_found

# Função para gerar relatório HTML
def generate_html_report(log_entries, error_entries, malware_found, total_files, suspicious_files, clean_files):
    """Gera um relatório HTML com os resultados da varredura."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write(f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Varredura</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body.dark {{
                    background-color: #121212;
                    color: #ffffff;
                }}
                .dark .card {{
                    background-color: #1e1e1e;
                    border-color: #333;
                }}
                .dark .log-entry {{
                    background-color: #2c2c2c;
                    border-left: 5px solid #444;
                    color: #ffffff;
                }}
                .dark .error-entry {{
                    background-color: #3c1e1e;
                    border-left: 5px solid #ff4444;
                    color: #ffffff;
                }}
                .dark .btn-toggle {{
                    background-color: #333;
                    color: #ffffff;
                }}
            </style>
        </head>
        <body class="dark">
            <div class="container">
                <h1 class="text-center my-4">Relatório de Varredura</h1>
                <button class="btn btn-toggle mb-3" onclick="toggleTheme()">Alternar Tema</button>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Estatísticas</h5>
                        <canvas id="scanChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Logs</h5>
                        <div id="logs">
                            {"".join(f'<div class="log-entry">{entry}</div>' for entry in log_entries)}
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Erros</h5>
                        <div id="errors">
                            {"".join(f'<div class="error-entry">{error}</div>' for error in error_entries)}
                        </div>
                    </div>
                </div>
                <footer class="text-center mt-4">
                    <p>Autor: {AUTHOR} | Github: <a href="{GITHUB_PROFILE}">{GITHUB_PROFILE}</a></p>
                </footer>
            </div>
            <script>
                const ctx = document.getElementById('scanChart').getContext('2d');
                const scanChart = new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: ['Arquivos Escaneados', 'Arquivos Suspeitos', 'Arquivos Limpos'],
                        datasets: [{{
                            label: 'Estatísticas de Escaneamento',
                            data: [{total_files}, {suspicious_files}, {clean_files}],
                            backgroundColor: ['#007bff', '#dc3545', '#28a745']
                        }}]
                    }},
                    options: {{
                        scales: {{
                            y: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});

                function toggleTheme() {{
                    document.body.classList.toggle('dark');
                }}
            </script>
        </body>
        </html>
        """)

# Interface gráfica moderna com tema dark
def create_gui():
    """Cria uma interface gráfica moderna para o scanner."""
    root = ThemedTk(theme="black")  # Usa o tema "black" do ttkthemes
    root.title("Backdoor Scanner")
    root.geometry("1000x700")

    # Frame principal
    main_frame = ttk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Área de logs
    log_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=20, font=("Arial", 10), background="#1e1e1e", foreground="#ffffff")
    log_area.pack(fill=tk.BOTH, expand=True, pady=10)

    # Barra de progresso
    progress_bar = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=800, mode="determinate")
    progress_bar.pack(pady=10)

    # Botões
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(pady=10)

    def start_scan():
        directory = filedialog.askdirectory()
        if directory:
            log_area.insert(tk.END, f"[INFO] Escaneando diretório: {directory}\n")
            malware_found = scan_files_parallel(directory, progress_bar, log_area, root)
            if malware_found:
                messagebox.showwarning("ALERTA", "Backdoor encontrado! Verifique 'scan_report.html' para detalhes.")
            else:
                messagebox.showinfo("SUCESSO", "Nenhum malware encontrado.")

    start_button = ttk.Button(button_frame, text="Selecionar Diretório", command=start_scan)
    start_button.pack(side=tk.LEFT, padx=5)

    exit_button = ttk.Button(button_frame, text="Sair", command=root.quit)
    exit_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

# Função principal
def main():
    create_gui()

if __name__ == "__main__":
    main()