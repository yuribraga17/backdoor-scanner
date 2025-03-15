import os
import re
import json
import hashlib
import requests
import sqlite3
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv

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

# Dicionários de localização
LOCALIZATION = {
    "pt-br": {
        "title": "Backdoor Scanner",
        "select_directory": "Selecionar Diretório",
        "scanning": "Escaneando...",
        "malware_found": "🚨 Backdoor encontrado! Verifique 'scan_report.html' para detalhes.",
        "no_malware": "✅ Nenhum malware encontrado.",
        "error_directory": "Diretório não encontrado.",
        "error_webhook": "Webhook do Discord inválido ou não configurado.",
        "alert": "ALERTA",
        "error": "ERRO",
        "file_modified": "Arquivo modificado:",
        "monitoring": "Monitorando diretório:",
        "backup_created": "Backup criado:",
        "email_sent": "E-mail enviado com sucesso.",
        "hash_malicious": "Hash malicioso detectado:",
        "obfuscation_detected": "Ofuscação detectada:",
        "suspicious_behavior": "Comportamento suspeito detectado:",
        "suspicious_pattern": "Padrão suspeito encontrado:",
        "file": "Arquivo",
        "line": "Linha",
        "code": "Código suspeito",
        "pattern": "Padrão Detectado",
        "footer": f"Autor: {AUTHOR} | Github: {GITHUB_PROFILE}",
    }
}

# Idioma padrão
LANGUAGE = "pt-br"

def translate(key):
    """Retorna a mensagem traduzida com base no idioma selecionado."""
    return LOCALIZATION[LANGUAGE].get(key, key)

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
                return f"[{translate('alert')}] {translate('hash_malicious')} {file_hash}"
    except Exception as e:
        return f"[{translate('error')}] Falha ao verificar hash: {e}"
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
                log_entries.append(f"[{translate('alert')}] {translate('hash_malicious')} {file_hash} {translate('file')} {file_path}")
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
                        f"[{translate('alert')}] {translate('suspicious_pattern')}: {pattern}\n"
                        f"{translate('file')}: {file_path}\n"
                        f"{translate('line')}: {content[:match.start()].count('\n') + 1}\n"
                        f"{translate('code')}: {line.strip()}\n"
                    )
                    log_entries.append(log_entry)
                    create_backup(file_path)  # Cria backup do arquivo suspeito
    except Exception as e:
        return f"[{translate('error')}] Falha ao ler o arquivo {file_path}: {e}"
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
                error_entries.append(f"[{translate('error')}] Falha ao escanear o arquivo {file}: {e}")

    generate_html_report(log_entries, error_entries, malware_found)
    if error_entries:
        with open(ERROR_LOG, "w", encoding="utf-8") as error_log:
            error_log.write("[ERROS] Ocorreram erros durante a varredura:\n")
            error_log.write("\n".join(error_entries))

    return malware_found

# Função para gerar relatório HTML
def generate_html_report(log_entries, error_entries, malware_found):
    """Gera um relatório HTML com os resultados da varredura."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório de Varredura</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Chart.js -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { padding: 20px; }
            .card { margin-bottom: 20px; }
            .log-entry { margin-bottom: 10px; padding: 10px; border-left: 5px solid #ccc; }
            .error-entry { margin-bottom: 10px; padding: 10px; border-left: 5px solid #ff0000; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="text-center my-4">Relatório de Varredura</h1>
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
                        <!-- Logs serão inseridos aqui -->
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Erros</h5>
                    <div id="errors">
                        <!-- Erros serão inseridos aqui -->
                    </div>
                </div>
            </div>
            <footer class="text-center mt-4">
                <p>Autor: {{ AUTHOR }} | Github: <a href="{{ GITHUB_PROFILE }}">{{ GITHUB_PROFILE }}</a></p>
            </footer>
        </div>

        <script>
            // Dados para o gráfico
            const ctx = document.getElementById('scanChart').getContext('2d');
            const scanChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Arquivos Escaneados', 'Arquivos Suspeitos', 'Arquivos Limpos'],
                    datasets: [{
                        label: 'Estatísticas de Escaneamento',
                        data: [{{ total_files }}, {{ suspicious_files }}, {{ clean_files }}],
                        backgroundColor: ['#007bff', '#dc3545', '#28a745']
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });

            // Adiciona logs e erros ao HTML
            const logs = document.getElementById('logs');
            const errors = document.getElementById('errors');

            {% for entry in log_entries %}
                logs.innerHTML += `<div class="log-entry">${"{{ entry }}"}</div>`;
            {% endfor %}

            {% for error in error_entries %}
                errors.innerHTML += `<div class="error-entry">${"{{ error }}"}</div>`;
            {% endfor %}
        </script>
    </body>
    </html>
    """
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write(html_content)

# Interface gráfica
def create_gui():
    """Cria uma interface gráfica para o scanner."""
    root = tk.Tk()
    root.title(translate("title"))
    root.geometry("800x600")

    # Frame principal
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Área de logs
    log_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=20)
    log_area.pack(fill=tk.BOTH, expand=True, pady=10)

    # Barra de progresso
    progress_bar = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
    progress_bar.pack(pady=10)

    # Botões
    button_frame = tk.Frame(main_frame)
    button_frame.pack(pady=10)

    def start_scan():
        directory = filedialog.askdirectory()
        if directory:
            log_area.insert(tk.END, f"[INFO] Escaneando diretório: {directory}\n")
            malware_found = scan_files_parallel(directory, progress_bar, log_area, root)
            if malware_found:
                messagebox.showwarning(translate("alert"), translate("malware_found"))
            else:
                messagebox.showinfo(translate("alert"), translate("no_malware"))

    start_button = tk.Button(button_frame, text=translate("select_directory"), command=start_scan)
    start_button.pack(side=tk.LEFT, padx=5)

    exit_button = tk.Button(button_frame, text="Sair", command=root.quit)
    exit_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

# Função principal
def main():
    create_gui()

if __name__ == "__main__":
    main()