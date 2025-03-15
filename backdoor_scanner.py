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
LANGUAGE = os.getenv("LANGUAGE", "pt-br")  # Idioma padrão: pt-br
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

# Lista de exceções (padrões que devem ser ignorados)
def load_exceptions():
    """Carrega exceções de um arquivo JSON."""
    try:
        with open("exceptions.json", "r") as f:
            return json.load(f).get("exceptions", [])
    except Exception as e:
        print(f"[ERRO] Falha ao carregar exceções: {e}")
        return []

# Lista de palavras-chave seguras (contexto seguro)
def load_safe_keywords():
    """Carrega palavras-chave seguras de um arquivo JSON."""
    try:
        with open("safe_keywords.json", "r") as f:
            return json.load(f).get("safe_keywords", [])
    except Exception as e:
        print(f"[ERRO] Falha ao carregar palavras-chave seguras: {e}")
        return []

PATTERNS = load_suspicious_patterns()
EXCEPTIONS = load_exceptions()
SAFE_KEYWORDS = load_safe_keywords()

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
    },
    "en": {
        "title": "Backdoor Scanner",
        "select_directory": "Select Directory",
        "scanning": "Scanning...",
        "malware_found": "🚨 Backdoor found! Check 'scan_report.html' for details.",
        "no_malware": "✅ No malware found.",
        "error_directory": "Directory not found.",
        "error_webhook": "Invalid or unconfigured Discord webhook.",
        "alert": "ALERT",
        "error": "ERROR",
        "file_modified": "File modified:",
        "monitoring": "Monitoring directory:",
        "backup_created": "Backup created:",
        "email_sent": "Email sent successfully.",
        "hash_malicious": "Malicious hash detected:",
        "obfuscation_detected": "Obfuscation detected:",
        "suspicious_behavior": "Suspicious behavior detected:",
        "suspicious_pattern": "Suspicious pattern found:",
        "file": "File",
        "line": "Line",
        "code": "Suspicious Code",
        "pattern": "Pattern Detected",
        "footer": f"Author: {AUTHOR} | Github: {GITHUB_PROFILE}",
    }
}

def translate(key):
    """Retorna a mensagem traduzida com base no idioma selecionado."""
    return LOCALIZATION[LANGUAGE].get(key, key)

# Função para enviar notificações ao Discord
def send_to_discord(file_path, line, pattern, malware_found):
    """Envia uma notificação ao Discord em formato Embed."""
    if DISCORD_WEBHOOK:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        embed = {
            "title": translate("title"),
            "description": translate("scanning"),
            "color": 0xFF0000 if malware_found else 0x00FF00,
            "fields": [
                {"name": translate("file"), "value": file_path, "inline": False},
                {"name": translate("line"), "value": line, "inline": False},
                {"name": translate("pattern"), "value": pattern, "inline": False},
                {"name": "Status", "value": translate("malware_found") if malware_found else translate("no_malware"), "inline": False},
                {"name": translate("file_modified"), "value": timestamp, "inline": False}
            ],
            "footer": {"text": translate("footer")}
        }
        message = {
            "username": translate("title"),
            "avatar_url": AVATAR_URL,
            "embeds": [embed]
        }
        try:
            requests.post(DISCORD_WEBHOOK, json=message)
        except Exception as e:
            print(f"[{translate('error')}] Falha ao enviar mensagem para o Discord: {e}")

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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{timestamp}_{os.path.basename(file_path)}"
    backup_path = os.path.join(BACKUP_DIR, file_name)
    shutil.copy(file_path, backup_path)
    return backup_path

# Função para verificar contexto seguro
def is_safe_context(content, pattern):
    """Verifica se o padrão está em um contexto seguro."""
    for keyword in SAFE_KEYWORDS:
        if keyword in content:
            return True
    return False

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
                if pattern in EXCEPTIONS:  # Ignora padrões na lista de exceções
                    continue
                if is_safe_context(content, pattern):  # Ignora padrões em contexto seguro
                    continue
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
                    send_to_discord(file_path, line, pattern, True)  # Envia notificação para o Discord
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
    log_area.insert(tk.END, f"[INFO] {translate('scanning')} {total_files} arquivos...\n")

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

    generate_html_report(log_entries, error_entries, malware_found, total_files, len(log_entries), total_files - len(log_entries))
    if error_entries:
        with open(ERROR_LOG, "w", encoding="utf-8") as error_log:
            error_log.write(f"[{translate('error')}] Ocorreram erros durante a varredura:\n")
            error_log.write("\n".join(error_entries))

    return malware_found

# Função para gerar relatório HTML
def generate_html_report(log_entries, error_entries, malware_found, total_files, suspicious_files, clean_files):
    """Gera um relatório HTML com os resultados da varredura."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write(f"""
        <!DOCTYPE html>
        <html lang="{LANGUAGE}">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{translate('title')}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{
                    background-color: #ffffff;
                    color: #000000;
                }}
                .dark {{
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
                .btn-toggle {{
                    background-color: #007bff;
                    color: #ffffff;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="text-center my-4">{translate('title')}</h1>
                <button class="btn btn-toggle mb-3" onclick="toggleTheme()">Alternar Tema</button>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">{translate('scanning')}</h5>
                        <canvas id="scanChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">{translate('file')}</h5>
                        <div id="logs">
                            {"".join(f'<div class="log-entry">{entry}</div>' for entry in log_entries)}
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">{translate('error')}</h5>
                        <div id="errors">
                            {"".join(f'<div class="error-entry">{error}</div>' for error in error_entries)}
                        </div>
                    </div>
                </div>
                <footer class="text-center mt-4">
                    <p>{translate('footer')}</p>
                </footer>
            </div>
            <script>
                const ctx = document.getElementById('scanChart').getContext('2d');
                const scanChart = new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: ['{translate('file')}', '{translate('suspicious_pattern')}', '{translate('no_malware')}'],
                        datasets: [{{
                            label: '{translate('scanning')}',
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

# Interface gráfica moderna com tema white
def create_gui():
    """Cria uma interface gráfica moderna para o scanner."""
    root = ThemedTk(theme="azure")  # Usa o tema "azure" do ttkthemes (moderno e elegante)
    root.title(translate("title"))
    root.geometry("1000x700")
    root.iconbitmap("icon.ico")  # Adicione um ícone ao aplicativo (opcional)

    # Barra de menu
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    # Menu Arquivo
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label=translate("select_directory"), command=lambda: start_scan())
    file_menu.add_separator()
    file_menu.add_command(label="Sair", command=root.quit)
    menu_bar.add_cascade(label="Arquivo", menu=file_menu)

    # Menu Ajuda
    help_menu = tk.Menu(menu_bar, tearoff=0)
    help_menu.add_command(label="Sobre", command=lambda: messagebox.showinfo("Sobre", f"{translate('title')}\nAutor: {AUTHOR}"))
    menu_bar.add_cascade(label="Ajuda", menu=help_menu)

    # Frame principal
    main_frame = ttk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Área de logs
    log_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=20, font=("Arial", 10))
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
            log_area.insert(tk.END, f"[INFO] {translate('scanning')} {directory}\n")
            malware_found = scan_files_parallel(directory, progress_bar, log_area, root)
            if malware_found:
                messagebox.showwarning(translate("alert"), translate("malware_found"))
            else:
                messagebox.showinfo(translate("alert"), translate("no_malware"))

    start_button = ttk.Button(button_frame, text=translate("select_directory"), command=start_scan)
    start_button.pack(side=tk.LEFT, padx=5)

    exit_button = ttk.Button(button_frame, text="Sair", command=root.quit)
    exit_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

# Função principal
def main():
    create_gui()

if __name__ == "__main__":
    main()