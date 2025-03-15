import os
import re
import json
import hashlib
import requests
import smtplib
import sqlite3
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from email.mime.text import MIMEText
from datetime import datetime

# Configurações
LOG_FILE = "scan_report.html"
ERROR_LOG = "error_log.html"
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt", ".py", ".php", ".html"]
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1349765035294982154/sr-g1UT64_OIFhmC0OGSCWjb5ZFyhIM5Hu84fDB2D4ox4Jr9uae-JL1KyWrVZaoKRYv_"
AUTHOR = "Yuri Braga"
GITHUB_PROFILE = "https://github.com/yuribraga17"
AVATAR_URL = "https://i.imgur.com/Io94kCm.jpeg"
VIRUSTOTAL_API_KEY = "d2452a7113afca74cdb07ad946fd081498c3301ab076a9760b62ef26ee29dfa2"

# Lista de hashes maliciosos conhecidos (exemplo)
MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

# Lista de padrões suspeitos (backdoor strings)
PATTERNS = [
    r"cipher-panel",
    r"Enchanced_Tabs",
    r"helperServer",
    r"ketamin\.cc",
    r"\x63\x69\x70\x68\x65\x72\x2d\x70\x61\x6e\x65\x6c\x2e\x6d\x65",
    r"\x6b\x65\x74\x61\x6d\x69\x6e\x2e\x63\x63",
    r"MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR",
    r"yegScgjjdqJxajjEciirKPjVTDLrLPgTortCuhkITTKSrEAwzAFYeYHJbtwOKqgDNXIovf",
    r"zvoUEAhbeuIUspwvFMqmZmxJcYQKDGlgCXvXHWcHHsOnttuqJHvRfxExcVuuenaPYaUDoS",
    r"fzjrcOAVtqFkaAxWywpiwLojRAXpFyaqxYYWyYjryAVzoBtJpfHIgxdzkaVCestbWKSvuw",
    r"QZqzNpxLlcExGPKnpVHAnCEeHRhcalmKugKhNKxmiLrkAtHsqlfRcwipMtdpyUYcFwOBEc",
    r"UhBYcKlieqsXIFAeZKjhUPjCBVhjsiAePUBrdJCJWReeDOEmeJppTaDEpGFQQVzLFwZLSl",
    r"zmpEqNeFCrmHDfAeEqpnhacxRABCXWPBITvcRaUnagoDzplRqrbUTMtArqBkLYOcuFjPwb",
    r"yNFQacnrOUrYkjgbmlNiQASimwTmGijAqrsAnImrFdzlKAOiMsBHfsUkTSXQbXunaCtEdr",
    r"wPYBfzhUSeDCaVfBScIzFvHbIfnIqgJvCcxlXqfQydKpbjqvYwVHUAcYchsyrvvvFsKeUc",
    r"\x52\x65\x67\x69\x73\x74\x65\x72\x4e\x65\x74\x45\x76\x65\x6e\x74",
    r"\x52\x65\x67",
    r"tzCAyogCumAjjWRyUfjqMFmQuSCatkjdngxSidpiGRYBiqosQSJvmTWMhfExvRRkQUxXPf",
    r"\x50\x65\x72",
    r"Enchanced_Tabs"
]

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

# Função para detectar ofuscação
def detect_obfuscation(content):
    """Detecta ofuscação no código."""
    # Verifica se há strings codificadas em hexadecimal
    hex_pattern = r"\\x[0-9a-fA-F]{2}"
    if re.search(hex_pattern, content):
        return f"[{translate('alert')}] {translate('obfuscation_detected')} (hexadecimal)"

    # Verifica se há strings codificadas em base64
    base64_pattern = r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    if re.search(base64_pattern, content):
        return f"[{translate('alert')}] {translate('obfuscation_detected')} (base64)"

    return None

# Função para analisar comportamento suspeito
def analyze_behavior(content):
    """Analisa o comportamento do código."""
    # Exemplo: Verifica se há chamadas suspeitas de execução de código
    suspicious_calls = ["eval(", "exec(", "system(", "PerformHttpRequest(", "GetConvar("]
    for call in suspicious_calls:
        if call in content:
            return f"[{translate('alert')}] {translate('suspicious_behavior')}: {call}"
    return None

# Função para enviar notificações ao Discord em Embed
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
            print(f"[{translate('error')}] Falha ao enviar mensagem para o Discord: {e}")

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
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .log-entry {{ margin-bottom: 20px; padding: 10px; border-left: 5px solid #ccc; }}
            .error-entry {{ margin-bottom: 20px; padding: 10px; border-left: 5px solid #ff0000; }}
            .footer {{ margin-top: 40px; font-size: 0.9em; color: #666; }}
        </style>
    </head>
    <body>
        <h1>Relatório de Varredura</h1>
        <p><strong>Data e Hora:</strong> {timestamp}</p>
        <p><strong>Resultado:</strong> {"Backdoor encontrado!" if malware_found else "Nenhum backdoor encontrado."}</p>
        <h2>Logs</h2>
    """
    for entry in log_entries:
        html_content += f'<div class="log-entry">{entry}</div>'
    if error_entries:
        html_content += "<h2>Erros</h2>"
        for error in error_entries:
            html_content += f'<div class="error-entry">{error}</div>'
    html_content += f"""
        <div class="footer">
            <p>Autor: {AUTHOR} | Github: <a href="{GITHUB_PROFILE}">{GITHUB_PROFILE}</a></p>
        </div>
    </body>
    </html>
    """
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write(html_content)

# Função para gerar HTML do banco de dados
def generate_db_html():
    """Gera um arquivo HTML para visualizar os resultados do banco de dados."""
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM results")
    rows = cursor.fetchall()
    conn.close()

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Resultados do Banco de Dados</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 10px; border: 1px solid #ccc; text-align: left; }}
            th {{ background-color: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>Resultados do Banco de Dados</h1>
        <table>
            <tr>
                <th>ID</th>
                <th>Arquivo</th>
                <th>Padrão</th>
                <th>Data e Hora</th>
            </tr>
    """
    for row in rows:
        html_content += f"""
            <tr>
                <td>{row[0]}</td>
                <td>{row[1]}</td>
                <td>{row[2]}</td>
                <td>{row[3]}</td>
            </tr>
        """
    html_content += """
        </table>
    </body>
    </html>
    """
    with open("db_results.html", "w", encoding="utf-8") as file:
        file.write(html_content)

# Banco de dados de resultados
def create_database():
    """Cria um banco de dados para armazenar resultados."""
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            pattern TEXT,
            timestamp DATETIME
        )
    """)
    conn.commit()
    conn.close()

def save_result(file_path, pattern):
    """Salva um resultado no banco de dados."""
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO results (file_path, pattern, timestamp)
        VALUES (?, ?, datetime('now'))
    """, (file_path, pattern))
    conn.commit()
    conn.close()

# Função principal de escaneamento
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
            
            # Verificação com VirusTotal
            virustotal_result = check_hash_with_virustotal(file_hash)
            if virustotal_result:
                log_entries.append(virustotal_result)
            
            # Detecção de ofuscação
            obfuscation_result = detect_obfuscation(content)
            if obfuscation_result:
                log_entries.append(obfuscation_result)
            
            # Análise de comportamento
            behavior_result = analyze_behavior(content)
            if behavior_result:
                log_entries.append(behavior_result)
            
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
                    save_result(file_path, pattern)
                    send_to_discord(file_path, line, pattern, True)
    except Exception as e:
        return f"[{translate('error')}] Falha ao ler o arquivo {file_path}: {e}"
    return log_entries

# Função para escanear múltiplos arquivos
def scan_files(directory, progress_bar, log_area, root):
    """Escaneia todos os arquivos em um diretório."""
    malware_found = False
    log_entries = []
    error_entries = []

    # Contador de arquivos escaneados
    total_files = 0
    scanned_files = 0

    # Contar o número total de arquivos
    for root_dir, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                total_files += 1

    log_area.insert(tk.END, f"[INFO] Total de arquivos a serem escaneados: {total_files}\n")

    # Escanear os arquivos
    for root_dir, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                file_path = os.path.join(root_dir, file)
                scanned_files += 1
                log_area.insert(tk.END, f"[INFO] Escaneando arquivo {scanned_files}/{total_files}: {file_path}\n")
                progress_bar["value"] = (scanned_files / total_files) * 100
                root.update_idletasks()  # Atualiza a barra de progresso

                result = scan_file(file_path)
                if isinstance(result, list):
                    log_entries.extend(result)
                    if result:
                        malware_found = True
                else:
                    error_entries.append(result)

    # Salva os logs
    generate_html_report(log_entries, error_entries, malware_found)

    if error_entries:
        with open(ERROR_LOG, "w", encoding="utf-8") as error_log:
            error_log.write("[ERROS] Ocorreram erros durante a varredura:\n")
            error_log.write("\n".join(error_entries))

    return malware_found

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
            malware_found = scan_files(directory, progress_bar, log_area, root)  # Passando root como argumento
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
    create_database()
    create_gui()

if __name__ == "__main__":
    main()