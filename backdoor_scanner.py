import os
import re
import json
import hashlib
import requests
import smtplib
import sqlite3
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from email.mime.text import MIMEText
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# Configurações
LOG_FILE = "malware_log.txt"
ERROR_LOG = "error_log.txt"
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt"]
DISCORD_WEBHOOK = "WEBHOOK_LINK"  # Substitua pelo seu webhook do Discord
AUTHOR = "Yuri Braga"
GITHUB_PROFILE = "https://github.com/yuribraga17"
AVATAR_URL = "https://i.imgur.com/Io94kCm.jpeg"
VIRUSTOTAL_API_KEY = "SUA_CHAVE_API_VIRUSTOTAL"  # Obtenha uma chave em https://www.virustotal.com/

# Lista de hashes maliciosos conhecidos (exemplo)
MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

# Dicionários de localização
LOCALIZATION = {
    "pt-br": {
        "title": "Backdoor Scanner",
        "select_directory": "Selecionar Diretório",
        "scanning": "Escaneando...",
        "malware_found": "🚨 Backdoor encontrado! Verifique 'malware_log.txt' para detalhes.",
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
        "malware_found": "🚨 Backdoor found! Check 'malware_log.txt' for details.",
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

# Modelo de machine learning
def train_model():
    """Treina um modelo simples para classificar código."""
    texts = ["malicious code", "safe code", "another malicious example"]
    labels = [1, 0, 1]  # 1 = malicioso, 0 = seguro
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)
    model = RandomForestClassifier()
    model.fit(X, labels)
    return model, vectorizer

def predict_code(model, vectorizer, code):
    """Classifica o código como malicioso ou seguro."""
    X = vectorizer.transform([code])
    return model.predict(X)[0]

# Verificação de hash com VirusTotal
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

# Monitoramento em tempo real
class FileChangeHandler(FileSystemEventHandler):
    """Monitora alterações no sistema de arquivos."""
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[{translate('alert')}] {translate('file_modified')} {event.src_path}")
            scan_file(event.src_path)

def start_monitoring(directory):
    """Inicia o monitoramento de um diretório."""
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()
    print(f"[INFO] {translate('monitoring')} {directory}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Backup e restauração
def create_backup(file_path):
    """Cria um backup do arquivo."""
    backup_dir = "backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    backup_file = os.path.join(backup_dir, f"{os.path.basename(file_path)}_{timestamp}")
    shutil.copy(file_path, backup_file)
    print(f"[INFO] {translate('backup_created')} {backup_file}")
    return backup_file

# Notificações por e-mail
def send_email(subject, body):
    """Envia um e-mail de notificação."""
    sender = "seu_email@gmail.com"
    receiver = "destinatario@gmail.com"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, "sua_senha")
        server.sendmail(sender, receiver, msg.as_string())
    print(f"[INFO] {translate('email_sent')}")

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
                    if not any(re.search(exc, line) for exc in EXCEPTIONS):
                        log_entry = (
                            f"[{translate('alert')}] {translate('suspicious_pattern')}: {pattern}\n"
                            f"{translate('file')}: {file_path}\n"
                            f"{translate('line')}: {content[:match.start()].count('\n') + 1}\n"
                            f"{translate('code')}: {line.strip()}\n"
                        )
                        log_entries.append(log_entry)
                        save_result(file_path, pattern)
                        send_to_discord(file_path, line, pattern)
    except Exception as e:
        return f"[{translate('error')}] Falha ao ler o arquivo {file_path}: {e}"
    return log_entries

# Função principal
def main():
    create_database()
    model, vectorizer = train_model()
    
    # Interface gráfica
    root = tk.Tk()
    root.title(translate("title"))
    tk.Button(root, text=translate("select_directory"), command=lambda: start_monitoring(filedialog.askdirectory())).pack()
    root.mainloop()

if __name__ == "__main__":
    main()