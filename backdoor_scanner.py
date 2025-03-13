import os
import re
import json
import requests

# Configurações
LOG_FILE = "malware_log.txt"
ERROR_LOG = "error_log.txt"
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt"]
DISCORD_WEBHOOK = "WEBHOOK_LINK"
AUTHOR = "Yuri Braga"
GITHUB_PROFILE = "https://github.com/yuribraga17"
AVATAR_URL = "https://i.imgur.com/Io94kCm.jpeg"

# Padrões suspeitos, mas agora evitando falsos positivos
PATTERNS = [
    r"PerformHttpRequest\s*\(",
    r"task\s*\(",
    r"assert\s*\(\s*load\s*\(",
    r"pcall\s*\(",
    r"RunString\s*\(",
    r"Citizen\.InvokeNative\s*\(",
    r"LoadResourceFile\s*\(",
    r"RegisterServerEvent\s*\(",
    r"ExecuteCommand\s*\(",
    r"require\(\s*[\"'`]socket[\"'`]\s*\)",
    r"GetPlayerIdentifiers\s*\(",
    r"base64\.decode\s*\(",
    r"Buffer\.from\s*\(",
    r"pastebin\.com\/raw",
    r"1ox\.org",
    r"ls2\.org",
    r"http:\/\/l00x\.org",
    r"warden-panel\.me"
]

# Exceções para evitar falsos positivos
EXCEPTIONS = [
    r"https:\/\/github\.com\/citizenfx\/cfx-server-data",
    r"document\.createElementNS\(\"http:\/\/www\.w3\.org\/2000\/svg\",", 
    r"cfx-default",
    r"\.png$",
    r"\.svg$",
    r"font-src",
    r"github\.com\/citizenfx"
]

def scan_files(directory):
    """Escaneia os arquivos em busca de padrões suspeitos."""
    malware_found = False
    log_entries = []
    error_entries = []

    for root, _, files in os.walk(directory):
        if "cfx-default" in root:  # Ignorar a pasta cfx-default
            continue
        
        for file in files:
            if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for line_num, line in enumerate(lines, 1):
                            if any(re.search(exc, line) for exc in EXCEPTIONS):
                                continue  # Pular se for um falso positivo conhecido
                            
                            for pattern in PATTERNS:
                                if re.search(pattern, line):
                                    log_entry = f"[ALERTA] Padrão suspeito encontrado: {pattern} no arquivo {file_path} (Linha {line_num})\nCódigo suspeito: {line.strip()}"
                                    log_entries.append(log_entry)
                                    malware_found = True
                                    send_to_discord(file_path, line_num, line.strip(), pattern)
                except Exception as e:
                    error_entries.append(f"[ERRO] Falha ao ler o arquivo {file_path}: {e}")

    # Salva os logs
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("[MalScanner] Iniciando varredura de backdoors...\n")
        log.write("------------------------------------\n")
        log.write("\n".join(log_entries))
        log.write("\n------------------------------------\n")
        log.write(f"[MalScanner] Varredura concluída.\n\nAutor: {AUTHOR}\nGithub: {GITHUB_PROFILE}\n")

    if error_entries:
        with open(ERROR_LOG, "w", encoding="utf-8") as error_log:
            error_log.write("[ERROS] Ocorreram erros durante a varredura:\n")
            error_log.write("\n".join(error_entries))

    return malware_found

def send_to_discord(file_path, line_num, line, pattern):
    """Envia uma notificação para o Discord via Webhook."""
    payload = {
        "username": "Backdoor Scanner",
        "avatar_url": AVATAR_URL,
        "embeds": [
            {
                "title": "🚨 POSSÍVEL BACKDOOR DETECTADO! 🚨",
                "color": 16711680,
                "fields": [
                    {"name": "Arquivo", "value": file_path, "inline": False},
                    {"name": "Linha", "value": str(line_num), "inline": True},
                    {"name": "Código suspeito", "value": f"```{line}```", "inline": False},
                    {"name": "Padrão Detectado", "value": pattern, "inline": False}
                ],
                "footer": {
                    "text": f"Autor: {AUTHOR} | Github: {GITHUB_PROFILE}",
                    "icon_url": AVATAR_URL
                }
            }
        ]
    }
    requests.post(DISCORD_WEBHOOK, json=payload)

def main():
    # Diretório atual (onde o script está sendo executado)
    current_directory = os.getcwd()
    print(f"[INFO] Escaneando o diretório: {current_directory}")

    print("[INFO] Iniciando varredura de backdoors...")
    malware_found = scan_files(current_directory)

    if malware_found:
        print("[ALERTA] 🚨 Backdoor encontrado! Verifique 'malware_log.txt' para detalhes.")
    else:
        print("[SEGURO] ✅ Nenhum malware encontrado.")

    print(f"[INFO] Verifique os arquivos de log: {LOG_FILE} e {ERROR_LOG}")
    print(f"[INFO] Script desenvolvido por {AUTHOR} | Github: {GITHUB_PROFILE}")

if __name__ == "__main__":
    main()
