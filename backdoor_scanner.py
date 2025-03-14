import os
import re
import json
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor

# Configurações
LOG_FILE = "malware_log.txt"
ERROR_LOG = "error_log.txt"
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt"]
DISCORD_WEBHOOK = "WEBHOOK_LINK"
AUTHOR = "Yuri Braga"
GITHUB_PROFILE = "https://github.com/yuribraga17"
AVATAR_URL = "https://i.imgur.com/Io94kCm.jpeg"

# Lista de hashes maliciosos conhecidos (exemplo)
MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

# Padrões suspeitos
PATTERNS = [
    r"PerformHttpRequest\s*\(\s*[\"'`](https?:\/\/[^\s\"'`]+)[\"'`]",
    r"task\s*\(\s*[\"'`](https?:\/\/[^\s\"'`]+)[\"'`]",
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
    r"warden-panel\.me",
    r"fetch\s*\(",
    r"SendNUIMessage\s*\(",
    r"SetResourceKvp\s*\(",
    r"GetResourceKvp\s*\(",
    r"os\.execute\s*\(",
    r"io\.popen\s*\(",
    r"loadstring\s*\(",
    r"debug\.setmetatable\s*\(",
    r"string\.reverse\s*\(",
    r"load\s*\(",
    r"require\(\s*[\"'`]crypto[\"'`]\s*\)",
]

# Exceções para evitar falsos positivos
EXCEPTIONS = [
    r"https:\/\/github\.com\/citizenfx\/cfx-server-data",
    r"document\.createElementNS\(\"http:\/\/www\.w3\.org\/2000\/svg\",",
    r"cfx-default",
    r"\.png$",
    r"\.svg$",
    r"font-src",
    r"github\.com\/citizenfx",
    r"GetCurrentResourceName\s*\(",
    r"SendNUIMessage\s*\(",
    r"json\.decode\s*\(",
    r"os\.clock\s*\(",
    r"ox_",
    r"qbx_",
    r"qb_",
    r"esx_",
]

def calculate_file_hash(file_path):
    """Calcula o hash SHA-256 de um arquivo."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_hash(file_path):
    """Verifica se o hash do arquivo está na lista de hashes maliciosos."""
    file_hash = calculate_file_hash(file_path)
    if file_hash in MALICIOUS_HASHES:
        return f"[ALERTA] Hash malicioso encontrado: {file_hash} no arquivo {file_path}"
    return None

def detect_obfuscation(content):
    """Detecta técnicas comuns de ofuscação."""
    obfuscation_patterns = [
        r"base64\.decode\s*\(",
        r"fromCharCode\s*\(",
        r"string\.reverse\s*\(",
        r"\\x[0-9a-fA-F]{2}",  # Caracteres hexadecimais
        r"eval\s*\(",
    ]
    for pattern in obfuscation_patterns:
        if re.search(pattern, content):
            return f"[ALERTA] Ofuscação detectada: {pattern}"
    return None

def analyze_behavior(content):
    """Analisa o comportamento do código."""
    suspicious_sequences = [
        (r"PerformHttpRequest\s*\(", r"ExecuteCommand\s*\("),
        (r"LoadResourceFile\s*\(", r"RunString\s*\("),
    ]
    for seq in suspicious_sequences:
        if re.search(seq[0], content) and re.search(seq[1], content):
            return f"[ALERTA] Comportamento suspeito detectado: {seq[0]} seguido de {seq[1]}"
    return None

def scan_file(file_path):
    """Escaneia um arquivo em busca de padrões suspeitos."""
    log_entries = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
            # Verificação de hash
            hash_result = check_file_hash(file_path)
            if hash_result:
                log_entries.append(hash_result)
            
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
                            f"[ALERTA] Padrão suspeito encontrado: {pattern}\n"
                            f"Arquivo: {file_path}\n"
                            f"Linha: {content[:match.start()].count('\n') + 1}\n"
                            f"Código suspeito: {line.strip()}\n"
                        )
                        log_entries.append(log_entry)
                        send_to_discord(file_path, line, pattern)
    except Exception as e:
        return f"[ERRO] Falha ao ler o arquivo {file_path}: {e}"
    return log_entries

def scan_files(directory):
    """Escaneia os arquivos em busca de padrões suspeitos."""
    malware_found = False
    log_entries = []
    error_entries = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for root, _, files in os.walk(directory):
            if "cfx-default" in root:
                continue
            for file in files:
                if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                    file_path = os.path.join(root, file)
                    futures.append(executor.submit(scan_file, file_path))

        for future in futures:
            result = future.result()
            if isinstance(result, list):
                log_entries.extend(result)
                if result:
                    malware_found = True
            else:
                error_entries.append(result)

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

def send_to_discord(file_path, line, pattern):
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
                    {"name": "Código suspeito", "value": f"```{line.strip()}```", "inline": False},
                    {"name": "Padrão Detectado", "value": pattern, "inline": False}
                ],
                "footer": {
                    "text": f"Autor: {AUTHOR} | Github: {GITHUB_PROFILE}",
                    "icon_url": AVATAR_URL
                }
            }
        ]
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=payload)
    except Exception as e:
        print(f"[ERRO] Falha ao enviar notificação para o Discord: {e}")

def main():
    # Validação do diretório
    current_directory = os.getcwd()
    if not os.path.exists(current_directory):
        print(f"[ERRO] Diretório não encontrado: {current_directory}")
        return

    print(f"[INFO] Escaneando o diretório: {current_directory}")

    # Validação do webhook do Discord
    if not DISCORD_WEBHOOK or not DISCORD_WEBHOOK.startswith("https://discord.com/api/webhooks/"):
        print("[ERRO] Webhook do Discord inválido ou não configurado.")
        return

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