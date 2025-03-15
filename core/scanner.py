import os
import re
import hashlib
from .detector import detect_patterns
from .hash_checker import check_hash_with_virustotal
from .obfuscation_detector import detect_obfuscation
from .behavior_analyzer import analyze_behavior
from .database import save_result
from .utils import translate
from config import (
    VIRUSTOTAL_API_KEY,
    MALICIOUS_HASHES,
    PATTERNS,
    SCAN_EXTENSIONS,
    ERROR_LOG,
    DISCORD_WEBHOOK,
    DISCORD_AVATAR_URL,
    DISCORD_AUTHOR,
    DISCORD_GITHUB_PROFILE,
)
from notifications.discord_notifier import send_to_discord
from notifications.log_manager import log_error

def scan_file(file_path, patterns, malicious_hashes, virustotal_api_key):
    """Escaneia um arquivo em busca de padrões suspeitos."""
    log_entries = []
    try:
        # Verifica se o arquivo existe
        if not os.path.exists(file_path):
            return [f"[{translate('error')}] Arquivo não encontrado: {file_path}"]

        # Verifica permissões de leitura
        if not os.access(file_path, os.R_OK):
            return [f"[{translate('error')}] Permissão negada para ler o arquivo: {file_path}"]

        # Verifica se o arquivo está vazio
        if os.path.getsize(file_path) == 0:
            return [f"[{translate('warning')}] Arquivo vazio: {file_path}"]

        # Lê o conteúdo do arquivo
        with open(file_path, "rb") as f:
            content = f.read().decode("utf-8", errors="ignore")

        # Verificação de hash
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        if file_hash in malicious_hashes:
            log_entries.append(f"[{translate('alert')}] {translate('hash_malicious')} {file_hash} {translate('file')} {file_path}")

        # Verificação com VirusTotal
        virustotal_result = check_hash_with_virustotal(file_hash, virustotal_api_key)
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
        for pattern in patterns:
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
                send_to_discord(
                    file_path=file_path,
                    line=line,
                    pattern=pattern,
                    malware_found=True,
                    webhook_url=DISCORD_WEBHOOK,
                    author=DISCORD_AUTHOR,
                    github_profile=DISCORD_GITHUB_PROFILE,
                    avatar_url=DISCORD_AVATAR_URL,
                )
    except PermissionError as e:
        error_message = f"[{translate('error')}] Permissão negada ao acessar o arquivo {file_path}: {str(e)}"
        log_error(error_message, author=DISCORD_AUTHOR, github_profile=DISCORD_GITHUB_PROFILE)
        return [error_message]
    except Exception as e:
        error_message = f"[{translate('error')}] Falha ao processar o arquivo {file_path}: {str(e)}"
        log_error(error_message, author=DISCORD_AUTHOR, github_profile=DISCORD_GITHUB_PROFILE)
        return [error_message]
    return log_entries