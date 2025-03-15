# core/utils.py
from config import DISCORD_AUTHOR, DISCORD_GITHUB_PROFILE

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
        "footer": f"Autor: {DISCORD_AUTHOR} | Github: {DISCORD_GITHUB_PROFILE}",
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
        "footer": f"Author: {DISCORD_AUTHOR} | Github: {DISCORD_GITHUB_PROFILE}",
    }
}

def translate(key, language="pt-br"):
    return LOCALIZATION[language].get(key, key)