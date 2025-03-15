# notifications/discord_notifier.py
import requests
from datetime import datetime

def send_to_discord(file_path, line, pattern, malware_found, webhook_url, author, github_profile, avatar_url):
    """
    Envia uma notificação ao Discord em formato Embed.

    Args:
        file_path (str): Caminho do arquivo escaneado.
        line (str): Linha do código onde o padrão foi encontrado.
        pattern (str): Padrão suspeito detectado.
        malware_found (bool): Indica se malware foi encontrado.
        webhook_url (str): URL do webhook do Discord.
        author (str): Nome do autor.
        github_profile (str): Link do GitHub do autor.
        avatar_url (str): URL do avatar do bot no Discord.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    embed = {
        "title": "Backdoor Scanner",
        "description": "Resultado da varredura",
        "color": 0xFF0000 if malware_found else 0x00FF00,  # Vermelho se malware for encontrado, verde caso contrário
        "fields": [
            {"name": "Arquivo", "value": file_path, "inline": False},
            {"name": "Linha", "value": line, "inline": False},
            {"name": "Padrão Detectado", "value": pattern, "inline": False},
            {"name": "Status", "value": "Backdoor encontrado!" if malware_found else "Nenhum backdoor encontrado.", "inline": False},
            {"name": "Data e Hora", "value": timestamp, "inline": False}
        ],
        "footer": {"text": f"Autor: {author} | Github: {github_profile}"}
    }
    message = {
        "username": "Backdoor Scanner",
        "avatar_url": avatar_url,
        "embeds": [embed]
    }
    try:
        requests.post(webhook_url, json=message)
    except Exception as e:
        print(f"[ERRO] Falha ao enviar mensagem para o Discord: {e}")