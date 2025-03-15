from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from config import SLACK_API_TOKEN, SLACK_CHANNEL

def send_to_slack(message):
    """
    Envia uma notificação para o Slack.
    """
    client = WebClient(token=SLACK_API_TOKEN)
    try:
        response = client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message
        )
        return response
    except SlackApiError as e:
        print(f"[ERROR] Falha ao enviar mensagem para o Slack: {e}")
        return None