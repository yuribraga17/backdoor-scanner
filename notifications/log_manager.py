# notifications/log_manager.py
from datetime import datetime
from reports.html_report import generate_html_report  # Importação para gerar o log de erros em HTML

def log_error(error_message, author, github_profile):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    error_entry = f"[{timestamp}] ERROR: {error_message}"
    
    # Salvar o erro no arquivo error_log.html
    with open("error_log.html", "a", encoding="utf-8") as error_log:
        error_log.write(f'<div class="error-entry">{error_entry}</div>\n')

def log_activity(activity_message, log_file="activity_log.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] INFO: {activity_message}\n")