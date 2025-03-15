import shutil
from datetime import datetime

def create_backup(file_path):
    """
    Cria um backup do arquivo com um timestamp.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{file_path}.backup_{timestamp}"
    shutil.copy(file_path, backup_path)
    return backup_path