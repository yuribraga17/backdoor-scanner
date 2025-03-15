# security/quarantine_manager.py
import os
import shutil
from datetime import datetime

def quarantine_file(file_path):
    quarantine_dir = "quarantine"
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    quarantine_path = os.path.join(quarantine_dir, f"{os.path.basename(file_path)}.quarantine_{timestamp}")
    shutil.move(file_path, quarantine_path)
    return quarantine_path