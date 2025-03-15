import os
from concurrent.futures import ThreadPoolExecutor
from .scanner import scan_file
from config import SCAN_EXTENSIONS, PATTERNS, MALICIOUS_HASHES, VIRUSTOTAL_API_KEY

def scan_files_parallel(directory):
    """Escaneia todos os arquivos em um diretório de forma paralela."""
    files_to_scan = []

    # Coleta todos os arquivos válidos no diretório e subdiretórios
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                files_to_scan.append(os.path.join(root, file))

    # Escaneia os arquivos em paralelo
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda f: scan_file(f, PATTERNS, MALICIOUS_HASHES, VIRUSTOTAL_API_KEY), files_to_scan))

    return results