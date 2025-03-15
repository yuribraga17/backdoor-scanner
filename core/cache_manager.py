import json
import os
from datetime import datetime

def load_cache():
    """
    Carrega o cache de resultados.
    """
    try:
        with open("cache.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_cache(cache):
    """
    Salva o cache de resultados.
    """
    with open("cache.json", "w") as f:
        json.dump(cache, f)

def is_file_modified(file_path, cache):
    """
    Verifica se um arquivo foi modificado desde a última análise.
    """
    file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    return cache.get(file_path) != file_hash