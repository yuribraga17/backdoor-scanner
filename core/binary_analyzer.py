import subprocess

def analyze_binary(file_path):
    """
    Analisa um binário em busca de backdoors.
    """
    result = subprocess.run(["radare2", "-c", "aaa", file_path], capture_output=True, text=True)
    return result.stdout