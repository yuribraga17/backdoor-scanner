import subprocess

def check_dependencies():
    """
    Verifica vulnerabilidades em dependências externas.
    """
    result = subprocess.run(["pip-audit"], capture_output=True, text=True)
    return result.stdout