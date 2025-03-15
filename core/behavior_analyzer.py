import subprocess

def analyze_behavior(content):
    """
    Analisa o comportamento do código em busca de ações suspeitas.
    """
    suspicious_calls = ["eval(", "exec(", "system(", "PerformHttpRequest(", "GetConvar("]
    for call in suspicious_calls:
        if call in content:
            return f"[ALERT] Suspicious behavior detected: {call}"
    return None