import re
import base64

def detect_obfuscation(content):
    """
    Detecta técnicas de ofuscação no código.
    Retorna uma lista de alertas no formato [mensagem, linha, código].
    """
    alerts = []

    # Verifica strings codificadas em hexadecimal
    hex_pattern = r"\\x[0-9a-fA-F]{2}"
    hex_matches = re.finditer(hex_pattern, content)
    for match in hex_matches:
        line = content[:match.start()].count('\n') + 1
        code = content.splitlines()[line - 1].strip()
        alerts.append((
            "[ALERT] Obfuscation detected (hexadecimal)",
            line,
            code
        ))

    # Verifica strings codificadas em Base64
    base64_pattern = r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    base64_matches = re.finditer(base64_pattern, content)
    for match in base64_matches:
        line = content[:match.start()].count('\n') + 1
        code = content.splitlines()[line - 1].strip()
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8')
            alerts.append((
                f"[ALERT] Obfuscation detected (Base64): {decoded}",
                line,
                code
            ))
        except:
            pass

    # Verifica strings codificadas em Unicode
    unicode_pattern = r"\\u[0-9a-fA-F]{4}"
    unicode_matches = re.finditer(unicode_pattern, content)
    for match in unicode_matches:
        line = content[:match.start()].count('\n') + 1
        code = content.splitlines()[line - 1].strip()
        alerts.append((
            "[ALERT] Obfuscation detected (Unicode)",
            line,
            code
        ))

    # Verifica técnicas de packing
    packing_patterns = [
        r"eval\(.*\)",  # Uso de eval para desempacotar
        r"exec\(.*\)",  # Uso de exec para desempacotar
        r"Function\(",  # Uso de Function em JavaScript
        r"unescape\(",  # Uso de unescape em JavaScript
    ]
    for pattern in packing_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            line = content[:match.start()].count('\n') + 1
            code = content.splitlines()[line - 1].strip()
            alerts.append((
                f"[ALERT] Obfuscation detected (packing): {pattern}",
                line,
                code
            ))

    return alerts