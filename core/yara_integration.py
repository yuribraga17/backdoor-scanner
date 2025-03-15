import yara

def scan_with_yara(file_path, rules_path):
    """
    Escaneia um arquivo com regras YARA.
    """
    rules = yara.compile(rules_path)
    matches = rules.match(file_path)
    return matches