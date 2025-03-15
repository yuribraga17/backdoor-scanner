# core/detector.py
import re

def detect_patterns(content, patterns):
    results = []
    for pattern in patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            line = content.splitlines()[content[:match.start()].count('\n')]
            results.append((pattern, line))
    return results