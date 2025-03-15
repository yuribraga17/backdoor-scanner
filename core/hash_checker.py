# core/hash_checker.py
import requests

def check_hash_with_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                return f"[ALERT] Malicious hash detected: {file_hash}"
    except Exception as e:
        return f"[ERROR] Failed to check hash: {e}"
    return None