from dotenv import load_dotenv
import os

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Configurações do Discord
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
DISCORD_AVATAR_URL = os.getenv("DISCORD_AVATAR_URL")
DISCORD_AUTHOR = "Yuri Braga"
DISCORD_GITHUB_PROFILE = "https://github.com/yuribraga17"

# Configurações de E-mail
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_SMTP_USERNAME = os.getenv("EMAIL_SMTP_USERNAME")
EMAIL_SMTP_PASSWORD = os.getenv("EMAIL_SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_SMTP_USERNAME")
EMAIL_TO = "destinatario@gmail.com"

# Lista de extensões de arquivo a serem escaneadas
SCAN_EXTENSIONS = [".lua", ".js", ".json", ".cfg", ".sql", ".txt", ".py", ".php", ".html"]

# Lista de hashes maliciosos conhecidos (exemplo)
MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
}

# Lista de padrões suspeitos (backdoor strings)
PATTERNS = [
    r"cipher-panel",
    r"Enchanced_Tabs",
    r"helperServer",
    r"ketamin\.cc",
    r"\x63\x69\x70\x68\x65\x72\x2d\x70\x61\x6e\x65\x6c\x2e\x6d\x65",
    r"\x6b\x65\x74\x61\x6d\x69\x6e\x2e\x63\x63",
    r"MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR",
    r"yegScgjjdqJxajjEciirKPjVTDLrLPgTortCuhkITTKSrEAwzAFYeYHJbtwOKqgDNXIovf",
    r"zvoUEAhbeuIUspwvFMqmZmxJcYQKDGlgCXvXHWcHHsOnttuqJHvRfxExcVuuenaPYaUDoS",
    r"fzjrcOAVtqFkaAxWywpiwLojRAXpFyaqxYYWyYjryAVzoBtJpfHIgxdzkaVCestbWKSvuw",
    r"QZqzNpxLlcExGPKnpVHAnCEeHRhcalmKugKhNKxmiLrkAtHsqlfRcwipMtdpyUYcFwOBEc",
    r"UhBYcKlieqsXIFAeZKjhUPjCBVhjsiAePUBrdJCJWReeDOEmeJppTaDEpGFQQVzLFwZLSl",
    r"zmpEqNeFCrmHDfAeEqpnhacxRABCXWPBITvcRaUnagoDzplRqrbUTMtArqBkLYOcuFjPwb",
    r"yNFQacnrOUrYkjgbmlNiQASimwTmGijAqrsAnImrFdzlKAOiMsBHfsUkTSXQbXunaCtEdr",
    r"wPYBfzhUSeDCaVfBScIzFvHbIfnIqgJvCcxlXqfQydKpbjqvYwVHUAcYchsyrvvvFsKeUc",
    r"\x52\x65\x67\x69\x73\x74\x65\x72\x4e\x65\x74\x45\x76\x65\x6e\x74",
    r"\x52\x65\x67",
    r"tzCAyogCumAjjWRyUfjqMFmQuSCatkjdngxSidpiGRYBiqosQSJvmTWMhfExvRRkQUxXPf",
    r"\x50\x65\x72",
    r"Enchanced_Tabs"
]

# Caminho para o arquivo de log de erros
ERROR_LOG = "error_log.txt"