# Backdoor Scanner 🔍 (English Version)

A powerful scanner to detect possible backdoors in FiveM server scripts.

## 📌 Features
- 🚀 **Advanced Scanning**: Identifies suspicious patterns without false positives.
- 📜 **Detailed Logging**: Logs with file name, line number, and suspicious snippet.
- 🌐 **Discord Alerts**: Automatic notifications sent to a Webhook with full details.
- 🔥 **Smart Filtering**: Avoids detecting trusted files like PNG, SVG, and CitizenFX assets.
- 👤 **Author & Credits**: Personalized signature with name, GitHub, and avatar in Discord Webhook.

## 📥 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yuribraga17/backdoor-scanner.git
   cd backdoor-scanner
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Discord Webhook** (Optional):
   - Edit `backdoor_scanner.py` and replace `DISCORD_WEBHOOK` with your webhook URL.

4. **Run the Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

## ⚠️ How It Works

- The scanner checks `.lua`, `.js`, `.json`, `.cfg`, `.sql`, and `.txt` files.
- It detects common backdoor patterns and raises alerts if something suspicious is found.
- Logs are saved in `malware_log.txt` and `error_log.txt`.
- If a backdoor is detected, a message is sent to Discord.

## 📜 Author
- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
---

# Backdoor Scanner 🔍

Um scanner poderoso para detectar possíveis backdoors em scripts de servidores FiveM.

## 📌 Recursos
- 🚀 **Varredura Avançada**: Identifica padrões suspeitos sem falsos positivos.
- 📜 **Registro Detalhado**: Log detalhado com linha, arquivo e trecho suspeito.
- 🌐 **Envio para Discord**: Alertas automáticos com detalhes diretamente para um Webhook.
- 🔥 **Filtragem Inteligente**: Evita detectar arquivos confiáveis, como PNG, SVG e fontes do CitizenFX.
- 👤 **Autor & Créditos**: Assinatura personalizada com nome, GitHub e avatar no Webhook do Discord.

## 📥 Instalação

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/yuribraga17/backdoor-scanner.git
   cd backdoor-scanner
   ```

2. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure o Webhook do Discord** (Opcional):
   - Edite o arquivo `backdoor_scanner.py` e substitua `DISCORD_WEBHOOK` pelo seu webhook.

4. **Execute o Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

## ⚠️ Como Funciona

- O scanner percorre os arquivos `.lua`, `.js`, `.json`, `.cfg`, `.sql` e `.txt`.
- Ele detecta padrões comuns de backdoor e envia alertas caso algo suspeito seja encontrado.
- Logs são salvos nos arquivos `malware_log.txt` e `error_log.txt`.
- Caso um backdoor seja detectado, uma mensagem é enviada ao Discord.

## 📜 Autor

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  

