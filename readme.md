# Backdoor Scanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yuribraga17/backdoor-scanner?style=social)](https://github.com/yuribraga17/backdoor-scanner/stargazers)

Backdoor Scanner is a powerful security tool designed to detect potential backdoors in FiveM server scripts. It is built for server administrators and developers who prioritize security and efficiency.

---

## 🌟 Features

- **🚀 Advanced Detection**: Identifies suspicious patterns with minimal false positives.
- **📜 Detailed Reports**: Generates comprehensive logs with filenames, line numbers, and code snippets.
- **🌐 Discord Alerts**: Sends instant notifications to a Discord Webhook with full details.
- **🔥 Smart Filtering**: Ignores trusted files such as PNG, SVG, and CitizenFX assets.
- **👤 Custom Branding**: Includes personalized author signature, GitHub link, and avatar in alerts.
- **🔍 Multi-Language Support**: Available in English and Portuguese (Brazilian).
- **⚡ Real-Time Monitoring**: Watches for file modifications and alerts immediately.
- **🔒 Security Checks**: Detects obfuscated code and verifies file permissions.

---

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
   - Edit `config.json` and set `DISCORD_WEBHOOK` to your webhook URL.

4. **Run the Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

---

## 🛠️ How It Works

- Scans `.lua`, `.js`, `.json`, `.cfg`, `.sql`, `.txt`, `.py`, `.php`, and `.html` files for suspicious patterns.
- Uses a database of known malicious hashes and suspicious patterns to detect potential threats.
- If a threat is detected, it logs the details and sends an alert to Discord.
- Creates backups of flagged files in the `backups` directory.
- Generates an interactive HTML report (`scan_report.html`) with scan results.

---

## 📖 Usage Examples

### Scanning a Directory
```bash
python backdoor_scanner.py
```
- A file dialog will open for directory selection.

### Real-Time Monitoring
- The scanner can watch a directory for changes and alert on suspicious modifications.

### Discord Alert Example
![Discord Alert Example](https://i.imgur.com/Io94kCm.jpeg)

---

## 🚧 Roadmap

- [x] Discord Webhook integration
- [x] Real-time monitoring
- [x] Multi-language support (English and Portuguese)
- [x] Backup of flagged files
- [x] Interactive HTML reports
- [ ] VirusTotal API integration for hash verification
- [ ] Graphical User Interface (GUI)
- [ ] Additional file type support

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork the repository**.
2. **Create a new branch**:
   ```bash
   git checkout -b feature/YourFeatureName
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "Add some feature"
   ```
4. **Push to the branch**:
   ```bash
   git push origin feature/YourFeatureName
   ```
5. **Open a pull request**.

Read the [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
  [Email](mailto:yuribraga17@example.com)  

---

# Backdoor Scanner 🔍 (Versão em Português)

Um scanner poderoso para detectar possíveis backdoors em scripts de servidores FiveM. Ideal para administradores e desenvolvedores que priorizam segurança.

---

## 🌟 Recursos

- **🚀 Detecção Avançada**: Identifica padrões suspeitos com poucos falsos positivos.
- **📜 Relatórios Detalhados**: Gera logs completos com nome do arquivo, linha e código suspeito.
- **🌐 Alertas no Discord**: Notificações automáticas via Webhook do Discord.
- **🔥 Filtragem Inteligente**: Ignora arquivos confiáveis como PNG, SVG e assets do CitizenFX.
- **👤 Personalização**: Inclui assinatura do autor, GitHub e avatar nas notificações.
- **🔍 Suporte a Múltiplos Idiomas**: Disponível em inglês e português.
- **⚡ Monitoramento em Tempo Real**: Observa alterações de arquivos e alerta imediatamente.
- **🔒 Verificação de Segurança**: Detecta código ofuscado e verifica permissões.

---

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
   - Edite o `config.json` e defina `DISCORD_WEBHOOK` com seu webhook.

4. **Execute o Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

---

## 🛠️ Como Funciona

- Varre arquivos `.lua`, `.js`, `.json`, `.cfg`, `.sql`, `.txt`, `.py`, `.php`, e `.html` para padrões suspeitos.
- Utiliza banco de dados de hashes maliciosos e padrões suspeitos.
- Registra alertas no Discord e salva logs detalhados.
- Cria backups de arquivos suspeitos na pasta `backups`.
- Gera um relatório HTML interativo (`scan_report.html`).

---

## 📖 Exemplos de Uso

### Escaneando um Diretório
```bash
python backdoor_scanner.py
```
- Uma janela abrirá para selecionar o diretório a ser escaneado.

### Monitoramento em Tempo Real
- O scanner pode monitorar alterações de arquivos e alertar em tempo real.

### Exemplo de Alerta no Discord
![Exemplo de Alerta no Discord](https://i.imgur.com/Io94kCm.jpeg)

---

## 🚧 Roadmap

- [x] Integração com Webhook do Discord
- [x] Monitoramento em tempo real
- [x] Suporte a múltiplos idiomas (inglês e português)
- [x] Backup de arquivos suspeitos
- [x] Relatórios HTML interativos
- [ ] Integração com a API do VirusTotal
- [ ] Interface gráfica (GUI)
- [ ] Suporte a mais tipos de arquivos

---

## 📜 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 📞 Contato

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
  [Email](mailto:yuribraga17@example.com)

