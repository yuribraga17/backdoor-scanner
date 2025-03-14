# Backdoor Scanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yuribraga17/backdoor-scanner?style=social)](https://github.com/yuribraga17/backdoor-scanner/stargazers)

A powerful and intelligent scanner to detect potential backdoors in FiveM server scripts. Designed for server administrators and developers who value security and efficiency.

---

## 🌟 Features

- **🚀 Advanced Scanning**: Detects suspicious patterns with minimal false positives.
- **📜 Detailed Logging**: Logs include file name, line number, and suspicious code snippets.
- **🌐 Discord Alerts**: Sends automatic notifications to a Discord Webhook with full details.
- **🔥 Smart Filtering**: Ignores trusted files like PNG, SVG, and CitizenFX assets.
- **👤 Author & Credits**: Personalized signature with name, GitHub, and avatar in Discord Webhook.
- **🔍 Multi-Language Support**: Available in English and Portuguese (Brazilian).
- **⚡ Real-Time Monitoring**: Watches for file changes and alerts immediately.
- **🔒 Security Checks**: Verifies file permissions and detects obfuscated code.

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
   - Edit `backdoor_scanner.py` and replace `DISCORD_WEBHOOK` with your webhook URL.

4. **Run the Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

---

## 🛠️ How It Works

- The scanner checks `.lua`, `.js`, `.json`, `.cfg`, `.sql`, and `.txt` files for suspicious patterns.
- It uses advanced detection techniques to minimize false positives.
- If a backdoor is detected, it logs the details and sends an alert to Discord.
- Logs are saved in `malware_log.txt` and `error_log.txt`.

---

## 📖 Examples of Use

### Scanning a Directory
```bash
python backdoor_scanner.py
```
- A file dialog will open for you to select the directory to scan.

### Real-Time Monitoring
- The scanner can monitor a directory for changes and alert you in real-time.

### Discord Alert Example
![Discord Alert Example](https://i.imgur.com/Io94kCm.jpeg)

---

## 🚧 Roadmap

- [x] Add Discord Webhook integration.
- [x] Implement real-time monitoring.
- [x] Add multi-language support (English and Portuguese).
- [ ] Integrate with VirusTotal API for hash verification.
- [ ] Add a graphical user interface (GUI).
- [ ] Support for more file types and languages.

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

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

Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for more details.

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

Um scanner poderoso e inteligente para detectar possíveis backdoors em scripts de servidores FiveM. Projetado para administradores e desenvolvedores que valorizam segurança e eficiência.

---

## 🌟 Recursos

- **🚀 Varredura Avançada**: Detecta padrões suspeitos com mínimos falsos positivos.
- **📜 Registro Detalhado**: Logs incluem nome do arquivo, número da linha e trechos de código suspeitos.
- **🌐 Alertas no Discord**: Envia notificações automáticas para um Webhook do Discord com detalhes completos.
- **🔥 Filtragem Inteligente**: Ignora arquivos confiáveis, como PNG, SVG e assets do CitizenFX.
- **👤 Autor & Créditos**: Assinatura personalizada com nome, GitHub e avatar no Webhook do Discord.
- **🔍 Suporte a Multi Idiomas**: Disponível em inglês e português (brasileiro).
- **⚡ Monitoramento em Tempo Real**: Observa alterações em arquivos e alerta imediatamente.
- **🔒 Verificações de Segurança**: Verifica permissões de arquivos e detecta código ofuscado.

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
   - Edite o arquivo `backdoor_scanner.py` e substitua `DISCORD_WEBHOOK` pelo seu webhook.

4. **Execute o Scanner**:
   ```bash
   python backdoor_scanner.py
   ```

---

## 🛠️ Como Funciona

- O scanner verifica arquivos `.lua`, `.js`, `.json`, `.cfg`, `.sql` e `.txt` em busca de padrões suspeitos.
- Usa técnicas avançadas de detecção para minimizar falsos positivos.
- Se um backdoor for detectado, ele registra os detalhes e envia um alerta para o Discord.
- Logs são salvos nos arquivos `malware_log.txt` e `error_log.txt`.

---

## 📖 Exemplos de Uso

### Escaneando um Diretório
```bash
python backdoor_scanner.py
```
- Uma janela será aberta para você selecionar o diretório a ser escaneado.

### Monitoramento em Tempo Real
- O scanner pode monitorar um diretório e alertar em tempo real sobre alterações.

### Exemplo de Alerta no Discord
![Exemplo de Alerta no Discord](https://i.imgur.com/Io94kCm.jpeg)

---

## 🚧 Roadmap

- [x] Adicionar integração com Webhook do Discord.
- [x] Implementar monitoramento em tempo real.
- [x] Adicionar suporte a multi idiomas (inglês e português).
- [ ] Integrar com a API do VirusTotal para verificação de hashes.
- [ ] Adicionar uma interface gráfica (GUI).
- [ ] Suporte para mais tipos de arquivos e linguagens.

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Aqui está como você pode ajudar:

1. **Faça um fork do repositório**.
2. **Crie uma nova branch**:
   ```bash
   git checkout -b feature/NomeDaSuaFeature
   ```
3. **Faça commit das suas alterações**:
   ```bash
   git commit -m "Adiciona alguma feature"
   ```
4. **Envie para a branch**:
   ```bash
   git push origin feature/NomeDaSuaFeature
   ```
5. **Abra um pull request**.

Leia o arquivo [CONTRIBUTING.md](CONTRIBUTING.md) para mais detalhes.

---

## 📜 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 📞 Contato

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
  [Email](mailto:yuribraga17@example.com)  
