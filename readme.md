# Backdoor Scanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yuribraga17/backdoor-scanner?style=social)](https://github.com/yuribraga17/backdoor-scanner/stargazers)

**Backdoor Scanner** is an advanced security tool designed to detect potential backdoors and malicious code in FiveM servers. It is built for server administrators and developers who prioritize security.

---

## 🌟 Main Features

✅ **Advanced Detection** - Identifies suspicious patterns and minimizes false positives.  
✅ **Detailed Reports** - Generates logs with filename, code line, and detected patterns.  
✅ **Discord Alerts** - Sends automatic notifications to a configured Webhook.  
✅ **Real-Time Monitoring** - Watches file changes and alerts instantly.  
✅ **Signature Database** - Checks file hashes against a database of known malicious hashes.  
✅ **Obfuscated Code Detection** - Identifies suspicious and potentially harmful scripts.  
✅ **Interactive Reports** - Generates an HTML report (`scan_report.html`) for analysis.  
✅ **Configuration via `.env`** - All settings are managed through a `.env` file, making it easy to configure.

---

## 📥 Installation

### 1️⃣ Requirements
- Python 3.7 or higher
- Dependencies listed in `requirements.txt`

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/yuribraga17/backdoor-scanner.git
cd backdoor-scanner
```

### 3️⃣ Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### 4️⃣ Configure `.env`
Create a `.env` file in the project root and configure the variables:
```ini
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_WEBHOOK
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_TOKEN
LANGUAGE=en  # or "pt-br" for Portuguese
```

### 5️⃣ Run the Scanner
```bash
py backdoor_scanner.py
```
---

## 🛠️ How It Works

- Scans `.lua`, `.js`, `.json`, `.cfg`, `.sql`, `.txt`, `.py`, `.php`, `.html`, among others.
- Detects suspicious code patterns and verifies file hashes.
- If malicious code is found, it logs the details and can send an alert to Discord.
- Suspicious files are automatically moved to the `backups` folder.
- A detailed HTML report (`scan_report.html`) is generated after each scan.

---

## 📖 Usage Examples

### 🔍 Scanning a Directory
```bash
py backdoor_scanner.py
```

### 🕵️ Real-Time Monitoring
The scanner can continuously monitor a directory and alert on suspicious changes.

### 🔔 Example Discord Alert
![Example Discord Alert](https://i.imgur.com/SkuSl8m.png)

### 🔔 Get to Know Backdoor Scanner  
![Backdoor](https://i.imgur.com/eigzrYS.png)  
![Backdoor 2](https://i.imgur.com/sWcQSA6.png)  

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork the repository**.
2. **Create a new branch**:
   ```bash
   git checkout -b feature/NewFeature
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "Added new feature"
   ```
4. **Push to the repository**:
   ```bash
   git push origin feature/NewFeature
   ```
5. **Open a Pull Request**.

Read the [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
  [Email](mailto:yuribragasoares@gmail.com)

---

# Backdoor Scanner 🔍 (Versão em Português)

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yuribraga17/backdoor-scanner?style=social)](https://github.com/yuribraga17/backdoor-scanner/stargazers)

**Backdoor Scanner** é uma ferramenta avançada de segurança projetada para detectar possíveis backdoors e códigos maliciosos em servidores FiveM. Desenvolvido para administradores de servidores e desenvolvedores que priorizam segurança.

---

## 🌟 Principais Recursos

✅ **Detecção Avançada** - Identifica padrões suspeitos e minimiza falsos positivos.  
✅ **Relatórios Detalhados** - Gera logs com nome do arquivo, linha do código e padrões detectados.  
✅ **Alertas no Discord** - Envia notificações automáticas para um Webhook configurado.  
✅ **Monitoramento em Tempo Real** - Observa mudanças nos arquivos e alerta instantaneamente.  
✅ **Banco de Dados de Assinaturas** - Verifica hashes de arquivos com uma base de dados de hashes maliciosos conhecidos.  
✅ **Detecção de Código Ofuscado** - Identifica scripts suspeitos e potencialmente perigosos.  
✅ **Relatórios Interativos** - Gera um relatório em HTML (`scan_report.html`) para análise.  
✅ **Configuração via `.env`** - Todas as configurações são feitas no arquivo `.env`, facilitando a configuração.

---

## 📥 Instalação

### 1️⃣ Requisitos
- Python 3.7 ou superior
- Dependências listadas em `requirements.txt`

### 2️⃣ Clonar o Repositório
```bash
git clone https://github.com/yuribraga17/backdoor-scanner.git
cd backdoor-scanner
```

### 3️⃣ Instalar Dependências
```bash
py -m pip install -r requirements.txt
```

### 4️⃣ Configurar `.env`
Crie um arquivo `.env` na raiz do projeto e configure as variáveis:
```ini
DISCORD_WEBHOOK=https://discord.com/api/webhooks/SEU_WEBHOOK
VIRUSTOTAL_API_KEY=SEU_TOKEN_VIRUSTOTAL
LANGUAGE=pt-br  # ou "en" para inglês
```

### 5️⃣ Executar o Scanner
```bash
py backdoor_scanner.py
```
---

## 🛠️ Como Funciona

- Varre arquivos `.lua`, `.js`, `.json`, `.cfg`, `.sql`, `.txt`, `.py`, `.php`, `.html`, entre outros.
- Detecta padrões suspeitos e verifica hashes de arquivos.
- Se um código malicioso for encontrado, ele registra os detalhes e pode enviar um alerta para o Discord.
- Arquivos suspeitos são automaticamente movidos para a pasta `backups`.
- Um relatório detalhado em HTML (`scan_report.html`) é gerado após cada varredura.

---

## 📖 Exemplos de Uso

### 🔍 Escaneando um Diretório
```bash
py backdoor_scanner.py
```

### 🕵️ Monitoramento em Tempo Real
O scanner pode monitorar continuamente um diretório e alertar sobre mudanças suspeitas.

### 🔔 Exemplo de Alerta no Discord
![Exemplo de Alerta no Discord](https://i.imgur.com/SkuSl8m.png)

### 🔔 Conheça o Backdoor scanner
![Backdoor](https://i.imgur.com/eigzrYS.png)
![Backdoor 2](https://i.imgur.com/sWcQSA6.png)

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. **Faça um fork do repositório**.
2. **Crie uma nova branch**:
   ```bash
   git checkout -b feature/NovaFuncionalidade
   ```
3. **Faça commit das suas alterações**:
   ```bash
   git commit -m "Adicionando nova funcionalidade"
   ```
4. **Envie para o repositório**:
   ```bash
   git push origin feature/NovaFuncionalidade
   ```
5. **Abra um Pull Request**.

Leia o arquivo [CONTRIBUTING.md](CONTRIBUTING.md) para mais detalhes.

---

## 📜 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 📞 Contato

- **Yuri Braga**  
  [GitHub](https://github.com/yuribraga17)  
  [Email](mailto:yuribragasoares@gmail.com)


