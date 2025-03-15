from datetime import datetime
import plotly.express as px
import pandas as pd
import os

def generate_html_report(log_entries, error_entries, malware_found, author, github_profile):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Verifica se há logs para processar
        if not log_entries:
            log_entries = [("Nenhum log disponível.", "", "", "")]

        # Filtra entradas mal formatadas
        filtered_entries = []
        for entry in log_entries:
            if isinstance(entry, (list, tuple)) and len(entry) == 4:
                filtered_entries.append(entry)
            else:
                print(f"Entrada mal formatada removida: {entry}")  # Depuração

        # Cria um DataFrame para os logs
        df = pd.DataFrame(filtered_entries, columns=["Message", "File", "Line", "Code"])

        # Gera um gráfico de barras com Plotly (se houver dados válidos)
        graph_html = ""
        if not df.empty and "File" in df.columns and "Line" in df.columns:
            fig = px.bar(df, x="File", y="Line", color="Message", title="Resultados da Varredura")
            graph_html = fig.to_html(full_html=False)

        # Gera o conteúdo HTML
        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Varredura</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .log-entry {{ margin-bottom: 20px; padding: 10px; border-left: 5px solid #ccc; }}
                .error-entry {{ margin-bottom: 20px; padding: 10px; border-left: 5px solid #ff0000; }}
                .footer {{ margin-top: 40px; font-size: 0.9em; color: #666; }}
            </style>
        </head>
        <body>
            <h1>Relatório de Varredura</h1>
            <p><strong>Data e Hora:</strong> {timestamp}</p>
            <p><strong>Resultado:</strong> {"Backdoor encontrado!" if malware_found else "Nenhum backdoor encontrado."}</p>
            <h2>Gráfico de Resultados</h2>
            {graph_html}
            <h2>Logs</h2>
        """
        for entry in filtered_entries:
            try:
                message, file, line, code = entry
                html_content += f"""
                <div class="log-entry">
                    <p><strong>Mensagem:</strong> {message}</p>
                    <p><strong>Arquivo:</strong> {file}</p>
                    <p><strong>Linha:</strong> {line}</p>
                    <p><strong>Código:</strong> <code>{code}</code></p>
                </div>
                """
            except (ValueError, TypeError):
                # Se a entrada estiver mal formatada, ignora ou exibe uma mensagem de erro
                html_content += f"""
                <div class="log-entry">
                    <p><strong>Erro:</strong> Log mal formatado: {entry}</p>
                </div>
                """

        # Adiciona erros ao relatório
        if error_entries:
            html_content += "<h2>Erros</h2>"
            for error in error_entries:
                html_content += f"""
                <div class="error-entry">
                    <p><strong>Erro:</strong> {error}</p>
                </div>
                """

        # Adiciona o rodapé
        html_content += f"""
            <div class="footer">
                <p>Autor: {author} | Github: <a href="{github_profile}">{github_profile}</a></p>
            </div>
        </body>
        </html>
        """

        # Salva o relatório HTML
        report_path = os.path.abspath("scan_report.html")
        print(f"Gerando relatório em: {report_path}")
        with open(report_path, "w", encoding="utf-8") as log:
            log.write(html_content)

    except Exception as e:
        # Log de erro em caso de falha na geração do relatório
        error_message = f"[{timestamp}] ERROR: Falha ao gerar relatório HTML: {str(e)}"
        print(error_message)
        with open("error_log.html", "a", encoding="utf-8") as error_log:
            error_log.write(error_message + "\n")