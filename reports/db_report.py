# reports/db_report.py
import sqlite3

def generate_db_report(output_file="db_report.html"):
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM results")
    rows = cursor.fetchall()
    conn.close()

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório do Banco de Dados</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 10px; border: 1px solid #ccc; text-align: left; }}
            th {{ background-color: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>Relatório do Banco de Dados</h1>
        <table>
            <tr>
                <th>ID</th>
                <th>Arquivo</th>
                <th>Padrão</th>
                <th>Data e Hora</th>
            </tr>
    """
    for row in rows:
        html_content += f"""
            <tr>
                <td>{row[0]}</td>
                <td>{row[1]}</td>
                <td>{row[2]}</td>
                <td>{row[3]}</td>
            </tr>
        """
    html_content += """
        </table>
    </body>
    </html>
    """
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)