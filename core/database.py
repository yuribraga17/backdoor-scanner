# core/database.py
import sqlite3
import os

def create_database():
    """
    Cria o banco de dados e a tabela 'results' se ela não existir.
    """
    db_path = "scan_results.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Verifica se a tabela 'results' já existe
    cursor.execute("""
        SELECT name FROM sqlite_master WHERE type='table' AND name='results'
    """)
    table_exists = cursor.fetchone()

    # Se a tabela não existir, cria ela
    if not table_exists:
        cursor.execute("""
            CREATE TABLE results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                pattern TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    
    conn.close()

def save_result(file_path, pattern):
    """
    Salva um resultado no banco de dados.

    Args:
        file_path (str): Caminho do arquivo escaneado.
        pattern (str): Padrão suspeito encontrado.
    """
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO results (file_path, pattern)
        VALUES (?, ?)
    """, (file_path, pattern))
    conn.commit()
    conn.close()