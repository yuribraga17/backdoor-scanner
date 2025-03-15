import pandas as pd
from datetime import datetime

def analyze_trends(db_path):
    """
    Analisa tendências de backdoors ao longo do tempo.
    """
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM results", conn)
    conn.close()
    
    # Agrupa por data e conta ocorrências
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    trends = df.groupby(df["timestamp"].dt.date).size()
    return trends