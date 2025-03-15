import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def export_to_csv(data, filename):
    """
    Exporta os resultados para um arquivo CSV.
    """
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)

def export_to_json(data, filename):
    """
    Exporta os resultados para um arquivo JSON.
    """
    df = pd.DataFrame(data)
    df.to_json(filename, orient="records", indent=4)

def export_to_pdf(data, filename):
    """
    Exporta os resultados para um arquivo PDF.
    """
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Relatório de Varredura")
    y = 730
    for entry in data:
        c.drawString(100, y, str(entry))
        y -= 20
        if y < 50:
            c.showPage()
            y = 750
    c.save()