# main.py
from core.database import create_database
from gui.main_window import create_gui

def main():
    create_database()  # Garante que o banco de dados e a tabela sejam criados
    create_gui()

if __name__ == "__main__":
    main()