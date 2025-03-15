import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import threading
from core.scanner import scan_file
from core.parallel_scanner import scan_files_parallel
from core.utils import translate
from config import PATTERNS, MALICIOUS_HASHES, VIRUSTOTAL_API_KEY, SCAN_EXTENSIONS, DISCORD_AUTHOR, DISCORD_GITHUB_PROFILE
from reports.html_report import generate_html_report
from reports.export import export_to_csv, export_to_json, export_to_pdf
from security.restore_manager import restore_file

def create_gui():
    root = tk.Tk()
    root.title(translate("title"))
    root.geometry("1000x800")

    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    log_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=20)
    log_area.pack(fill=tk.BOTH, expand=True, pady=10)

    progress_bar = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=800, mode="determinate")
    progress_bar.pack(pady=10)

    button_frame = tk.Frame(main_frame)
    button_frame.pack(pady=10)

    def start_scan():
        directory = filedialog.askdirectory()
        if directory:
            start_button.config(state=tk.DISABLED)
            log_area.insert(tk.END, f"[INFO] Scanning directory: {directory}\n")

            def scan_thread():
                malware_found = False
                log_entries = []
                error_entries = []
                total_files = 0
                scanned_files = 0

                # Contar o número total de arquivos
                for root_dir, _, files in os.walk(directory):
                    for file in files:
                        if any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                            total_files += 1

                # Escanear os arquivos em paralelo
                results = scan_files_parallel(directory)
                for result in results:
                    if isinstance(result, list):
                        log_entries.extend(result)
                        if any("ALERT" in entry[0] for entry in result):
                            malware_found = True
                    else:
                        error_entries.append(result)

                # Gera o relatório HTML após o escaneamento
                root.after(0, lambda: generate_html_report(log_entries, error_entries, malware_found, DISCORD_AUTHOR, DISCORD_GITHUB_PROFILE))

                # Exibe o resultado final
                if malware_found:
                    root.after(0, lambda: messagebox.showwarning(translate("alert"), translate("malware_found")))
                else:
                    root.after(0, lambda: messagebox.showinfo(translate("alert"), translate("no_malware")))

                # Reabilita o botão de escaneamento após o término
                root.after(0, lambda: start_button.config(state=tk.NORMAL))

            # Inicia o escaneamento em uma thread separada
            threading.Thread(target=scan_thread, daemon=True).start()

    def export_results():
        """
        Exporta os resultados da varredura.
        """
        export_format = export_format_var.get()
        if export_format == "CSV":
            export_to_csv(log_entries, "scan_results.csv")
        elif export_format == "JSON":
            export_to_json(log_entries, "scan_results.json")
        elif export_format == "PDF":
            export_to_pdf(log_entries, "scan_results.pdf")
        messagebox.showinfo("Exportação", f"Resultados exportados em {export_format}")

    def restore_files():
        """
        Restaura arquivos da quarentena.
        """
        file_to_restore = filedialog.askopenfilename()
        if file_to_restore:
            restore_file(file_to_restore, os.path.join("original_path", os.path.basename(file_to_restore)))
            messagebox.showinfo("Restauração", "Arquivo restaurado com sucesso!")

    start_button = tk.Button(button_frame, text=translate("select_directory"), command=start_scan)
    start_button.pack(side=tk.LEFT, padx=5)

    export_format_var = tk.StringVar(value="CSV")
    export_format_menu = tk.OptionMenu(button_frame, export_format_var, "CSV", "JSON", "PDF")
    export_format_menu.pack(side=tk.LEFT, padx=5)

    export_button = tk.Button(button_frame, text="Exportar Resultados", command=export_results)
    export_button.pack(side=tk.LEFT, padx=5)

    restore_button = tk.Button(button_frame, text="Restaurar Arquivos", command=restore_files)
    restore_button.pack(side=tk.LEFT, padx=5)

    exit_button = tk.Button(button_frame, text="Sair", command=root.quit)
    exit_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()