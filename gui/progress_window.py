# gui/progress_window.py
import tkinter as tk
from tkinter import ttk

class ProgressWindow:
    def __init__(self, root, title="Progresso", width=300, height=100):
        self.root = root
        self.window = tk.Toplevel(root)
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")

        self.progress_bar = ttk.Progressbar(self.window, orient=tk.HORIZONTAL, length=280, mode="determinate")
        self.progress_bar.pack(pady=20)

        self.label = tk.Label(self.window, text="Escaneando...")
        self.label.pack()

    def update_progress(self, value):
        self.progress_bar["value"] = value
        self.root.update_idletasks()

    def update_label(self, text):
        self.label.config(text=text)
        self.root.update_idletasks()

    def close(self):
        self.window.destroy()