import tkinter as tk
from tkinter import ttk

class ToggledFrame(tk.Frame):
    def __init__(self, parent, protocol, data):
        tk.Frame.__init__(self, parent, bg='#232323')
        self.data = data
        self.show = False

        # Style the toggle button
        style = ttk.Style()
        style.configure("Toggled.TButton",
                        background="#232323",
                        foreground="#fafafa",
                        font=('Segoe UI', 10, 'bold'))
        style.map("Toggled.TButton",
                  background=[('active', '#640000')],
                  foreground=[('active', '#ffffff')])

        self.title_button = ttk.Button(
            self, text=protocol, command=self.toggle, style="Toggled.TButton"
        )
        self.title_button.pack(fill="x", expand=1, padx=2, pady=(2,0))

        self.sub_frame = tk.Frame(self, bg='#2b2b2b', relief="groove", bd=1)

        self.format_data()

    def toggle(self):
        if self.show:
            self.sub_frame.forget()
            self.show = False
        else:
            self.sub_frame.pack(fill="x", expand=1, padx=5, pady=5)
            self.show = True

    def format_data(self):
        if isinstance(self.data, dict):
            for key in self.data:
                if key != 'Data':
                    tk.Label(
                        self.sub_frame,
                        text=f"{key}: {self.data[key]}",
                        anchor='w',
                        bg='#2b2b2b',
                        fg='#fafafa',
                        font=('Segoe UI', 10)
                    ).pack(fill='x', padx=10, pady=3)
        elif isinstance(self.data, str):
            tk.Label(
                self.sub_frame,
                text=self.data,
                anchor='w',
                bg='#2b2b2b',
                fg='#fafafa',
                font=('Segoe UI', 10)
            ).pack(fill='x', padx=10, pady=3)
