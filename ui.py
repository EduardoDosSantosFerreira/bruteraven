import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import pywifi
from pywifi import const
import urllib.request
import time
from script import WifiBruteForceLogic

class WifiBruteForceUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BruteRaven")
        self.geometry("900x750")
        self.resizable(False, False)

        # Variáveis
        self.url_var = tk.StringVar(value="https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.txt")
        self.verbose_var = tk.BooleanVar(value=True)
        self.quick_var = tk.BooleanVar(value=False)
        self.passwords = []
        self.networks = []
        self.selected_network = None
        self.brute_force_thread = None
        self.stop_brute_force_flag = threading.Event()

        # Instância da lógica
        self.logic = WifiBruteForceLogic(self)

        self.create_widgets()
        self.wifi = pywifi.PyWiFi()
        self.iface = self.wifi.interfaces()[0]

    def create_widgets(self):
        frame_wordlist = ttk.LabelFrame(self, text="Wordlist")
        frame_wordlist.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_wordlist, text="URL da wordlist:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        url_entry = ttk.Entry(frame_wordlist, textvariable=self.url_var, width=70)
        url_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        btn_load_url = ttk.Button(frame_wordlist, text="Carregar da URL", command=self.load_passwords_from_url)
        btn_load_url.grid(row=0, column=2, padx=5, pady=5)

        btn_load_file = ttk.Button(frame_wordlist, text="Carregar de Arquivo", command=self.load_passwords_from_file)
        btn_load_file.grid(row=1, column=2, padx=5, pady=5)

        frame_opts = ttk.Frame(frame_wordlist)
        frame_opts.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        ttk.Checkbutton(frame_opts, text="Verbose", variable=self.verbose_var).pack(side="left", padx=5)
        ttk.Checkbutton(frame_opts, text="Quick Mode", variable=self.quick_var).pack(side="left", padx=5)

        # Redes Wi-Fi com detalhes na Treeview
        frame_networks = ttk.LabelFrame(self, text="Redes Wi-Fi Detectadas")
        frame_networks.pack(fill="both", expand=True, padx=10, pady=5)

        self.btn_scan = ttk.Button(frame_networks, text="Escanear Redes", command=self.scan_networks)
        self.btn_scan.pack(anchor="nw", padx=5, pady=5)

        columns = ("SSID", "Sinal (dBm)", "Segurança")
        self.tree_ssids = ttk.Treeview(frame_networks, columns=columns, show="headings", height=10)
        for col in columns:
            self.tree_ssids.heading(col, text=col)
            self.tree_ssids.column(col, width=200 if col == "SSID" else 100, anchor="center")
        self.tree_ssids.pack(fill="both", expand=True, padx=5, pady=5)
        self.tree_ssids.bind("<<TreeviewSelect>>", self.on_network_select)

        # Controles brute force com botão parar
        frame_controls = ttk.Frame(self)
        frame_controls.pack(fill="x", padx=10, pady=5)

        self.btn_start = ttk.Button(frame_controls, text="Iniciar Brute Force", command=self.start_brute_force)
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(frame_controls, text="Parar Ataque", command=self.stop_brute_force, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.btn_clear_log = ttk.Button(frame_controls, text="Limpar Log", command=self.clear_log)
        self.btn_clear_log.pack(side="left", padx=5)

        # Log
        frame_log = ttk.LabelFrame(self, text="Log de Execução")
        frame_log.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_log = tk.Text(frame_log, height=15, state="disabled", wrap="word")
        self.text_log.pack(fill="both", expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(frame_log, command=self.text_log.yview)
        scrollbar.pack(side="right", fill="y")
        self.text_log.config(yscrollcommand=scrollbar.set)

    def log(self, message):
        self.text_log.configure(state="normal")
        self.text_log.insert("end", message + "\n")
        self.text_log.see("end")
        self.text_log.configure(state="disabled")

    def clear_log(self):
        self.text_log.configure(state="normal")
        self.text_log.delete("1.0", "end")
        self.text_log.configure(state="disabled")

    def load_passwords_from_url(self):
        self.logic.load_passwords_from_url(self.url_var.get(), self.log)

    def load_passwords_from_file(self):
        path = filedialog.askopenfilename(title="Selecione arquivo de wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.logic.load_passwords_from_file(path, self.log)

    def scan_networks(self):
        self.log("[+] Escaneando redes Wi-Fi...")
        self.btn_scan.config(state="disabled")
        self.tree_ssids.delete(*self.tree_ssids.get_children())
        self.networks = []

        def task():
            networks = self.logic.scan_networks(self.iface, self.quick_var.get())
            
            if not networks:
                self.log("[×] Nenhuma rede Wi-Fi encontrada.")
            else:
                self.networks = networks
                self.log(f"[✓] {len(networks)} redes encontradas.")
                for net in networks:
                    self.tree_ssids.insert("", "end", values=(net['ssid'], net['signal'], net['auth']))
            self.btn_scan.config(state="normal")

        threading.Thread(target=task, daemon=True).start()

    def on_network_select(self, event):
        selected = self.tree_ssids.selection()
        if selected:
            index = self.tree_ssids.index(selected[0])
            self.selected_network = self.networks[index]
            self.log(f"[+] Rede selecionada: {self.selected_network['ssid']}")

    def start_brute_force(self):
        if not self.passwords:
            messagebox.showwarning("Aviso", "Carregue a wordlist antes de iniciar.")
            return
        if not self.selected_network:
            messagebox.showwarning("Aviso", "Selecione uma rede Wi-Fi para atacar.")
            return

        if self.brute_force_thread and self.brute_force_thread.is_alive():
            messagebox.showinfo("Info", "Brute force já está em execução.")
            return

        self.stop_brute_force_flag.clear()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        ssid = self.selected_network['ssid']
        self.log(f"[+] Iniciando brute force na rede: {ssid}")

        def brute_force():
            self.logic.brute_force(
                iface=self.iface,
                ssid=ssid,
                passwords=self.passwords,
                auth=self.selected_network['auth'],
                verbose=self.verbose_var.get(),
                stop_flag=self.stop_brute_force_flag,
                log_func=self.log
            )
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")

        self.brute_force_thread = threading.Thread(target=brute_force, daemon=True)
        self.brute_force_thread.start()

    def stop_brute_force(self):
        if self.brute_force_thread and self.brute_force_thread.is_alive():
            self.stop_brute_force_flag.set()
            self.log("[!] Solicitado parada do ataque...")