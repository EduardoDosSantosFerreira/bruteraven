# 🛠️ Wi-Fi Brute Force - BruteRaven

Um projeto educacional que demonstra como realizar força bruta em redes Wi-Fi com interface gráfica feita em Tkinter e motor de execução usando `pywifi`.

> ⚠️ **Uso estritamente educacional!** Não utilize este software em redes que você não tem permissão para testar. Invadir redes sem autorização é crime.

---

## 🎯 Funcionalidades

- Escaneia redes Wi-Fi disponíveis
- Permite selecionar a rede-alvo pela interface
- Suporte a várias wordlists:
  - Top100k (download automático e cache)
  - RockYou (opcional)
  - Arquivo local `.txt`
  - URL remota
  - Interface gráfica com:
  - Combobox de redes com força do sinal
  - Opções extras (Verbose, Modo Rápido, Forçar download)
  - Botão para iniciar o ataque
- Terminal exibe o progresso detalhado das tentativas
- Compatível com Windows (recomendado)

---

## 🖥️ Interface Gráfica

![Interface gráfica](./assets/preview.png)

---

## 🧩 Estrutura

```bash
wifi_brute_force/
├── main.py           # Script principal de ataque
├── ui_launcher.py    # Interface gráfica em Tkinter
├── wordlists/        # Wordlists armazenadas em cache
└── README.md
````

---

## ⚙️ Como usar

### 🔹 Instale as dependências

```bash
pip install pywifi
```

> 💡 Recomendado: usar Python 3.9+ no Windows com permissões elevadas

### 🔹 Rodar pela interface

```bash
python ui_launcher.py
```

A interface irá:

* Escanear redes disponíveis
* Permitir a seleção da rede-alvo
* Oferecer modos de wordlist e configurações extras

### 🔹 Rodar via terminal

```bash
# Usar Top100k (cache automático):
python main.py -w top100k

# Usar RockYou (mais pesada):
python main.py -w rockyou

# Usar arquivo local:
python main.py -f minha_lista.txt

# Usar URL direta:
python main.py -u https://exemplo.com/lista.txt

# Ativando verbose + modo rápido:
python main.py -w top100k -v --quick

# Forçar download de wordlist novamente:
python main.py -w top100k --force-download

# Atacar uma rede específica:
python main.py -w top100k --ssid "NOME_DA_REDE"
```

---

## 📌 Requisitos

* Windows com adaptador Wi-Fi funcional
* Python 3.8+
* Permissões de administrador (recomendado)

---

## 🧠 Observações

* O script **não quebra WPA2 com brute puro**, apenas tenta autenticar usando senhas comuns da wordlist
* O `pywifi` apenas testa conexões; **não captura handshake**
* Apenas redes visíveis podem ser atacadas

---

## 🧑‍💻 Autor

Desenvolvido por **Eduardo dos Santos Ferreira**

GitHub: [github.com/EduardoDosSantosFerreira](https://github.com/EduardoDosSantosFerreira)

---

## ⚠️ Aviso Legal

Este projeto é fornecido **apenas para fins educacionais e testes em ambientes controlados**.
**Não me responsabilizo por qualquer uso indevido.**

```
---