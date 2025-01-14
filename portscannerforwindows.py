import tkinter as tk
import tkinter.ttk as ttk
import socket
import requests
from tkinter.filedialog import askopenfilename
from impacket.smbconnection import SMBConnection

def get_host_info():
    host = entry_host.get()
    
    try:
        response = requests.get(f"https://ipinfo.io/{host}/json")
        data = response.json()

        result_text = f"Host: {data['ip']}\n"
        result_text += f"Cidade: {data.get('city', 'N/A')}\n"
        result_text += f"Região: {data.get('region', 'N/A')}\n"
        result_text += f"País: {data.get('country', 'N/A')}\n"
        result_text += f"Provedor: {data.get('org', 'N/A')}\n"

        result.delete('1.0', tk.END)
        result.insert(tk.END, result_text)
    except Exception as e:
        result.delete('1.0', tk.END)
        result.insert(tk.END, f"Erro ao obter informações do host: {e}")

def check_port():
    host = entry_host2.get()
    port = entry_port2.get()

    result2.delete('1.0', tk.END)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((host, int(port))) == 0:
            result_text = f"A porta {port} está aberta para o host {host}"
        else:
            result_text = f"A porta {port} está fechada para o host {host}"

        result2.insert(tk.END, result_text)
    except Exception as e:
        result2.insert(tk.END, f"Erro ao verificar a porta: {e}")

def load_ip_file():
    filename = askopenfilename(filetypes=[("Text Files", "*.txt")])
    
    if not filename:
        return
    
    with open(filename, 'r') as file:
        ips = file.readlines()

    rules = []
    for ip in ips:
        ip = ip.strip()
        ip_range = f"{ip}/32"  # Exemplo simples de conversão
        rule = f"/ip firewall filter add chain=input src-address={ip_range} action=drop comment='Bloqueio de {ip}'"
        rules.append(rule)
    
    result3.delete('1.0', tk.END)
    result3.insert(tk.END, "\n".join(rules))

def scan_smb_shares():
    host = entry_host4.get()
    username = entry_user.get()
    password = entry_pass.get()

    try:
        conn = SMBConnection(username, password, 'client', host)  # Utilizando as credenciais fornecidas
        conn.connect(host, 139)

        shares = conn.listShares()

        result_text = f"Compartilhamentos encontrados para {host}:\n\n"
        if not shares:
            result_text += "Nenhum compartilhamento encontrado."
        else:
            for share in shares:
                result_text += f"Compartilhamento: {share.name}\n"

        result5.delete('1.0', tk.END)
        result5.insert(tk.END, result_text)
    except Exception as e:
        result5.delete('1.0', tk.END)
        result5.insert(tk.END, f"Erro ao escanear compartilhamentos SMB: {e}")

window = tk.Tk()
window.title("Oxossi Software v.3.0 By Alquimia Hacking")
window.geometry("900x700")
window.configure(bg="#111111")

# Estilo para as abas
style = ttk.Style()
style.configure("TNotebook", background="#2d2d2d", tabmargins=[1, 5, 1, 0], relief="flat")
style.configure("TNotebook.Tab", background="#333333", foreground="#333333", font=("Courier New", 12, "bold"), padding=[10, 5])
style.map("TNotebook.Tab", background=[('selected', '#555555')])

# Estilo do Frame
style.configure("TFrame", background="#2d2d2d")
style.configure("TButton", background="#33FF00", foreground="#000000", font=("Courier New", 14), relief="flat")
style.configure("TText", background="#222222", foreground="#33FF00", font=("Courier New", 12), relief="flat")

# Layout de abas
notebook = ttk.Notebook(window)
info_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(info_frame, text="Informações do Host")
ports_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(ports_frame, text="Verificar Portas (Externo)")
ip_block_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(ip_block_frame, text="Carregar IPs e Criar Regras")
smb_scan_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(smb_scan_frame, text="Escanear SMB Shares")

# Estilo das abas (manter o estilo original sem o erro)
style.configure("TNotebook.Tab", font=("Courier New", 12, "bold"))

notebook.grid(row=0, column=0, padx=20, pady=20)

# Frame principal de informações do host
host_label = tk.Label(info_frame, text="Host:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
host_label.grid(row=0, column=0, padx=10, pady=10)

entry_host = tk.Entry(info_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_host.grid(row=0, column=1, padx=10, pady=10)

info_button = tk.Button(info_frame, text="Obter Informações", command=get_host_info)
info_button.grid(row=1, column=0, columnspan=2, padx=10, pady=15)

result = tk.Text(info_frame, height=10, width=40)
result.grid(row=2, column=0, columnspan=2, padx=20, pady=10)

# Frame de verificação de portas
host_label2 = tk.Label(ports_frame, text="Host:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
host_label2.grid(row=0, column=0, padx=10, pady=10)

entry_host2 = tk.Entry(ports_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_host2.grid(row=0, column=1, padx=10, pady=10)

port_label2 = tk.Label(ports_frame, text="Porta:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
port_label2.grid(row=1, column=0, padx=10, pady=10)

entry_port2 = tk.Entry(ports_frame, font=("Courier New", 14), width=10, relief="flat", bg="#222222", fg="#FFFFFF")
entry_port2.grid(row=1, column=1, padx=10, pady=10)

check_button = tk.Button(ports_frame, text="Verificar", command=check_port)
check_button.grid(row=2, column=0, columnspan=2, padx=10, pady=15)

result2 = tk.Text(ports_frame, height=10, width=40)
result2.grid(row=3, column=0, columnspan=2, padx=20, pady=10)

# Frame para carregar IPs e gerar regras
load_button = tk.Button(ip_block_frame, text="Carregar Arquivo de IPs", command=load_ip_file)
load_button.grid(row=0, column=0, padx=10, pady=20)

result3 = tk.Text(ip_block_frame, height=10, width=40)
result3.grid(row=1, column=0, padx=20, pady=10)

# Frame para escanear SMB Shares
host_label4 = tk.Label(smb_scan_frame, text="Host:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
host_label4.grid(row=0, column=0, padx=10, pady=10)

entry_host4 = tk.Entry(smb_scan_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_host4.grid(row=0, column=1, padx=10, pady=10)

user_label = tk.Label(smb_scan_frame, text="Usuário:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
user_label.grid(row=1, column=0, padx=10, pady=10)

entry_user = tk.Entry(smb_scan_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_user.grid(row=1, column=1, padx=10, pady=10)

pass_label = tk.Label(smb_scan_frame, text="Senha:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
pass_label.grid(row=2, column=0, padx=10, pady=10)

entry_pass = tk.Entry(smb_scan_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF", show="*")
entry_pass.grid(row=2, column=1, padx=10, pady=10)

scan_button = tk.Button(smb_scan_frame, text="Escanear SMB Shares", command=scan_smb_shares)
scan_button.grid(row=3, column=0, columnspan=2, padx=10, pady=15)

result5 = tk.Text(smb_scan_frame, height=10, width=40)
result5.grid(row=4, column=0, columnspan=2, padx=20, pady=10)

# Rodapé
footer = tk.Label(window, text="Desenvolvido por Alquimia Hacking", font=("Courier New", 10), fg="#888888", bg="#111111")
footer.grid(row=1, column=0, columnspan=2, pady=10)

# Centralizar o layout
window.grid_rowconfigure(0, weight=1)
window.grid_columnconfigure(0, weight=1)

# Adicionando bordas "hacker"
window.config(bg="#0e0e0e")

window.mainloop()
