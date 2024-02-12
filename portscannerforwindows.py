import tkinter as tk
import tkinter.ttk as ttk
import socket
import requests


def get_host_info():
    host = entry_host.get()
    
    try:
        response = requests.get(f"http://ip-api.com/json/{host}")
        data = response.json()

        result_text = f"Host: {data['query']}\n"
        result_text += f"Cidade: {data['city']}\n"
        result_text += f"Região: {data['regionName']}\n"
        result_text += f"País: {data['country']}\n"
        result_text += f"Provedor: {data['isp']}\n"

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


window = tk.Tk()
window.title("Oxossi Software v.1.0 By Leonardo Reis")
window.geometry("800x600")
window.configure(bg="#000000")


notebook = ttk.Notebook(window)


info_frame = ttk.Frame(notebook)
notebook.add(info_frame, text="Informações do Host")


main_frame = ttk.Frame(info_frame)
main_frame.pack(pady=20)


host_label = tk.Label(main_frame, text="Host:", font=("Helvetica", 12), fg="#FFFFFF", bg="#000000")
host_label.grid(row=0, column=0, padx=5, pady=5)

entry_host = tk.Entry(main_frame, font=("Helvetica", 12), width=30)
entry_host.grid(row=0, column=1, padx=5, pady=5)


info_button = tk.Button(main_frame, text="Obter Informações", font=("Helvetica", 12), bg="#1DB954", fg="#000000", command=get_host_info)
info_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)


result = tk.Text(info_frame, height=10, width=40, font=("Helvetica", 12), bg="#191919", fg="#1DB954")
result.pack()


ports_frame = ttk.Frame(notebook)
notebook.add(ports_frame, text="Verificar Portas (Externo)")


main_frame2 = ttk.Frame(ports_frame)
main_frame2.pack(pady=20)


host_label2 = tk.Label(main_frame2, text="Host:", font=("Helvetica", 12), fg="#FFFFFF", bg="#000000")
host_label2.grid(row=0, column=0, padx=5, pady=5)

entry_host2 = tk.Entry(main_frame2, font=("Helvetica", 12), width=30)
entry_host2.grid(row=0, column=1, padx=5, pady=5)


port_label2 = tk.Label(main_frame2, text="Porta:", font=("Helvetica", 12), fg="#FFFFFF", bg="#000000")
port_label2.grid(row=1, column=0, padx=5, pady=5)

entry_port2 = tk.Entry(main_frame2, font=("Helvetica", 12), width=10)
entry_port2.grid(row=1, column=1, padx=5, pady=5)


check_button = tk.Button(main_frame2, text="Verificar", font=("Helvetica", 12), bg="#1DB954", fg="#000000", command=check_port)
check_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10)


result2 = tk.Text(ports_frame, height=10, width=40, font=("Helvetica", 12), bg="#191919", fg="#1DB954")
result2.pack()

notebook.pack(expand=True, fill=tk.BOTH)

footer_label = tk.Label(window, text="Desenvolvido por Leonardo Reis", font=("Helvetica", 10), fg="#FFFFFF", bg="#000000")
footer_label.pack(side=tk.BOTTOM, pady=10)

window.mainloop()