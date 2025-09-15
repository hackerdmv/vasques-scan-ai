import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import subprocess
import json
import socket
import requests
import nmap
import time
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
import os

# ========= CONFIGURAÇÕES =========
TITLE = "VASQUES-SCAN AI — Ethical Hacker Toolkit"
BG_COLOR = "#000000"  # Preto
FG_COLOR = "#00FF00"  # Verde hacker
BUTTON_COLOR = "#003300"  # Verde escuro
FONT = ("Courier", 10, "bold")

# URLs
IP_API_URL = "http://ip-api.com/json/"
OLLAMA_API_URL = "http://localhost:11434/api/generate"

# Inicializa Nmap
nm = nmap.PortScanner()

# ========= FUNÇÕES PRINCIPAIS =========

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        output.insert(tk.END, f"\n[✅ IP LOCAL] → {ip}\n")
        root.update()
        return ip
    except Exception as e:
        output.insert(tk.END, f"[!] Erro ao obter IP local: {e}\n")
        root.update()
        return "127.0.0.1"

def scan_ports(target):
    if not target.strip():
        target = "127.0.0.1"
    output.insert(tk.END, f"\n[+] Iniciando varredura de portas em {target}... (pode levar 1-2 minutos)\n")
    root.update()
    try:
        nm.scan(target, arguments='-sV -T4 --open')
        results = f"\n--- PORTAS ABERTAS EM {target} ---\n"
        found = False
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    found = True
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    results += f"Porta: {port}/TCP → Serviço: {service} → Versão: {version}\n"
        if not found:
            results += "Nenhuma porta aberta encontrada.\n"
        output.insert(tk.END, results + "\n")
        root.update()
        return nm
    except Exception as e:
        output.insert(tk.END, f"[!] Erro no scan: {str(e)}\n")
        root.update()
        return None

def get_ip_info(ip):
    if not ip.strip():
        ip = "8.8.8.8"
    output.insert(tk.END, f"\n[+] Coletando informações geográficas de {ip}...\n")
    root.update()
    try:
        response = requests.get(IP_API_URL + ip, timeout=10)
        data = response.json()
        if data['status'] == 'success':
            info = f"\n--- INTELIGÊNCIA DE AMEAÇAS (IP: {ip}) ---\n"
            info += f"País: {data.get('country', 'N/A')}\n"
            info += f"Cidade: {data.get('city', 'N/A')}\n"
            info += f"ISP: {data.get('isp', 'N/A')}\n"
            info += f"Organização: {data.get('org', 'N/A')}\n"
            info += f"Latitude: {data.get('lat', 'N/A')}, Longitude: {data.get('lon', 'N/A')}\n"
            output.insert(tk.END, info + "\n")
            root.update()
            return data
        else:
            output.insert(tk.END, "[!] Informações não encontradas.\n")
            root.update()
            return None
    except Exception as e:
        output.insert(tk.END, f"[!] Erro na coleta de Intel: {str(e)}\n")
        root.update()
        return None

def detect_vulnerabilities(target, scan_result):
    if not scan_result:
        output.insert(tk.END, "[!] Execute primeiro o 'Scan Portas'.\n")
        root.update()
        return "Nenhuma vulnerabilidade detectada."

    output.insert(tk.END, f"\n[+] Detectando vulnerabilidades em {target}...\n")
    root.update()
    vulns = "\n--- VULNERABILIDADES DETECTADAS (SIMULADAS) ---\n"
    found_vuln = False

    try:
        for host in scan_result.all_hosts():
            for proto in scan_result[host].all_protocols():
                lport = scan_result[host][proto].keys()
                for port in lport:
                    service = scan_result[host][proto][port]['name']
                    version = scan_result[host][proto][port]['version']
                    if version:
                        found_vuln = True
                        if "vsftpd" in service and "2.3.4" in version:
                            vulns += f"⚠️ CRÍTICO: vsftpd 2.3.4 → Backdoor conhecido (CVE-2011-2523)\n"
                            vulns += f"   Ação: Desativar serviço imediatamente.\n\n"
                        elif "Apache" in service and "2.4.49" in version:
                            vulns += f"⚠️ ALTO: Apache 2.4.49 → Path Traversal (CVE-2021-41773)\n"
                            vulns += f"   Ação: Atualizar para 2.4.51 ou superior.\n\n"
                        elif "OpenSSH" in service and (version.startswith("7.") or version.startswith("6.")):
                            vulns += f"⚠️ MÉDIO: OpenSSH {version} → Vulnerável a ataques de força bruta\n"
                            vulns += f"   Ação: Implementar autenticação por chave + fail2ban.\n\n"
                        else:
                            vulns += f"ℹ️ {service} {version} → Verificar atualizações disponíveis.\n\n"
        if not found_vuln:
            vulns += "Nenhuma vulnerabilidade crítica detectada.\n"
        output.insert(tk.END, vulns + "\n")
        root.update()
        return vulns
    except Exception as e:
        output.insert(tk.END, f"[!] Erro na detecção: {str(e)}\n")
        root.update()
        return "Erro ao detectar vulnerabilidades."

def ai_analysis():
    output.insert(tk.END, "\n[🧠] IA ANALYZING DATA... AGUARDE (pode levar até 5 minutos na primeira execução)...\n")
    output.insert(tk.END, "[ℹ️] Dica: Abra outro terminal e execute 'ollama run llama3' para pré-carregar o modelo.\n")
    root.update()

    full_text = output.get(1.0, tk.END)

    prompt = f"""
Você é VASQUES-GPT, um especialista sênior em segurança cibernética.
Analise o relatório abaixo e forneça:

1. Classificação de Risco Geral (Baixo, Médio, Alto, Crítico)
2. Top 3 riscos mais críticos encontrados
3. Ações corretivas prioritárias (passo a passo)
4. Recomendações de hardening e prevenção

RELATÓRIO PARA ANÁLISE:
{full_text}
"""

    models_to_try = ["llama3", "phi3", "llama2"]

    for model_name in models_to_try:
        try:
            output.insert(tk.END, f"[🔄] Tentando análise com modelo: {model_name}...\n")
            root.update()

            response = requests.post(OLLAMA_API_URL, json={
                "model": model_name,
                "prompt": prompt,
                "stream": False
            }, timeout=300)  # ✅ TIMEOUT AUMENTADO PARA 5 MINUTOS!

            if response.status_code == 200:
                result = response.json().get('response', 'Resposta vazia da IA.')
                output.insert(tk.END, f"\n[✅ VASQUES-GPT ({model_name.upper()}) AI ANALYSIS]\n{result}\n")
                output.insert(tk.END, f"\n[✔️] Análise concluída com sucesso usando {model_name}.\n")
                root.update()
                return result
            else:
                output.insert(tk.END, f"[⚠️] Modelo {model_name} retornou erro HTTP {response.status_code}. Tentando próximo...\n")
                root.update()

        except requests.exceptions.ConnectionError:
            output.insert(tk.END, f"[❌] Ollama não está rodando. Execute 'ollama run {model_name}' em outro terminal.\n")
            root.update()
            break
        except requests.exceptions.Timeout:
            output.insert(tk.END, f"[⏱️] Timeout de 5 minutos excedido com {model_name}. Tentando próximo modelo...\n")
            root.update()
        except Exception as e:
            output.insert(tk.END, f"[❌] Erro inesperado com {model_name}: {str(e)}. Tentando próximo...\n")
            root.update()

    # Fallback se todos falharem
    fallback_msg = """
[🧠 VASQUES-GPT — ANÁLISE DE EMERGÊNCIA]

⚠️ Nenhum modelo de IA disponível no momento.

✅ Ações Imediatas Recomendadas:
1. Priorize o patch de serviços com versões conhecidas por vulnerabilidades.
2. Restrinja o acesso a portas críticas (22, 3389, 445) por IP ou VPN.
3. Implemente WAF se houver serviços web expostos.
4. Habilite logs detalhados e monitore tentativas de acesso suspeitas.

📈 Classificação de Risco: ALTO (assumindo exposição de serviços críticos)

🛠️ Hardening Básico:
• sudo ufw enable && sudo ufw default deny incoming
• sudo apt update && sudo apt upgrade -y
• Desative serviços não essenciais.

🔁 Tente novamente após garantir que o Ollama está rodando com 'ollama run llama3'.
"""
    output.insert(tk.END, fallback_msg)
    root.update()
    return fallback_msg

def generate_report():
    filename = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        title="Salvar Relatório como PDF"
    )
    if not filename:
        return

    try:
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        # Cabeçalho
        c.setFont("Courier-Bold", 16)
        c.setFillColor(FG_COLOR)
        c.drawCentredString(width/2, height - 30*mm, "VASQUES-SCAN AI — RELATÓRIO DE SEGURANÇA")

        # Corpo
        c.setFont("Courier", 9)
        text = output.get(1.0, tk.END)
        y = height - 50*mm
        for line in text.split('\n'):
            if y < 30*mm:
                c.showPage()
                y = height - 30*mm
            if len(line) > 110:
                line = line[:110] + "..."
            c.drawString(20*mm, y, line)
            y -= 5*mm

        # Rodapé
        c.setFont("Courier", 8)
        c.setFillColor("#006600")
        c.drawCentredString(width/2, 15*mm, "Gerado por VASQUES-SCAN AI — Ferramenta para fins educacionais e éticos apenas.")

        c.save()
        messagebox.showinfo("✅ Sucesso", f"Relatório salvo com sucesso!\nLocal: {filename}")
    except Exception as e:
        messagebox.showerror("❌ Erro", f"Erro ao gerar PDF:\n{str(e)}")

# ========= INTERFACE GRÁFICA =========
root = tk.Tk()
root.title(TITLE)
root.geometry("1000x750")
root.configure(bg=BG_COLOR)
root.resizable(True, True)

# Título
title_label = tk.Label(root, text=TITLE, bg=BG_COLOR, fg=FG_COLOR, font=("Courier", 18, "bold"))
title_label.pack(pady=10)

# Frame de botões
button_frame = tk.Frame(root, bg=BG_COLOR)
button_frame.pack(pady=10)

# Botões
buttons_config = [
    ("🔍 IP LOCAL", get_local_ip),
    ("📡 SCAN PORTAS", lambda: scan_ports(entry_target.get().strip())),
    ("🌍 COLETAR INTEL", lambda: get_ip_info(entry_target.get().strip())),
    ("💥 DETECTAR VULNS", lambda: detect_vulnerabilities(entry_target.get().strip(), scan_ports(entry_target.get().strip()))),
    ("🤖 ANALISAR COM IA", ai_analysis),
    ("📄 GERAR RELATÓRIO", generate_report),
]

for text, command in buttons_config:
    btn = tk.Button(button_frame, text=text, command=command, bg=BUTTON_COLOR, fg=FG_COLOR, font=FONT, width=20, height=2)
    btn.pack(side=tk.LEFT, padx=5, pady=5)

# Campo de entrada
entry_label = tk.Label(root, text="Digite o IP/Alvo:", bg=BG_COLOR, fg=FG_COLOR, font=("Courier", 12, "bold"))
entry_label.pack(pady=5)

entry_target = tk.Entry(root, width=60, bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Courier", 12))
entry_target.pack(pady=5)
entry_target.insert(0, "192.168.0.1")

# Área de saída
output_label = tk.Label(root, text="RESULTADOS EM TEMPO REAL:", bg=BG_COLOR, fg="#00CC00", font=("Courier", 10, "bold"))
output_label.pack(pady=5)

output = scrolledtext.ScrolledText(root, bg=BG_COLOR, fg=FG_COLOR, font=("Courier", 11), insertbackground=FG_COLOR, height=28)
output.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Mensagem inicial
output.insert(tk.END, "🚀 BEM-VINDO AO VASQUES-SCAN AI — A FERRAMENTA DEFINITIVA DE HACKER ÉTICO COM IA!\n")
output.insert(tk.END, "💡 Dica: Comece inserindo um IP e clicando em 'SCAN PORTAS'.\n")
output.insert(tk.END, "⚠️ IMPORTANTE: Certifique-se de que o Ollama está rodando ('ollama run llama3') para usar a análise de IA.\n\n")

# Rodapé
footer = tk.Label(root, text="VASQUES-SCAN AI v1.0 — Ferramenta para fins educacionais e éticos apenas. | Dr. Vasques © 2025", bg=BG_COLOR, fg="#006600", font=("Courier", 8))
footer.pack(side=tk.BOTTOM, pady=5)

# Inicia a interface
root.mainloop()