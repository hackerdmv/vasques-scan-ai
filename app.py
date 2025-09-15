import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW, CENTER
import asyncio
import requests
import socket
import json

class VasquesScanApp(toga.App):

    def startup(self):
        # Estilo principal
        main_box = toga.Box(style=Pack(direction=COLUMN, background_color='#000000', padding=10))

        # Título
        title_label = toga.Label(
            'VASQUES-SCAN AI — Android',
            style=Pack(color='#00FF00', font_size=16, font_weight='bold', text_align=CENTER, padding=10)
        )
        main_box.add(title_label)

        # Campo de entrada
        self.ip_input = toga.TextInput(
            placeholder='Digite o IP/Alvo',
            style=Pack(flex=1, background_color='#000000', color='#00FF00')
        )
        ip_box = toga.Box(style=Pack(direction=ROW, padding=5))
        ip_box.add(self.ip_input)
        main_box.add(ip_box)

        # Botões
        buttons = [
            ("IP Local", self.get_local_ip),
            ("Scan Portas", self.scan_ports),
            ("Coletar Intel", self.get_ip_info),
            ("Analisar com IA", self.ai_analysis),
            ("Gerar Relatório", self.generate_report),
        ]

        for text, handler in buttons:
            btn = toga.Button(
                text,
                on_press=handler,
                style=Pack(
                    background_color='#003300',
                    color='#00FF00',
                    font_weight='bold',
                    padding=10,
                    margin=5
                )
            )
            main_box.add(btn)

        # Área de saída (TextView)
        self.output = toga.MultilineTextInput(
            readonly=True,
            style=Pack(
                flex=1,
                background_color='#000000',
                color='#00FF00',
                font_family='monospace',
                padding=10
            )
        )
        main_box.add(self.output)

        # Rodapé
        footer = toga.Label(
            'Dr. Vasques © 2025 — Uso ético apenas',
            style=Pack(color='#006600', font_size=8, text_align=CENTER, padding_top=10)
        )
        main_box.add(footer)

        # Janela principal
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = main_box
        self.main_window.show()

        # Mensagem inicial
        self.output.value = "🚀 BEM-VINDO AO VASQUES-SCAN AI ANDROID!\n💡 Comece digitando um IP e clicando em um botão.\n⚠️ Scan local e IA requerem backend externo.\n"

    def get_local_ip(self, widget):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.output.value += f"\n[✅ IP LOCAL] → {ip}\n"
        except Exception as e:
            self.output.value += f"\n[!] Erro ao obter IP local: {e}\n"

    def scan_ports(self, widget):
        target = self.ip_input.value.strip() or "scanme.nmap.org"
        self.output.value += f"\n[+] Iniciando scan em {target}...\n"
        self.output.value += "[ℹ️] No Android, usamos API externa para simular scan.\n"

        # Simulação de scan (em produção, chame seu backend com Nmap)
        simulated_result = """
--- PORTAS ABERTAS ---
Porta: 22/TCP → Serviço: ssh → Versão: OpenSSH 7.6p1
Porta: 80/TCP → Serviço: http → Versão: Apache 2.4.29
Porta: 443/TCP → Serviço: https → Versão: nginx 1.14.0
Porta: 3306/TCP → Serviço: mysql → Versão: MySQL 5.7.33
Porta: 8080/TCP → Serviço: http-proxy → Versão: Apache Tomcat 9.0.50
"""
        self.output.value += simulated_result + "\n"

    def get_ip_info(self, widget):
        ip = self.ip_input.value.strip() or "8.8.8.8"
        self.output.value += f"\n[+] Coletando Intel de {ip}...\n"

        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            if data['status'] == 'success':
                info = f"\n--- INTELIGÊNCIA DE AMEAÇAS ---\n"
                info += f"📌 IP: {ip}\n"
                info += f"🌍 País: {data.get('country', 'N/A')}\n"
                info += f"🏙️ Cidade: {data.get('city', 'N/A')}\n"
                info += f"🏢 ISP: {data.get('isp', 'N/A')}\n"
                info += f"🏷️ Org: {data.get('org', 'N/A')}\n"
                info += f"📍 Coordenadas: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}\n"
                self.output.value += info + "\n"
            else:
                self.output.value += "[!] Informações não encontradas.\n"
        except Exception as e:
            self.output.value += f"\n[!] Erro na coleta de Intel: {e}\n"

    async def ai_analysis(self, widget):
        self.output.value += "\n[🧠] IA ANALYZING DATA... (simulando análise com VASQUES-GPT)...\n"
        await asyncio.sleep(2)  # Simula processamento

        # Simulação de análise de IA (em produção, chame seu backend com Ollama)
        simulated_ai_response = """
[✅ VASQUES-GPT AI ANALYSIS — VERSÃO ANDROID]

⚠️ CLASSIFICAÇÃO DE RISCO: ALTO
🔍 TOP 3 VULNERABILIDADES DETECTADAS:
   1. Serviço SSH exposto na porta 22 → Risco de força bruta.
   2. Apache 2.4.29 desatualizado → Vulnerável a ataques de path traversal.
   3. MySQL 5.7.33 sem autenticação forte → Risco de vazamento de dados.

🛡️ AÇÕES PRIORITÁRIAS:
   1. Restringir acesso SSH por IP ou implementar chave SSH.
   2. Atualizar Apache para versão 2.4.58+.
   3. Aplicar senha forte no MySQL e mudar porta padrão.

📈 RECOMENDAÇÃO DE HARDENING:
   • Implementar WAF (ex: ModSecurity) para proteger serviços web.
   • Configurar fail2ban para bloquear tentativas de força bruta.
   • Monitorar logs com ferramenta centralizada (ex: Graylog).

[✔️] Análise concluída com sucesso. Para análise mais profunda, use a versão Desktop com Ollama local.
"""
        self.output.value += simulated_ai_response + "\n"

    def generate_report(self, widget):
        report_content = f"RELATÓRIO VASQUES-SCAN AI ANDROID\n\n{self.output.value}"
        self.output.value += "\n[📄] Relatório gerado com sucesso! (Função de compartilhamento em desenvolvimento)\n"
        # Em breve: self.save_or_share_report(report_content)

def main():
    return VasquesScanApp()