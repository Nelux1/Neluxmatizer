import requests, sys, threading, urllib3, random, urllib.parse
from urllib.parse import urlparse, parse_qs, urljoin, quote_plus
from bs4 import BeautifulSoup
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from colorama import Cursor, Fore, ansi, init
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

indicadores_esperados = [
    'root:x:0:0:', 'bin:x:1:1:', 'daemon:x:2:2:', 'sys:x:3:3:',
    'USER=', 'HOME=', 'SHELL=', 'UID=', 'GID=',
    '127.0.0.1', 'localhost', 'RewriteEngine', '<title>Index of',
    'fopen()', 'open_basedir', 'fpassthru', 'file_get_contents',
    'failed to open stream', 'Operation not permitted', 'No such file',
    'Permission denied', 'Access denied'
]

def is_lfi_response(text):
    """Detecta respuestas de LFI de manera más específica y estricta"""
    text_lower = text.lower()
    
    # Evitar falsos positivos de mensajes genéricos del sitio
    if "this is not a real shop" in text_lower or "example php application" in text_lower:
        return False
    
    # Verificar si contiene contenido real de /etc/passwd
    passwd_indicators = [
        'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:', 'sys:x:3:3:',
        'adm:x:4:4:', 'lp:x:7:7:', 'mail:x:8:8:', 'news:x:9:9:',
        'uucp:x:10:10:', 'operator:x:11:0:', 'games:x:12:100:',
        'man:x:13:62:', 'at:x:25:25:', 'cron:x:16:16:', 'ftp:x:21:21:',
        'nobody:x:99:99:', 'systemd-network:x:192:192:', 'systemd-resolve:x:193:193:'
    ]
    
    # Si contiene contenido real de /etc/passwd, es definitivamente LFI
    if any(indicator in text for indicator in passwd_indicators):
        return True
    
    # Verificar si contiene errores específicos de LFI
    lfi_errors = [
        'open_basedir', 'fpassthru', 'file_get_contents',
        'failed to open stream', 'Operation not permitted', 'No such file',
        'Permission denied', 'Access denied'
    ]
    
    # Solo considerar válido si hay múltiples indicadores de error
    error_count = sum(1 for error in lfi_errors if error.lower() in text_lower)
    
    # EVITAR FALSOS POSITIVOS: Si hay open_basedir restriction, NO es LFI explotable
    if "open_basedir restriction" in text_lower or "operation not permitted" in text_lower:
        return False
    
    return error_count >= 2  # Al menos 2 indicadores para considerar válido

def get_baseline_response(method, url, data=None, custom_headers=None, random_agent=False):
    headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
    try:
        # Solo hacer request si hay datos, sino retornar string vacío
        if not data:
            return ""
            
        neutral_data = {k: "TEST123" for k in data}
        if method == "post":
            response = requests.post(url, data=neutral_data, headers=headers, verify=False, timeout=8)
        else:
            response = requests.get(url, params=neutral_data, headers=headers, verify=False, timeout=8)
        
        # Solo retornar texto si la respuesta es exitosa
        if response.status_code == 200:
            return response.text
        return ""
    except requests.exceptions.Timeout:
        return ""  # Timeout específico
    except requests.exceptions.RequestException:
        return ""  # Otros errores de requests
    except Exception:
        return ""  # Cualquier otro error

def lfi(urip, urif, wordlist, urls_vulnerables, threads, custom_headers, random_agent):
    print()
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Local File Inclusion \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    lock = Lock()
    found = set()
    
    # Cache para baselines y formularios
    baseline_cache = {}
    form_cache = {}

    def test_get_post(url, payload, method):
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        if not qs:
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        # Verificar si ya se explotó esta URL usando el sistema unificado
        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            # Verificar si ya se explotó esta combinación específica
            if vuln_manager.should_skip_url(base_url, param):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return
                
            data = {param: payload}
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            
            # Cache key para baseline
            baseline_key = f"{method}-{base_url}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response(method, base_url, data, custom_headers, random_agent)

            try:
                # Timeout más corto para GET requests
                timeout = 5 if method == "get" else 8
                
                if method == "post":
                    r = requests.post(base_url, data=data, headers=headers, verify=False, timeout=timeout)
                else:
                    r = requests.get(base_url, params=data, headers=headers, verify=False, timeout=timeout)

                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_lfi_response(r.text) and r.text != baseline_cache[baseline_key]:
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        # Verificar falso positivo
                        if not vuln_manager.verify_false_positive(base_url, payload, method.upper(), custom_headers, random_agent):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            encoded = quote_plus(payload)
                            print_vulnerability(f"\033[1;32m[{method.upper()}] [VULNERABLE]{Fore.RESET} {base_url}?{param}={encoded}")
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                            # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                            current += 1
                            update_progress(current, total_tasks)
                            return
            except requests.exceptions.Timeout:
                continue  # Skip timeouts
            except requests.exceptions.RequestException:
                continue  # Skip other request errors
            except Exception:
                continue  # Skip any other errors

        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_form(url, payload):
        nonlocal current
        try:
            # Cache de formularios para evitar re-parsing
            if url not in form_cache:
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                r = requests.get(url, headers=headers, verify=False, timeout=10)
                soup = BeautifulSoup(r.text, "html.parser")
                forms = soup.find_all("form")
                form_cache[url] = forms
            else:
                forms = form_cache[url]

            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                data = {}
                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload

                if not data:
                    continue

                full_url = urljoin(url, action) if action else url
                
                # Cache de baseline para formularios
                baseline_key = f"{method}-{full_url}"
                if baseline_key not in baseline_cache:
                    baseline_cache[baseline_key] = get_baseline_response(method, full_url, data, custom_headers, random_agent)

                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                if method == "post":
                    res = requests.post(full_url, data=data, headers=headers, timeout=8)
                else:
                    res = requests.get(full_url, params=data, headers=headers, timeout=8)

                # Solo procesar si la respuesta es exitosa
                if res.status_code == 200 and is_lfi_response(res.text) and res.text != baseline_cache[baseline_key]:
                    key = f"form-{full_url}-{','.join(data.keys())}"
                    with lock:
                        if key not in found:
                            found.add(key)
                            encoded_data = {k: quote_plus(v) for k, v in data.items()}
                            print_vulnerability(f"\033[1;31m[FORM] [VULNERABLE]{Fore.RESET} {full_url}")
                            print_vulnerability(str(encoded_data))
                            urls_vulnerables.append(f"{full_url}")
        except requests.exceptions.Timeout:
            pass  # Skip timeouts silently
        except requests.exceptions.RequestException:
            pass  # Skip other request errors
        except Exception:
            pass  # Skip any other errors

        with lock:
            current += 1
            update_progress(current, total_tasks)

    # Crear tareas de manera más eficiente
    tasks = []
    
    # Agrupar tareas por URL para evitar duplicación
    for url in urip:
        for payload in wordlist:
            tasks.append((test_get_post, url, payload, "get"))
            tasks.append((test_get_post, url, payload, "post"))
    
    for url in urif:
        for payload in wordlist:
            tasks.append((test_form, url, payload))
    
    # Procesar TODAS las tareas en paralelo para máximo rendimiento
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Enviar todas las tareas al pool de hilos
        futures = [executor.submit(task[0], *task[1:]) for task in tasks]
        
        # Esperar a que se completen todas (pero en paralelo)
        for future in futures:
            try:
                future.result()
            except Exception:
                pass

    sys.stdout.write('\r' + ansi.clear_line())
    sys.stdout.flush()
    print()  # Asegurar salto de línea final
    if found:
        print(f"\n\033[1;36m[+] Found {len(found)} potential LFI vulnerabilities\033[0m\n")
    else:
        print('\n\033[1;31m[-] No LFI vulnerabilities found\033[0m\n')
    
    return urls_vulnerables
