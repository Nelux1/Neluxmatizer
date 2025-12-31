import requests
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urljoin, quote
from bs4 import BeautifulSoup
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import urllib3
import threading
import sys
import os
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_sqli_response(text):
    return any(keyword in text.lower() for keyword in ["sql syntax", "mysql_fetch", "syntax error", "unterminated quoted string", "query failed"])

def sqli(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    print()
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m Testing SQL Injection \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()


    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    lock = threading.Lock()
    vulnerable_endpoints = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()

    def get_baseline_response(method, url, data=None):
        try:
            # Solo hacer request si hay datos, sino retornar string vacío
            if not data:
                return ""
                
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            if method == "post":
                r = requests.post(url, data={k: "TEST123" for k in data}, headers=headers, verify=False, timeout=5)
            elif method == "get":
                r = requests.get(url, params={k: "TEST123" for k in data}, headers=headers, verify=False, timeout=5)
            else:
                return ""
            
            # Solo retornar texto si la respuesta es exitosa
            if r.status_code == 200:
                return r.text.lower()
            return ""
        except requests.exceptions.Timeout:
            return ""  # Timeout específico
        except requests.exceptions.RequestException:
            return ""  # Otros errores de requests
        except Exception:
            return ""  # Cualquier otro error

    def test_url(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)
        headers=get_headers(random_agent=random_agent, custom_headers=custom_headers)

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
            
            # Cache de baseline para GET
            baseline_key = f"GET-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("get", base_url, data)
            baseline = baseline_cache[baseline_key]
            
            try:
                r = requests.get(base_url, params=data, headers=headers, verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_sqli_response(r.text) and r.text.lower() != baseline:
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        # Verificar falso positivo
                        if not vuln_manager.verify_false_positive(base_url, payload, "GET", custom_headers, random_agent):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[GET][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                            # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                            current += 1
                            update_progress(current, total_tasks)
                            return
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
                
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_post(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        # Verificar si ya se explotó esta URL usando el sistema unificado
        if vuln_manager.should_skip_url(base_url, base_url_only=True) or not qs:
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
            
            # Cache de baseline para POST
            baseline_key = f"POST-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("post", base_url, data)
            baseline = baseline_cache[baseline_key]

            try:
                r = requests.post(base_url, data=data, headers=get_headers(random_agent=random_agent, custom_headers=custom_headers), verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_sqli_response(r.text) and r.text.lower() != baseline:
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        # Verificar falso positivo
                        if not vuln_manager.verify_false_positive(base_url, payload, "POST", custom_headers, random_agent):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[POST][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                            # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                            current += 1
                            update_progress(current, total_tasks)
                            return
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
                
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_form(url, payload):
        nonlocal current
        try:
            # Cache de formularios para evitar re-parsing
            if url not in form_cache:
                r = requests.get(url, headers=get_headers(random_agent=random_agent, custom_headers=custom_headers), timeout=7)
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
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload

                if not data:
                    continue

                full_url = urljoin(url, action) if action else url
                
                # Cache de baseline para formularios
                baseline_key = f"{method}-{full_url}-{','.join(data.keys())}"
                if baseline_key not in baseline_cache:
                    baseline_cache[baseline_key] = get_baseline_response(method, full_url, data)
                baseline = baseline_cache[baseline_key]

                if method == "post":
                    res = requests.post(full_url, data=data, headers=headers, timeout=5)
                else:
                    res = requests.get(full_url, params=data, headers=headers, timeout=5)

                # Solo procesar si la respuesta es exitosa
                if res.status_code == 200 and is_sqli_response(res.text) and res.text.lower() != baseline:
                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded_data = {k: quote(v, safe='') for k, v in data.items()}
                                print_vulnerability(f"\033[1;32m[FORM][VULNERABLE]\033[0m {full_url}\n{encoded_data}")
                            
                            urls_vulnerables.append(f"{full_url}")
                            # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                            current += 1
                            update_progress(current, total_tasks)
                            return
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
            tasks.append((test_url, url, payload))
            tasks.append((test_post, url, payload))
    
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
    
    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
        sys.stdout.write('\n')  # Asegurar salto de línea final
        sys.stdout.flush()
    
    if vulnerable_endpoints:
        sys.stdout.write(f'\n\033[1;36m[+] Found {len(vulnerable_endpoints)} potential SQLi vulnerabilities\033[0m\n')
        sys.stdout.flush()
    else:
        sys.stdout.write('\n\033[1;31m[-] No SQLi vulnerabilities found\033[0m\n')
        sys.stdout.flush()
    
    return urls_vulnerables
