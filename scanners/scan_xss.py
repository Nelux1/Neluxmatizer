import requests
import random
import sys
import os
import os
import threading
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin, quote
from parametizer.bounded_pool import run_threadpool_pending_bounded
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import urllib3
import sys
import os
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

# Importar el sistema de manejo de bloqueos
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.block_handler import create_safe_request_session
    BLOCK_HANDLER_AVAILABLE = True
except ImportError:
    BLOCK_HANDLER_AVAILABLE = False

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_xss_response(text, payload):
    """Validación más estricta para detectar XSS real"""
    
    # Verificar si el payload se refleja exactamente en el cuerpo de la respuesta
    if payload in text:
        return True
    
    # Verificar si el payload se refleja de forma codificada
    import html
    decoded_payload = html.unescape(payload)
    if decoded_payload in text:
        return True
    
    # Verificar si el payload se refleja en atributos HTML (más específico)
    if f'"{payload}"' in text or f"'{payload}'" in text:
        return True
    
    # Verificar si hay indicadores específicos de XSS exitoso
    xss_indicators = [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "alert(",
        "prompt(",
        "confirm(",
        "document.cookie",
        "window.location",
        "eval(",
        "innerHTML"
    ]
    
    # Solo considerar válido si hay múltiples indicadores o el payload se refleja claramente
    indicator_count = sum(1 for indicator in xss_indicators if indicator in text.lower())
    
    # Verificar que no sea solo un mensaje de error o página 404
    if "404" in text or "not found" in text.lower() or "error" in text.lower():
        return False
    
    # EVITAR FALSOS POSITIVOS: Si hay errores de SQL, NO es XSS
    if "sql syntax" in text.lower() or "mysql" in text.lower() or "you have an error in your sql" in text.lower():
        return False
    
    # Verificar que la respuesta tenga contenido significativo
    if len(text.strip()) < 50:  # Respuestas muy cortas probablemente son errores
        return False
    
    return indicator_count >= 2 or payload in text  # Al menos 2 indicadores o payload reflejado

def xss(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Cross-Site Scripting \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()
    total = (len(urip)*2 + len(urif)) * len(wordlist)
    current = 0
    found = 0
    lock = threading.Lock()
    vuln_set = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()

    def test_url(url, payload):
        nonlocal current, found
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if not qs:
            with lock:
                current += 1
                update_progress(current, total)
            return

        # Crear sesión segura con manejo de bloqueos si está disponible
        if BLOCK_HANDLER_AVAILABLE:
            session = create_safe_request_session(headers)
        else:
            session = requests.Session()
            session.headers.update(headers)

        # Verificar si esta URL ya fue explotada usando el sistema unificado
        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total)
            return

        for param in qs:
            # Cache de baseline para GET
            baseline_key = f"GET-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                try:
                    data = {p: "TEST123" for p in qs}
                    r = session.get(base_url, params=data, verify=False, timeout=5)
                    if r.status_code == 200:
                        baseline_cache[baseline_key] = r.text
                    else:
                        baseline_cache[baseline_key] = ""
                except requests.exceptions.Timeout:
                    baseline_cache[baseline_key] = ""
                except requests.exceptions.RequestException:
                    baseline_cache[baseline_key] = ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            baseline = baseline_cache[baseline_key]
            
            if not baseline:
                continue

            # Probar payload XSS
            data = {p: "TEST123" for p in qs}
            data[param] = payload
            try:
                r = session.get(base_url, params=data, verify=False, timeout=5, allow_redirects=True)
                
                # Solo procesar si la respuesta es exitosa Y el payload se refleja realmente
                if r.status_code == 200 and is_xss_response(r.text, payload) and r.text != baseline:
                    # Verificar que el payload realmente se refleja (no solo en URL)
                    if payload in r.text or urllib.parse.unquote(payload) in r.text:
                        # Verificar si ya se explotó esta combinación específica
                        if not vuln_manager.is_already_exploited(base_url, param):
                            # Verificar falso positivo
                            if not vuln_manager.verify_false_positive(base_url, payload, "GET", custom_headers, random_agent):
                                # Marcar como explotada
                                vuln_manager.mark_as_exploited(base_url, param)
                                vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                                
                                # Salida sincronizada usando la nueva función
                                with stdout_lock:
                                    print_vulnerability(f"\033[1;32m[GET] [VULNERABLE]\033[0m {base_url}?{param}={quote(payload)}")
                                
                                # Guardar URL con payload para el PoC
                                urls_vulnerables.append(f"{base_url}?{param}={quote(payload)}")
                                found += 1
                                # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                                with lock:
                                    current += 1
                                    update_progress(current, total)
                                return
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue

        # POST con los mismos parámetros
        for param in qs:
            # Cache de baseline para POST
            baseline_key = f"POST-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                try:
                    data = {p: "TEST123" for p in qs}
                    r = session.post(base_url, data=data, verify=False, timeout=5)
                    if r.status_code == 200:
                        baseline_cache[baseline_key] = r.text
                    else:
                        baseline_cache[baseline_key] = ""
                except requests.exceptions.Timeout:
                    baseline_cache[baseline_key] = ""
                except requests.exceptions.RequestException:
                    baseline_cache[baseline_key] = ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            baseline = baseline_cache[baseline_key]
            
            if not baseline:
                continue

            # Probar payload XSS
            data = {p: "TEST123" for p in qs}
            data[param] = payload
            try:
                r = session.post(base_url, data=data, verify=False, timeout=5, allow_redirects=True)
                
                # Solo procesar si la respuesta es exitosa Y el payload se refleja realmente
                if r.status_code == 200 and is_xss_response(r.text, payload) and r.text != baseline:
                    # Verificar que el payload realmente se refleja (no solo en URL)
                    if payload in r.text or urllib.parse.unquote(payload) in r.text:
                        key = f"{base_url}?{param}={payload}"
                        if key not in vuln_set:
                            vuln_set.add(key)
                            # Marcar esta URL como explotada para evitar más pruebas
                            vuln_set.add(url_key)
                            
                            # Salida sincronizada
                            with stdout_lock:
                                sys.stdout.write('\r' + ansi.clear_line())
                                sys.stdout.flush()
                                print(f"\033[1;32m[POST] [VULNERABLE]\033[0m {base_url}?{param}={quote(payload)}")
                            
                            # Guardar URL con payload para el PoC
                            urls_vulnerables.append(f"{base_url}?{param}={quote(payload)}")
                            found += 1
                            # CORTAR INMEDIATAMENTE - no probar más payloads en esta URL
                            with lock:
                                current += 1
                                update_progress(current, total)
                            return
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue

        with lock:
            current += 1
            update_progress(current, total)

    def test_form(url, payload):
        nonlocal current, found
        try:
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            
            # Crear sesión segura con manejo de bloqueos si está disponible
            if BLOCK_HANDLER_AVAILABLE:
                session = create_safe_request_session(headers)
            else:
                session = requests.Session()
                session.headers.update(headers)
            
            # Cache de formularios para evitar re-parsing
            if url not in form_cache:
                r = session.get(url, timeout=7)
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
                baseline_key = f"{method}-{full_url}-{','.join(data.keys())}"
                if baseline_key not in baseline_cache:
                    try:
                        baseline_data = {k: "TEST123" for k in data}
                        if method == "post":
                            r = session.post(full_url, data=baseline_data, timeout=5)
                        else:
                            r = session.get(full_url, params=baseline_data, timeout=5)
                        
                        if r.status_code == 200:
                            baseline_cache[baseline_key] = r.text
                        else:
                            baseline_cache[baseline_key] = ""
                    except requests.exceptions.Timeout:
                        baseline_cache[baseline_key] = ""
                    except requests.exceptions.RequestException:
                        baseline_cache[baseline_key] = ""
                    except Exception:
                        baseline_cache[baseline_key] = ""
                
                baseline = baseline_cache[baseline_key]
                if not baseline:
                    continue

                if method == "post":
                    res = session.post(full_url, data=data, timeout=5)
                else:
                    res = session.get(full_url, params=data, timeout=5)

                # Solo procesar si la respuesta es exitosa
                if res.status_code == 200 and is_xss_response(res.text, payload) and res.text != baseline:
                    key = f"{full_url}|{','.join(sorted(data.keys()))}|{payload}"
                    if key not in vuln_set:
                        vuln_set.add(key)
                        
                        # Salida sincronizada usando la nueva función
                        with stdout_lock:
                            encoded_data = {k: urllib.parse.quote_plus(v) for k, v in data.items()}
                            print_vulnerability(f"\033[1;32m[FORM] [VULNERABLE]\033[0m {full_url}" + "\033[1;32m ==> \033[0m" + f"{encoded_data}" )
                        
                        # Guardar URL con datos del formulario para el PoC
                        urls_vulnerables.append(f"{full_url} => {data}")
                        found += 1
        except requests.exceptions.Timeout:
            pass  # Skip timeouts silently
        except requests.exceptions.RequestException:
            pass  # Skip other request errors
        except Exception:
            pass  # Skip any other errors

        with lock:
            current += 1
            update_progress(current, total)

    def _iter_xss_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)

    try:
        run_threadpool_pending_bounded(_iter_xss_tasks(), threads)
    except KeyboardInterrupt:
        from parametizer.interrupt import is_interrupted
        if is_interrupted():
            return
        raise

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
        print()

    if found > 0:
        print(f'\033[1;36m[+] Found {found} potential XSS vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No XSS vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
