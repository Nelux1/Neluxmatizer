import requests
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urljoin, quote
from bs4 import BeautifulSoup
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import urllib3
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
try:
    from scanners.sqli_patterns import is_sqli_error_response
except ImportError:
    from sqli_patterns import is_sqli_error_response

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
)

# Parámetros de tracking/analytics que nunca llegan a una query SQL
_TRACKING_PARAMS: frozenset = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name", "utm_placing",
    "fbclid", "gclid", "msclkid", "dclid", "twclid",
    "_ga", "_gid", "_gl", "_hsenc", "_hsmi",
    "mc_eid", "mc_cid",
    "ref", "referrer",
})

# Params de paginación con prefijo hash generado por Symfony/WP/otros (ej: a1d72e41_page)
_HASHED_PAGE_RE = re.compile(r'^[0-9a-f]{6,}_page$', re.IGNORECASE)


def _is_static_path(url: str) -> bool:
    """Retorna True si la URL apunta a un recurso estático (no testeable para SQLi)."""
    path = urlparse(url).path.lower()
    return path.endswith(_STATIC_EXTENSIONS)


def _is_non_injectable_param(param: str) -> bool:
    """
    Retorna True si el parámetro es de tracking/analytics o paginación hash
    y no tiene sentido testear SQLi en él.
    """
    p = param.lower()
    if p in _TRACKING_PARAMS:
        return True
    if _HASHED_PAGE_RE.match(p):
        return True
    return False

def sqli(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
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
            return r.text.lower()
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

        if not qs or _is_static_path(url):
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
            if _is_non_injectable_param(param):
                continue

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
                
                if r.status_code in (200, 500) and is_sqli_error_response(r.text) and r.text.lower() != baseline:
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        # Verificar falso positivo (misma ruta con valor benigno en el parámetro)
                        if not vuln_manager.verify_sqli_false_positive(
                            base_url, "GET", param=param, custom_headers=custom_headers, random_agent=random_agent
                        ):
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
        if vuln_manager.should_skip_url(base_url, base_url_only=True) or not qs or _is_static_path(url):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            if _is_non_injectable_param(param):
                continue

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
                
                if r.status_code in (200, 500) and is_sqli_error_response(r.text) and r.text.lower() != baseline:
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        if not vuln_manager.verify_sqli_false_positive(
                            base_url, "POST", param=param, custom_headers=custom_headers, random_agent=random_agent
                        ):
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

                if vuln_manager.should_skip_url(full_url, base_url_only=True):
                    continue
                
                form_param = sorted(data.keys())[0]
                if vuln_manager.should_skip_url(full_url, form_param):
                    continue
                
                # Cache de baseline para formularios
                baseline_key = f"{method}-{full_url}-{','.join(sorted(data.keys()))}"
                if baseline_key not in baseline_cache:
                    baseline_cache[baseline_key] = get_baseline_response(method, full_url, data)
                baseline = baseline_cache[baseline_key]

                if method == "post":
                    res = requests.post(full_url, data=data, headers=headers, verify=False, timeout=5)
                else:
                    res = requests.get(full_url, params=data, headers=headers, verify=False, timeout=5)

                if res.status_code in (200, 500) and is_sqli_error_response(res.text) and res.text.lower() != baseline:
                    if vuln_manager.is_already_exploited(full_url, form_param):
                        continue
                    if vuln_manager.verify_sqli_false_positive(
                        full_url, method.upper(), form_data=data, custom_headers=custom_headers, random_agent=random_agent
                    ):
                        continue
                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            vuln_manager.mark_as_exploited(full_url, form_param)
                            vuln_manager.mark_as_exploited(full_url, base_url_only=True)
                            
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

    # No materializar millones de tareas/futures: agota RAM y el kernel mata el proceso (zsh: killed).
    pending_max = max(threads * 200, 2000)

    def drain_batch(batch):
        for fut in as_completed(batch):
            try:
                fut.result()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        pending = []
        for url in urip:
            for payload in wordlist:
                pending.append(executor.submit(test_url, url, payload))
                pending.append(executor.submit(test_post, url, payload))
                if len(pending) >= pending_max:
                    drain_batch(pending)
                    pending.clear()
        for url in urif:
            for payload in wordlist:
                pending.append(executor.submit(test_form, url, payload))
                if len(pending) >= pending_max:
                    drain_batch(pending)
                    pending.clear()
        if pending:
            drain_batch(pending)
    
    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    print()
    if vulnerable_endpoints:
        sys.stdout.write(f'\033[1;36m[+] Found {len(vulnerable_endpoints)} potential SQLi vulnerabilities\033[0m\n')
        sys.stdout.flush()
    else:
        sys.stdout.write('\033[1;31m[-] No SQLi vulnerabilities found\033[0m\n')
        sys.stdout.flush()
    print()
    
    return urls_vulnerables
