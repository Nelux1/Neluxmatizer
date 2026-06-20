import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode
from parametizer.bounded_pool import run_threadpool_tasks_in_chunks
import random, sys, os, threading
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from colorama import Cursor, ansi, init
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

_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
)

_TRACKING_PARAMS: frozenset = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name", "utm_placing",
    "fbclid", "gclid", "msclkid", "dclid", "twclid",
    "_ga", "_gid", "_gl", "_hsenc", "_hsmi",
    "mc_eid", "mc_cid",
    "ref", "referrer",
})

_HASHED_PAGE_RE = re.compile(r'^[0-9a-f]{6,}_page$', re.IGNORECASE)


def _is_static_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(_STATIC_EXTENSIONS)


def _is_non_injectable_param(param: str) -> bool:
    p = param.lower()
    return p in _TRACKING_PARAMS or bool(_HASHED_PAGE_RE.match(p))

def get_base_domain(netloc):
    # Eliminar el puerto antes de comparar (ej: securitas.com:443 → securitas.com)
    host = netloc.lower().split(':')[0]
    parts = host.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host

def is_redirect_vulnerable(location, base_url, injected_value):
    if not location:
        return False

    parsed_location = urlparse(location)
    parsed_base = urlparse(base_url)

    # Si redirige dentro del mismo dominio base, no es vulnerable
    if get_base_domain(parsed_location.netloc) == get_base_domain(parsed_base.netloc):
        return False

    # Si el payload no está reflejado en la redirección, tampoco es relevante
    if injected_value.lower() not in location.lower():
        return False

    return True

def redirect(urip, urif, wordlist, urls_vulnerables, threads, custom_headers, random_agent):
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m  Testing Open Redirect \033[1;36m>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()
    total_tasks = len(wordlist) * len(urip)
    current = 0
    found = []
    vulnerable_endpoints = set()
    lock = threading.Lock()
    timeout = 10
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    stdout_lock = threading.Lock()

    def test_get_redirect(url):
        nonlocal current, found
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if _is_static_path(url):
            return

        # Crear sesión segura con manejo de bloqueos si está disponible
        if BLOCK_HANDLER_AVAILABLE:
            session = create_safe_request_session(headers)
        else:
            session = requests.Session()
            session.headers.update(headers)

        for param in params:
            if _is_non_injectable_param(param):
                continue
            # Verificar si ya se explotó esta combinación específica usando el sistema unificado
            if vuln_manager.should_skip_url(base, param):
                continue

            for payload in wordlist:
                # Cache de baseline para GET
                baseline_key = f"GET-{base}-{param}"
                if baseline_key not in baseline_cache:
                    baseline_params = params.copy()
                    baseline_params[param] = "TEST123"
                    baseline_url = f"{base}?{urlencode(baseline_params, doseq=True)}"
                    try:
                        baseline_resp = session.get(
                            baseline_url,
                            allow_redirects=False,
                            timeout=5
                        )
                        baseline_location = baseline_resp.headers.get("Location", "")
                        baseline_cache[baseline_key] = baseline_location
                    except requests.exceptions.Timeout:
                        baseline_cache[baseline_key] = ""
                    except requests.exceptions.RequestException:
                        baseline_cache[baseline_key] = ""
                    except Exception:
                        baseline_cache[baseline_key] = ""
                else:
                    baseline_location = baseline_cache[baseline_key]

                # Payload
                mod_params = params.copy()
                mod_params[param] = payload
                new_url = f"{base}?{urlencode(mod_params, doseq=True)}"
                
                try:
                    resp = session.get(new_url, allow_redirects=False, timeout=5)
                    location = resp.headers.get("Location", "")

                    if (
                        is_redirect_vulnerable(location, base, payload)
                        and location != baseline_location
                    ):
                        # Verificar si ya se explotó esta combinación específica
                        if not vuln_manager.is_already_exploited(base, param):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base, param)
                            
                            # Salida sincronizada
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[GET] [VULNERABLE]\033[0m {new_url} => {location}")
                            
                            urls_vulnerables.append(f"{new_url}")
                            found.append(new_url)
                            break

                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue
                except Exception:
                    continue
                finally:
                    with lock:
                        if current < total_tasks:
                            current += 1    
                            update_progress(current, total_tasks)

    # Si hay URLs POST, se prueba en POST también (urif)
    def test_post_redirect(url):
        nonlocal current, found
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if _is_static_path(url):
            return

        for param in params:
            if _is_non_injectable_param(param):
                continue
            clave = f"{base}|{param}"
            with lock:
                if clave in vulnerable_endpoints:
                    continue

            for payload in wordlist:
                # Cache de baseline para POST
                baseline_key = f"POST-{base}-{param}"
                if baseline_key not in baseline_cache:
                    baseline_data = params.copy()
                    baseline_data[param] = "TEST123"
                    try:
                        baseline_resp = requests.post(
                            base,
                            data=baseline_data,
                            headers=get_headers(custom_headers, random_agent),
                            allow_redirects=False,
                            timeout=5
                        )
                        baseline_location = baseline_resp.headers.get("Location", "")
                        baseline_cache[baseline_key] = baseline_location
                    except requests.exceptions.Timeout:
                        baseline_cache[baseline_key] = ""
                    except requests.exceptions.RequestException:
                        baseline_cache[baseline_key] = ""
                    except Exception:
                        baseline_cache[baseline_key] = ""
                else:
                    baseline_location = baseline_cache[baseline_key]

                mod_data = params.copy()
                mod_data[param] = payload
                try:
                    resp = requests.post(
                        base,
                        data=mod_data,
                        headers=headers,
                        allow_redirects=False,
                        timeout=5
                    )
                    location = resp.headers.get("Location", "")

                    if (
                        is_redirect_vulnerable(location, base, payload)
                        and location != baseline_location
                    ):
                        # Verificar si ya se explotó esta combinación específica
                        if not vuln_manager.is_already_exploited(base, param):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base, param)
                            
                            # Salida sincronizada
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[POST] [VULNERABLE]\033[0m {url} => {location}")
                            
                            urls_vulnerables.append(f"{url}")
                            found.append(url)
                            break
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue
                except Exception:
                    continue
                finally:
                    with lock:
                        if current < total_tasks:
                            current += 1
                            update_progress(current, total_tasks)

    # Crear tareas de manera más eficiente
    tasks = []
    
    # Agrupar tareas por URL para evitar duplicación
    if urip:
        for url in urip:
            tasks.append((test_get_redirect, url))
    
    if urif:
        for url in urif:
            tasks.append((test_post_redirect, url))
    
    run_threadpool_tasks_in_chunks(tasks, threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    print()
    if found:
        sys.stdout.write(f'\033[1;36m[+] Found {len(found)} potential Open Redirect vulnerabilities\033[0m\n')
        sys.stdout.flush()
    else:
        sys.stdout.write('\033[1;31m[-] No Open Redirect vulnerabilities found\033[0m\n')
        sys.stdout.flush()
    print()
    
    return urls_vulnerables

    
    return urls_vulnerables
