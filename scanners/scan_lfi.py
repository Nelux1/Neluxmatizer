import requests, sys, threading, urllib3, random, urllib.parse, re
from urllib.parse import urlparse, parse_qs, urljoin, quote_plus
from bs4 import BeautifulSoup
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from colorama import Cursor, Fore, ansi, init
from threading import Lock
from parametizer.bounded_pool import run_threadpool_pending_bounded
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def is_lfi_response(text):
    """Detecta respuestas de LFI de manera específica."""
    text_lower = text.lower()

    # Evitar falsos positivos de mensajes genéricos del sitio
    if "this is not a real shop" in text_lower or "example php application" in text_lower:
        return False

    # Contenido real de /etc/passwd → LFI confirmado
    passwd_indicators = [
        'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:', 'sys:x:3:3:',
        'adm:x:4:4:', 'lp:x:7:7:', 'mail:x:8:8:', 'news:x:9:9:',
        'uucp:x:10:10:', 'operator:x:11:0:', 'games:x:12:100:',
        'man:x:13:62:', 'ftp:x:21:21:', 'nobody:x:99:99:',
    ]
    if any(indicator in text for indicator in passwd_indicators):
        return True

    # Errores de PHP/filesystem que evidencian path traversal activo
    # "Permission denied" y "Operation not permitted" confirman que el traversal
    # llegó al archivo pero fue bloqueado por permisos del SO → LFI parcial
    lfi_errors = [
        'open_basedir restriction in effect',
        'fpassthru()',
        'file_get_contents(',
        'failed to open stream',
        'no such file or directory',
        'permission denied',
        'operation not permitted',
    ]
    error_count = sum(1 for error in lfi_errors if error in text_lower)
    return error_count >= 2

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
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Local File Inclusion \033[1;36m>>>>>>>>>>>>>>\033[0m')
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
    def _iter_lfi_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_get_post, url, payload, "get")
                yield (test_get_post, url, payload, "post")
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)

    run_threadpool_pending_bounded(_iter_lfi_tasks(), threads)

    sys.stdout.write('\r' + ansi.clear_line())
    sys.stdout.flush()
    print()
    if found:
        print(f"\033[1;36m[+] Found {len(found)} potential LFI vulnerabilities\033[0m")
    else:
        print('\033[1;31m[-] No LFI vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
