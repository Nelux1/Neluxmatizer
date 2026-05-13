import requests
import random
import re
from parametizer.bounded_pool import run_threadpool_pending_bounded
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


rce_params = [
    "cmd", "exec", "execute", "run", "input", "query", "command",
    "cli", "process", "action", "call", "shell", "code", "eval",
    "file", "path", "dir", "template", "filename", "load",
    "source", "data", "script", "ping", "host", "domain",
    "ip", "target", "url", "endpoint", "syscmd", "system",
]

def is_rce_response(text):
    return any(keyword in text.lower() for keyword in ["uid=", "gid=", "root:", "/etc/passwd", "neluxmatizer"])

def rce(urip, urif, wordlist, urls_vulnerables, threads, custom_headers, random_agent):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Remote Code Execution \033[1;36m>>>>>>>>>>>>>>\033[0m')
    print()
    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    found = []
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
            neutral_data = {k: "TEST123" for k in data}
            
            if method == "post":
                r = requests.post(url, data=neutral_data, headers=headers, verify=False, timeout=5)
            elif method == "get":
                r = requests.get(url, params=neutral_data, headers=headers, verify=False, timeout=5)
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

        if not qs or base_url in vulnerable_endpoints or _is_static_path(url):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            if _is_non_injectable_param(param):
                continue
            if param.lower() not in rce_params:
                continue

            data = {k: payload if k == param else "TEST123" for k in qs}
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            
            # Cache de baseline para GET
            baseline_key = f"GET-{base_url}-{','.join(data.keys())}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("get", base_url, data)
            baseline = baseline_cache[baseline_key]

            try:
                r = requests.get(base_url, params=data, headers=headers, verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and (
                    is_rce_response(r.text)
                    and r.text.lower() != baseline
                    and abs(len(r.text) - len(baseline)) > 50
                ):
                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[GET][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                    break
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

        if base_url in vulnerable_endpoints or not qs or _is_static_path(url):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            if _is_non_injectable_param(param):
                continue
            if param.lower() not in rce_params:
                continue

            data = {k: payload if k == param else "TEST123" for k in qs}
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            
            # Cache de baseline para POST
            baseline_key = f"POST-{base_url}-{','.join(data.keys())}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("post", base_url, data)
            baseline = baseline_cache[baseline_key]

            try:
                r = requests.post(base_url, data=data, headers=headers, verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and (
                    is_rce_response(r.text)
                    and r.text.lower() != baseline
                    and abs(len(r.text) - len(baseline)) > 50
                ):
                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[POST][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                    break
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
                for i in inputs:
                    name = i.get("name")
                    if name and name.lower() in rce_params:
                        data[name] = payload

                if not data:
                    continue

                full_url = urljoin(url, action) if action else url
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                
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
                if res.status_code == 200 and (
                    is_rce_response(res.text)
                    and res.text.lower() != baseline
                    and abs(len(res.text) - len(baseline)) > 50
                ):
                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded_data = {k: quote(v, safe='') for k, v in data.items()}
                                print_vulnerability(f"\033[1;32m[FORM][VULNERABLE]\033[0m {full_url}\n{encoded_data}")
                            
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

    def _iter_rce_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
                yield (test_post, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)

    run_threadpool_pending_bounded(_iter_rce_tasks(), threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
        print()
    if vulnerable_endpoints:
        print(f'\033[1;36m[+] Found {len(vulnerable_endpoints)} potential RCE vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No RCE vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables

    return urls_vulnerables
