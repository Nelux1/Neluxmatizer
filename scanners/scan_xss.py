import requests
import random
import re
import sys
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

# ── DOM XSS headless config ────────────────────────────────────────────────────
_DOM_XSS_PAYLOADS = [
    "<img src=x onerror=\"alert('neluxXSS')\">",
    "<svg/onload=\"alert('neluxXSS')\">",
    "<iframe src=\"javascript:alert('neluxXSS')\">",
    "<details open ontoggle=\"alert('neluxXSS')\">",
]
_DOM_XSS_MARKER    = "neluxXSS"
_DOM_XSS_URL_LIMIT = 80    # max URLs testeadas headlessly
_DOM_XSS_TIMEOUT   = 7000  # ms por navegación
_DOM_XSS_SETTLE    = 2000  # ms de espera post-load para que el framework renderice

# Parámetros que suelen reflejarse en el DOM (mayor prioridad en el batch headless)
_DOM_XSS_PRIORITY_PARAMS: frozenset = frozenset({
    "q", "s", "search", "query", "keyword", "keywords", "term", "terms",
    "content", "text", "input", "name", "value", "msg", "message",
    "comment", "data", "html", "title", "description", "body", "subject",
    "url", "redirect", "return", "next", "to", "from", "path",
    "file", "src", "source", "cat", "category", "type", "page",
})

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


def _strip_tracking_params(url: str) -> str:
    """
    Devuelve la URL sin parámetros de tracking (UTM, fbclid, etc.).
    Usada para normalizar URLs de formularios antes del dedup,
    evitando que la misma form en 50 variantes UTM genere 50 findings.
    """
    try:
        from urllib.parse import urlunparse
        p = urlparse(url)
        clean_qs = {k: v for k, v in parse_qs(p.query, keep_blank_values=True).items()
                    if k.lower() not in _TRACKING_PARAMS}
        from urllib.parse import urlencode
        return urlunparse(p._replace(query=urlencode(clean_qs, doseq=True)))
    except Exception:
        return url


def _dom_xss_sort_key(url: str) -> int:
    """Retorna 0 si la URL tiene al menos un param prioritario (va primero), 1 si no."""
    try:
        qs = parse_qs(urlparse(url).query)
        if any(p.lower() in _DOM_XSS_PRIORITY_PARAMS for p in qs):
            return 0
    except Exception:
        pass
    return 1


def _dom_xss_batch(
    urls: list,
    already_found: set,
    custom_headers: dict = None,
) -> list:
    """
    Fase DOM-based XSS con Playwright headless Chromium.

    Lanza UNA sola sesión de browser y prueba hasta _DOM_XSS_URL_LIMIT URLs.
    Detecta ejecución JS real escuchando el evento 'dialog' (alert/confirm/prompt).
    Las URLs con parámetros de alta prioridad (q=, search=, content=…) se prueban primero.

    Retorna lista de tuplas (url_con_payload, param, payload).
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from parametizer.headless_crawl import _prefer_bundled_playwright, _restore_sys_path
    except ImportError:
        return []

    inserted = _prefer_bundled_playwright()
    results = []

    try:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return []

        # Filtrar y ordenar: primero URLs candidatas con params prioritarios
        candidates = [
            u for u in urls
            if parse_qs(urlparse(u).query) and not _is_static_path(u)
            and f"{urlparse(u).scheme}://{urlparse(u).netloc}{urlparse(u).path}" not in already_found
        ]
        candidates.sort(key=_dom_xss_sort_key)
        candidates = candidates[:_DOM_XSS_URL_LIMIT]
        total_cand = len(candidates)

        if total_cand == 0:
            return []

        dialog_history: list = []

        def _on_dialog(dialog):
            try:
                msg = dialog.message or ""
            except Exception:
                msg = ""
            dialog_history.append(msg)
            try:
                dialog.dismiss()
            except Exception:
                pass

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-software-rasterizer",
                ],
            )
            try:
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=custom_headers or {},
                )
                page = ctx.new_page()
                page.on("dialog", _on_dialog)

                for idx, url in enumerate(candidates, 1):
                    # Progress en línea (sobreescribe la misma línea)
                    sys.stdout.write(
                        f"\r\033[K  [DOM XSS] {idx}/{total_cand} | {url[:80]}"
                    )
                    sys.stdout.flush()

                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    qs = parse_qs(parsed.query)

                    vuln_found_for_url = False
                    for param in qs:
                        if _is_non_injectable_param(param):
                            continue
                        if vuln_found_for_url:
                            break

                        for payload in _DOM_XSS_PAYLOADS:
                            dialog_history.clear()

                            data = {p: "TEST123" for p in qs}
                            data[param] = payload
                            test_url_str = base_url + "?" + urllib.parse.urlencode(data, doseq=True)

                            try:
                                page.goto(
                                    test_url_str,
                                    wait_until="domcontentloaded",
                                    timeout=_DOM_XSS_TIMEOUT,
                                )
                                page.wait_for_timeout(_DOM_XSS_SETTLE)
                            except Exception:
                                continue

                            if any(_DOM_XSS_MARKER in m for m in dialog_history):
                                sys.stdout.write("\r\033[K")
                                sys.stdout.flush()
                                results.append((test_url_str, param, payload))
                                vuln_found_for_url = True
                                break

            finally:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                try:
                    browser.close()
                except Exception:
                    pass

    except Exception:
        pass
    finally:
        _restore_sys_path(inserted)

    return results


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
    
    # Evitar páginas de error HTTP claras (sin contenido de la app)
    if "404 not found" in text.lower() or "403 forbidden" in text.lower() or "500 internal server error" in text.lower():
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

        if not qs or _is_static_path(url):
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
            if _is_non_injectable_param(param):
                continue

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
            if _is_non_injectable_param(param):
                continue

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
                        if not vuln_manager.is_already_exploited(base_url, param):
                            if not vuln_manager.verify_false_positive(base_url, payload, "POST", custom_headers, random_agent):
                                vuln_manager.mark_as_exploited(base_url, param)
                                vuln_manager.mark_as_exploited(base_url, base_url_only=True)

                                with stdout_lock:
                                    print_vulnerability(f"\033[1;32m[POST] [VULNERABLE]\033[0m {base_url}?{param}={quote(payload)}")

                                urls_vulnerables.append(f"{base_url}?{param}={quote(payload)}")
                                found += 1
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

                # URL normalizada para dedup: sin tracking params
                # Evita reportar N veces la misma form en páginas con diferentes UTM params
                norm_url = _strip_tracking_params(full_url)

                # Cache de baseline para formularios
                baseline_key = f"{method}-{norm_url}-{','.join(data.keys())}"
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
                    # Clave de dedup usando URL normalizada (sin UTM) y campos del form
                    key = f"{norm_url}|{','.join(sorted(data.keys()))}|{payload}"
                    if key not in vuln_set:
                        vuln_set.add(key)

                        with stdout_lock:
                            encoded_data = {k: urllib.parse.quote_plus(v) for k, v in data.items()}
                            print_vulnerability(f"\033[1;32m[FORM] [VULNERABLE]\033[0m {norm_url}" + "\033[1;32m ==> \033[0m" + f"{encoded_data}")

                        # Reportar con URL normalizada (sin UTM) para el PoC
                        urls_vulnerables.append(f"{norm_url} => {data}")
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

    # Limpiar salida fase HTTP
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()

    # ── Fase DOM XSS (Playwright headless) ────────────────────────────────────
    # Construye el set de bases ya encontradas en fase HTTP para no duplicar.
    http_found_bases: set = set()
    for vuln_url in list(urls_vulnerables):
        try:
            p0 = urlparse(vuln_url.split(" =>")[0].strip())
            http_found_bases.add(f"{p0.scheme}://{p0.netloc}{p0.path}")
        except Exception:
            pass

    print('\033[1;36m[*] DOM XSS phase (headless Chromium)...\033[0m')
    dom_results = _dom_xss_batch(urip, http_found_bases, custom_headers)

    dom_found = 0
    for (dom_url, dom_param, dom_payload) in dom_results:
        dom_parsed = urlparse(dom_url)
        dom_base = f"{dom_parsed.scheme}://{dom_parsed.netloc}{dom_parsed.path}"
        if not vuln_manager.is_already_exploited(dom_base, dom_param):
            vuln_manager.mark_as_exploited(dom_base, dom_param)
            vuln_manager.mark_as_exploited(dom_base, base_url_only=True)
            print_vulnerability(
                f"\033[1;32m[DOM] [VULNERABLE]\033[0m {dom_url}"
            )
            urls_vulnerables.append(dom_url)
            found += 1
            dom_found += 1

    print()
    if found > 0:
        http_n = found - dom_found
        parts = []
        if http_n > 0:
            parts.append(f"{http_n} HTTP")
        if dom_found > 0:
            parts.append(f"{dom_found} DOM")
        print(f'\033[1;36m[+] Found {found} XSS vulnerabilities ({", ".join(parts)})\033[0m')
    else:
        print('\033[1;31m[-] No XSS vulnerabilities found\033[0m')
    print()

    return urls_vulnerables
