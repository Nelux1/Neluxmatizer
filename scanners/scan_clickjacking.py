import requests
import sys
import os
import re
from urllib.parse import urlparse
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.bounded_pool import run_threadpool_in_chunks
from threading import Lock
from parametizer.core.headers import get_headers
from parametizer.progress import update_progress, print_vulnerability
from colorama import init, ansi

init()

# Regex para extraer la directiva frame-ancestors de un CSP header
_FA_RE = re.compile(r'(?:^|;)\s*frame-ancestors\s+([^;]+)', re.IGNORECASE)

# Rutas que casi nunca son páginas HTML embebibles (APIs, feeds, manifests, scripts)
_NON_HTML_PATH_PATTERNS = re.compile(
    r'(/api/|/rest/|/graphql|/rpc|/soap|/ws/|/v[0-9]+/|/feed/?$|/atom/?$|/rss/?$'
    r'|/__manifest|/manifest\.json|\.json(\?|$)|\.xml(\?|$)|\.sh(\?|$)'
    r'|/swagger|/openapi|/health|/metrics|/ping|/status)',
    re.IGNORECASE,
)


def _framing_protection(resp_headers):
    """
    Devuelve (protected: bool, reason: str).

    Lógica:
    1. X-Frame-Options: DENY / SAMEORIGIN → protegido.
    2. CSP con frame-ancestors:
       - 'none' o 'self' (o dominio específico sin '*') → protegido.
       - solo '*' → vulnerable.
    3. Sin ninguna de las dos → vulnerable.

    No se considera CSP sin frame-ancestors como protección válida;
    muchos sitios tienen CSP por otras razones (script-src, etc.)
    y no configuran frame-ancestors.
    """
    xfo = resp_headers.get('X-Frame-Options', '').strip().upper()
    if xfo in ('DENY', 'SAMEORIGIN'):
        return True, f"X-Frame-Options: {resp_headers['X-Frame-Options']}"

    csp = resp_headers.get('Content-Security-Policy', '')
    if csp:
        match = _FA_RE.search(csp)
        if match:
            value = match.group(1).strip().lower()
            # frame-ancestors * → no protege
            if value == '*':
                return False, f"CSP frame-ancestors: * (allows all origins)"
            # Cualquier otra directiva (none, self, dominio) → protegido
            return True, f"CSP frame-ancestors: {match.group(1).strip()}"

    return False, "Missing X-Frame-Options and no CSP frame-ancestors directive"


def clickjacking(urip, urif, urls_vulnerables, threads, custom_headers, random_agent):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Clickjacking \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()

    # Configuración
    total_tasks = len(urip) + len(urif)
    progress = 0
    found = 0
    lock = Lock()
    found_urls = set()
    
    # Cache para respuestas y sincronización de salida
    response_cache = {}
    stdout_lock = Lock()

    # Construcción del header
    # def get_headers():
    #     headers = custom_headers or {}
    #     headers.setdefault('User-Agent', 'Mozilla/5.0')
    #     return headers

    def test_url(url):
        nonlocal progress, found
        
        # Filtrar archivos estáticos que no pueden ser vulnerables a Clickjacking
        static_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',  # Imágenes
            '.css', '.js', '.min.css', '.min.js',  # CSS y JavaScript
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Documentos
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',  # Videos
            '.mp3', '.wav', '.ogg', '.flac',  # Audio
            '.zip', '.rar', '.7z', '.tar', '.gz',  # Archivos comprimidos
            '.ttf', '.woff', '.woff2', '.eot',  # Fuentes
            '.xml', '.json', '.txt', '.csv',  # Datos
            '.exe', '.dmg', '.deb', '.rpm', '.msi'  # Ejecutables
        ]
        
        if any(ext in url.lower() for ext in static_extensions):
            with lock:
                progress += 1
                update_progress(progress, total_tasks)
            return

        # Saltar API endpoints, feeds, manifests y rutas claramente no-HTML
        parsed_path = urlparse(url).path if url else ''
        if _NON_HTML_PATH_PATTERNS.search(url):
            with lock:
                progress += 1
                update_progress(progress, total_tasks)
            return

        try:
            # Cache de respuestas para evitar requests duplicadas
            if url not in response_cache:
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                response_cache[url] = response
            else:
                response = response_cache[url]

            # Ignorar redirects (30x): la respuesta de redirect no tiene headers
            # de framing propios — lo que importa es la página final (HTTPS canonical).
            if response.status_code in (301, 302, 303, 307, 308):
                with lock:
                    progress += 1
                    update_progress(progress, total_tasks)
                return

            # Ignorar respuestas que no son HTML (API JSON, XML, scripts, etc.)
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                with lock:
                    progress += 1
                    update_progress(progress, total_tasks)
                return

            headers2 = response.headers

            protected, reason = _framing_protection(headers2)
            if not protected:
                with lock:
                    if url not in found_urls:
                        found += 1
                        found_urls.add(url)

                        with stdout_lock:
                            print_vulnerability(f"\033[1;32m[VULNERABLE]\033[0m {url}")
                            print(f"Missing protection: {reason}")

                        urls_vulnerables.append(url)
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass
        finally:
            with lock:
                progress += 1
                update_progress(progress, total_tasks)

    tasks = [u for u in urip + urif if u not in found_urls]
    run_threadpool_in_chunks(test_url, tasks, threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    
        print()
    if found > 0:
        print(f'\033[1;36m[+] Found {found} potential Clickjacking vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No Clickjacking vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
