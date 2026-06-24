import requests
import sys
import os
import threading
import secrets
import urllib3
from urllib.parse import urlparse
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from parametizer.bounded_pool import run_threadpool_pending_bounded
try:
    from scanners.throttle import request_throttle
except ImportError:
    from throttle import request_throttle


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.block_handler import create_safe_request_session
    BLOCK_HANDLER_AVAILABLE = True
except ImportError:
    BLOCK_HANDLER_AVAILABLE = False

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Headers que se inyectan con el marker
_INJECT_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-Host",
]

_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
)


def _is_static_path(url: str) -> bool:
    return urlparse(url).path.lower().endswith(_STATIC_EXTENSIONS)


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


def hostheader_injection(
    urip: list,
    urif: list,
    threads: int,
    custom_headers=None,
    random_agent: bool = False,
):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Host Header Injection \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()

    # Marker único por ejecución — 8 hex chars aleatorios
    marker = f"neluxhhi{secrets.token_hex(4)}.invalid"

    # Deduplicar por base URL para no testear el mismo endpoint múltiples veces
    seen_bases: set = set()
    candidate_urls: list = []
    for url in (urip or []):
        if _is_static_path(url):
            continue
        base = _base_url(url)
        if base not in seen_bases:
            seen_bases.add(base)
            candidate_urls.append(base)

    # Dominios ya encontrados vulnerables — una vez confirmado el dominio,
    # no se reportan más URLs del mismo host (evita miles de findings iguales).
    vulnerable_domains: set = set()

    total = len(candidate_urls)
    current = 0
    found = 0
    lock = threading.Lock()
    stdout_lock = threading.Lock()
    urls_vulnerables: list = []

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()

    def test_url(url: str):
        request_throttle(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).netloc)
        nonlocal current, found

        url_host = urlparse(url).netloc
        with lock:
            if url_host in vulnerable_domains:
                current += 1
                update_progress(current, total)
                return

        if vuln_manager.should_skip_url(url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total)
            return

        base_headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if BLOCK_HANDLER_AVAILABLE:
            session = create_safe_request_session(base_headers)
        else:
            session = requests.Session()
            session.headers.update(base_headers)

        if ban.is_banned(url_host):
            with lock:
                current += 1
                update_progress(current, total)
            return

        # Baseline sin inyección
        try:
            baseline = session.get(url, verify=False, timeout=5, allow_redirects=False)
            ban.record(url_host, baseline.status_code, baseline, url)
            baseline_text = baseline.text
        except Exception:
            with lock:
                current += 1
                update_progress(current, total)
            return

        # Probar cada header individualmente para saber cuál es el responsable
        for hdr in _INJECT_HEADERS:
            injected = dict(base_headers)
            injected[hdr] = marker
            try:
                r = session.get(
                    url,
                    headers=injected,
                    verify=False,
                    timeout=5,
                    allow_redirects=False,
                )
            except Exception:
                continue

            # Detectar reflejo del marker en body o Location
            reflected_in_body = marker in r.text and marker not in baseline_text
            reflected_in_location = marker in r.headers.get("Location", "")

            if reflected_in_body or reflected_in_location:
                if not vuln_manager.is_already_exploited(url, hdr):
                    vuln_manager.mark_as_exploited(url, hdr)
                    vuln_manager.mark_as_exploited(url, base_url_only=True)
                    where = "Location" if reflected_in_location else "body"
                    with lock:
                        if url_host in vulnerable_domains:
                            break  # Ya reportado para este dominio
                        vulnerable_domains.add(url_host)
                    with stdout_lock:
                        print_vulnerability(
                            f"\033[1;32m[HHI] [VULNERABLE]\033[0m {url} "
                            f"| header: {hdr} | reflected in {where}"
                        )
                    urls_vulnerables.append(f"{url} [header:{hdr}]")
                    found += 1
                break  # Un header vulnerable es suficiente para reportar la URL

        with lock:
            current += 1
            update_progress(current, total)

    def _tasks():
        for url in candidate_urls:
            yield (test_url, url)

    try:
        run_threadpool_pending_bounded(_tasks(), threads)
    except KeyboardInterrupt:
        from parametizer.interrupt import is_interrupted
        if is_interrupted():
            return urls_vulnerables
        raise

    sys.stdout.write('\r' + ansi.clear_line())
    sys.stdout.flush()
    print()

    if found > 0:
        print(f'\033[1;36m[+] Found {found} Host Header Injection vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No Host Header Injection vulnerabilities found\033[0m')
    print()

    return urls_vulnerables
