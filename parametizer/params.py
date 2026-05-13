import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import random
import re
import gzip
from colorama import ansi, Cursor
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import sys, time, json, threading, os
from collections import deque
from typing import List, Optional, Set, Tuple

from .progress import spinner_lock, fmt_line

# Importar el sistema de manejo de bloqueos
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.block_handler import create_safe_request_session
    BLOCK_HANDLER_AVAILABLE = True
except ImportError:
    BLOCK_HANDLER_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAYBACK_API = "https://web.archive.org/cdx/search/cdx"
COMMONCRAWL_INDEX = "https://index.commoncrawl.org/collinfo.json"
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
ROBOTS_TXT = "/robots.txt"

# Semillas típicas de sitemap (además de las líneas Sitemap: en robots.txt)
SITEMAP_COMMON_PATHS: Tuple[str, ...] = (
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/wp-sitemap.xml",
    "/sitemap/sitemap.xml",
    "/post-sitemap.xml",
    "/page-sitemap.xml",
)

# Regex ligera para URLs http(s) en HTML bruto (SPAs / JS embebido)
_RAW_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".eot", ".mp4", ".webm", ".pdf"
)

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36"
]

def ensure_url_format(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url

def get_headers(custom_headers=None):
    headers = {'User-Agent': random.choice(user_agents)}
    if custom_headers:
        headers.update(custom_headers)
    return headers

def get_wayback_urls(domain, retries=3):
    """
    CDX API puede devolver JSON enorme (p. ej. nasa.gov) y cortar por timeout o JSON inválido.
    Se usa limit decreciente y timeout de lectura largo (connect, read).
    """
    limits = [250000, 120000, 60000]
    for attempt in range(retries):
        read_timeout = 100 + attempt * 80
        timeout_tuple = (25, read_timeout)
        limit = limits[min(attempt, len(limits) - 1)]
        try:
            if BLOCK_HANDLER_AVAILABLE:
                session = create_safe_request_session(get_headers())
            else:
                session = requests.Session()
                session.headers.update(get_headers())

            response = session.get(
                WAYBACK_API,
                params={
                    "url": domain + "/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": limit,
                },
                timeout=timeout_tuple,
                verify=False,
            )
            if response.status_code == 200:
                try:
                    data = response.json()
                    if not data or len(data) < 2:
                        return []
                    return list(set(entry[0] for entry in data[1:]))
                except json.JSONDecodeError as parse_error:
                    # CDX devuelve un array JSON gigante; si corta red/timeout/servidor → JSON truncado (no es bug del dominio).
                    with spinner_lock:
                        sys.stdout.write("\r" + ansi.clear_line())
                        sys.stdout.write(
                            f"\033[1;33m[!] Wayback: respuesta JSON truncada o incompleta (limit={limit}); reintentando con menos filas…\033[0m\n"
                            f"    \033[2m{parse_error}\033[0m\n"
                        )
                        sys.stdout.flush()
                except Exception as parse_error:
                    with spinner_lock:
                        sys.stdout.write("\r" + ansi.clear_line())
                        sys.stdout.write(
                            f"\033[1;33m[!] Wayback JSON parse error (limit={limit}):\033[0m {parse_error}\n"
                        )
                        sys.stdout.flush()
            else:
                with spinner_lock:
                    sys.stdout.write("\r" + ansi.clear_line())
                    sys.stdout.write(
                        f"\033[1;31m[!] Wayback HTTP error:\033[0m {response.status_code}\n"
                    )
                    sys.stdout.flush()
        except Exception as e:
            with spinner_lock:
                sys.stdout.write("\r" + ansi.clear_line())
                sys.stdout.write(
                    f"\033[1;31m[!] Wayback error (attempt {attempt + 1}/{retries}, limit={limit}):\033[0m {e}\n"
                )
                sys.stdout.flush()
        time.sleep(3)
    return []

def get_commoncrawl_urls(domain):
    urls = set()
    try:
        # Crear sesión segura con manejo de bloqueos si está disponible
        if BLOCK_HANDLER_AVAILABLE:
            session = create_safe_request_session(get_headers())
        else:
            session = requests.Session()
            session.headers.update(get_headers())

        # collinfo a veces corta conexión (carga, rate limit); reintentar antes de fallar el hilo
        index_list = None
        last_idx_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                idx_resp = session.get(COMMONCRAWL_INDEX, timeout=20)
                idx_resp.raise_for_status()
                index_list = idx_resp.json()
                break
            except Exception as ex:
                last_idx_err = ex
                time.sleep(1.5 + attempt)
        if index_list is None:
            raise last_idx_err if last_idx_err else RuntimeError("collinfo vacío")

        if not isinstance(index_list, list):
            raise ValueError("collinfo.json no es una lista")

        # CDX acepta comodines; domain/ solo cubre un prefijo estrecho — *.dominio/* alinea mejor con Wayback (dominio/*)
        url_patterns = (f"*.{domain}/*", f"{domain}/*")
        for index in index_list[:2]:  # limit to first 2 indexes
            index_url = index["cdx-api"]
            for url_pat in url_patterns:
                try:
                    resp = session.get(
                        index_url,
                        params={"url": url_pat, "output": "json"},
                        timeout=20,
                    )
                    if resp.status_code != 200:
                        continue
                    for line in resp.text.splitlines():
                        try:
                            data = json.loads(line)
                            if "url" in data:
                                urls.add(data["url"])
                        except Exception:
                            continue
                except Exception:
                    continue
    except Exception:
        with spinner_lock:
            sys.stdout.write("\r" + ansi.clear_line())
            sys.stdout.flush()
        raise
    return list(urls)

def get_crtsh_subdomains(domain, retries=3):
    urls = set()
    for attempt in range(retries):
        # Timeout más largo desde el principio: 15 segundos base + 5 por intento
        timeout_val = 15 + (attempt * 5)
        try:
            resp = requests.get(CRT_SH_URL.format(domain=domain), timeout=timeout_val)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        if sub and domain in sub:
                            urls.add(ensure_url_format(sub))
                break
        except Exception:
            # Solo mostrar error en reintentos (no en el primer intento)
            if attempt > 0:
                sys.stdout.write(
                    f"\033[1;31m[!] Error crt.sh Timeout (retrying {attempt + 1})\033[0m\n"
                )
                sys.stdout.flush()
        time.sleep(3)
    return urls

def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0] if url else url


def _local_tag(el) -> str:
    if el is None or not hasattr(el, "tag"):
        return ""
    t = el.tag
    return t.split("}")[-1].lower() if t else ""


def _fetch_robots_txt(base_url: str) -> Optional[str]:
    """base_url sin barra final; devuelve texto o None."""
    url = base_url.rstrip("/") + ROBOTS_TXT
    try:
        r = requests.get(url, headers=get_headers(), timeout=10, verify=False)
        if r.status_code == 200 and r.text:
            return r.text
    except Exception:
        pass
    return None


def _parse_robots_sitemap_lines(robots_txt: str) -> List[str]:
    out: List[str] = []
    for line in robots_txt.splitlines():
        line = line.strip()
        if line.lower().startswith("sitemap:"):
            rest = line.split(":", 1)
            if len(rest) == 2:
                u = rest[1].strip()
                if u and not u.startswith("#"):
                    out.append(u)
    return out


def _parse_sitemap_xml_bytes(content: bytes) -> Tuple[Set[str], Set[str]]:
    """(urls de páginas, URLs de sitemaps hijos anidados)."""
    pages: Set[str] = set()
    nested: Set[str] = set()
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return pages, nested

    rt = _local_tag(root)
    if rt == "sitemapindex":
        for el in root.iter():
            if _local_tag(el) == "loc" and el.text:
                nested.add(el.text.strip())
        return pages, nested

    if rt == "urlset":
        for el in root.iter():
            if _local_tag(el) == "loc" and el.text:
                pages.add(el.text.strip())
        return pages, nested

    # Fallback: cualquier <loc> (namespaces raros)
    for el in root.iter():
        if _local_tag(el) == "loc" and el.text:
            u = el.text.strip()
            lu = u.lower()
            if lu.endswith(".xml") or "sitemap" in urlparse(u).path.lower():
                nested.add(u)
            else:
                pages.add(u)
    return pages, nested


def gather_sitemap_urls(domain: str, robots_txt: Optional[str] = None) -> Set[str]:
    """
    Sitemaps desde robots.txt (Sitemap:), rutas comunes, índices anidados (sitemap index),
    y URLs en urlset. Similar a lo que hace Katana al seguir sitemaps.
    """
    base = ensure_url_format(domain).rstrip("/")
    if robots_txt is None:
        robots_txt = _fetch_robots_txt(base)

    seeds: List[str] = []
    if robots_txt:
        seeds.extend(_parse_robots_sitemap_lines(robots_txt))
    for p in SITEMAP_COMMON_PATHS:
        seeds.append(base + p)

    seeds = list(dict.fromkeys(seeds))
    seen_sitemaps: Set[str] = set()
    page_urls: Set[str] = set()
    queue: List[str] = list(seeds)

    max_fetch = 80
    max_pages = 25000
    fetches = 0
    got_valid_xml = False

    while queue and fetches < max_fetch and len(page_urls) < max_pages:
        sm_url = queue.pop(0)
        key = _strip_fragment(sm_url)
        if key in seen_sitemaps:
            continue
        seen_sitemaps.add(key)

        try:
            r = requests.get(sm_url, headers=get_headers(), timeout=14, verify=False)
            fetches += 1
            if r.status_code != 200:
                continue

            data = r.content
            if sm_url.lower().endswith(".gz") or "gzip" in r.headers.get("Content-Encoding", "").lower():
                try:
                    data = gzip.decompress(data)
                except Exception:
                    continue

            pages, nested = _parse_sitemap_xml_bytes(data)
            if pages or nested:
                got_valid_xml = True
            page_urls.update(pages)
            for n in nested:
                nk = _strip_fragment(n)
                if nk not in seen_sitemaps:
                    queue.append(n)
        except Exception:
            continue

    with spinner_lock:
        sys.stdout.write("\r" + ansi.clear_line())
        if not page_urls and not got_valid_xml and seeds:
            sys.stdout.write(
                fmt_line("1;31", "[!] Sitemap:", "not found or empty") + "\n"
            )
            sys.stdout.flush()
        elif got_valid_xml and page_urls:
            sys.stdout.write(
                fmt_line("1;32", "[+] Sitemap:", f"{len(page_urls)} URL(s)") + "\n"
            )
            sys.stdout.flush()

    return page_urls


def get_sitemap_urls(domain):
    """Compat: delega en gather_sitemap_urls."""
    return gather_sitemap_urls(domain)


def get_robots_urls(domain, robots_txt: Optional[str] = None) -> Set[str]:
    """
    Allow:/Disallow: de robots.txt como pistas de path (mismo host).
    Las líneas Sitemap: las consume gather_sitemap_urls.
    """
    base = ensure_url_format(domain).rstrip("/")
    if robots_txt is None:
        robots_txt = _fetch_robots_txt(base)
    urls: Set[str] = set()
    if not robots_txt:
        with spinner_lock:
            sys.stdout.write(
                fmt_line("1;31", "[!] robots.txt:", "not found") + "\n"
            )
            sys.stdout.flush()
        return urls

    netloc = urlparse(base).netloc.lower()
    base_join = base + "/"
    for line in robots_txt.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("allow:") or low.startswith("disallow:"):
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            path = parts[1].strip()
            if not path or path.startswith("#") or path == "/":
                continue
            full = urljoin(base_join, path)
            if urlparse(full).netloc.lower() != netloc:
                continue
            urls.add(_strip_fragment(full))

    if urls:
        with spinner_lock:
            sys.stdout.write(
                fmt_line("1;32", "[+] robots.txt:", f"{len(urls)} path hint(s)") + "\n"
            )
            sys.stdout.flush()
    return urls


def _extract_urls_from_html(soup: BeautifulSoup, current_url: str, allowed_netloc: str) -> Set[str]:
    """href/src/action y más etiquetas + URLs en HTML crudo (SPAs / strings)."""
    out: Set[str] = set()

    def add_one(raw: Optional[str]) -> None:
        if not raw:
            return
        raw = raw.strip()
        if raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return
        u = raw
        if not u.startswith(("http://", "https://")):
            u = urljoin(current_url, u)
        u = _strip_fragment(u)
        if not u.startswith(("http://", "https://")):
            return
        if urlparse(u).netloc.lower() != allowed_netloc:
            return
        out.add(u)

    tag_attrs = (
        ("a", "href"),
        ("area", "href"),
        ("link", "href"),
        ("iframe", "src"),
        ("frame", "src"),
        ("embed", "src"),
        ("object", "data"),
        ("script", "src"),
        ("img", "src"),
        ("source", "src"),
        ("form", "action"),
    )
    for tag, attr in tag_attrs:
        try:
            for el in soup.find_all(tag, **{attr: True}):
                val = el.get(attr)
                if val:
                    add_one(val)
        except Exception:
            continue

    try:
        raw = str(soup)
        for m in _RAW_URL_RE.findall(raw)[:500]:
            add_one(m.rstrip(".,;:)"))
    except Exception:
        pass

    return out


def crawl_site(start_url, max_depth=3, threads=8):
    start_url = ensure_url_format(start_url).rstrip("/")
    allowed_netloc = urlparse(start_url).netloc.lower()
    visited = set()
    found_urls = set()
    found_urls.add(start_url)
    to_visit: deque = deque([(start_url, 0)])
    stdout_lock = threading.Lock()

    def fetch_and_extract(current_url, depth):
        if current_url in visited or depth > max_depth:
            return []
        visited.add(current_url)

        new_links = []
        try:
            response = requests.get(current_url, headers=get_headers(), timeout=10, verify=False)
            ct = response.headers.get("Content-Type", "").lower()
            if "html" not in ct and "text" not in ct:
                return []
            soup = BeautifulSoup(response.text, "html.parser")
            for u in _extract_urls_from_html(soup, current_url, allowed_netloc):
                found_urls.add(u)
                if u not in visited:
                    new_links.append((u, depth + 1))
        except Exception:
            pass
        return new_links

    with ThreadPoolExecutor(max_workers=threads) as executor:
        total_processed = 0
        while to_visit:
            futures = []
            batch = min(len(to_visit), threads)
            for _ in range(batch):
                url, depth = to_visit.popleft()
                futures.append(executor.submit(fetch_and_extract, url, depth))

            for future in futures:
                try:
                    results = future.result()
                    to_visit.extend(results)
                    total_processed += 1
                    with stdout_lock:
                        sys.stdout.write("\r" + ansi.clear_line())
                        sys.stdout.write(
                            f"🌐 Crawling: {total_processed} URLs processed, {len(to_visit)} pending"
                        )
                        sys.stdout.flush()
                except Exception:
                    total_processed += 1
                    continue

    with stdout_lock:
        sys.stdout.write("\r" + ansi.clear_line())
        sys.stdout.flush()

    return found_urls

def save_it(output_file, lines):
    with open(output_file, "a") as f:
        for line in lines:
            f.write(line + "\n")


def _heartbeat_collect_sources(stop: threading.Event) -> None:
    """Spinner mientras corren Wayback / Common Crawl / crt.sh / sitemap en paralelo."""
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop.is_set():
        with spinner_lock:
            c = frames[i % len(frames)]
            sys.stdout.write(
                f"\r{ansi.clear_line()}\r\033[1;36m{c}\033[0m  "
                "Collecting URL sources"
            )
            sys.stdout.flush()
        i += 1
        if stop.wait(0.12):
            break
    with spinner_lock:
        sys.stdout.write("\r" + ansi.clear_line())
        sys.stdout.flush()


def parametizer(domain, output_file=None, threads=5):
    domain = ensure_url_format(domain)
    parsed_domain = urlparse(domain).netloc.lower()
    base = domain.rstrip("/")
    robots_txt = _fetch_robots_txt(base)

    all_urls = set()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        pending = {
            executor.submit(get_wayback_urls, domain): "Wayback",
            executor.submit(get_commoncrawl_urls, parsed_domain): "Common Crawl",
            executor.submit(get_crtsh_subdomains, parsed_domain): "crt.sh",
            executor.submit(gather_sitemap_urls, domain, robots_txt): "Sitemap",
        }
        stop_hb = threading.Event()
        hb_thread = threading.Thread(target=_heartbeat_collect_sources, args=(stop_hb,), daemon=True)
        hb_thread.start()
        try:
            for fut in as_completed(pending):
                label = pending[fut]
                try:
                    result = fut.result()
                    if isinstance(result, list):
                        all_urls.update(result)
                    elif isinstance(result, set):
                        all_urls.update(result)
                    if label != "Sitemap":
                        n = len(result) if isinstance(result, (list, set)) else 0
                        with spinner_lock:
                            sys.stdout.write("\r" + ansi.clear_line())
                            sys.stdout.write(
                                fmt_line("1;32", f"[+] {label}:", f"{n} URL(s)") + "\n"
                            )
                            sys.stdout.flush()
                except Exception as e:
                    if label == "Common Crawl":
                        continue
                    with spinner_lock:
                        sys.stdout.write("\r" + ansi.clear_line())
                        sys.stdout.write(
                            f"\033[1;31m[!] {label} error:\033[0m {e}\n"
                        )
                        sys.stdout.flush()
        finally:
            stop_hb.set()
            hb_thread.join(timeout=5)

    all_urls.update(get_robots_urls(domain, robots_txt))

    all_urls.update(crawl_site(domain, threads=threads))

    filtered = set()
    for url in all_urls:
        try:
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and not parsed.path.lower().endswith(STATIC_EXTENSIONS):
                filtered.add(url)
        except:
            continue

    # Total de URLs: lo imprime scan_lista tras headless (evita duplicar "Total URLs collected")
    with spinner_lock:
        sys.stdout.write("\r" + ansi.clear_line())
        sys.stdout.flush()

    lines = sorted(filtered)
    if output_file:
        save_it(output_file, lines)

    return lines
