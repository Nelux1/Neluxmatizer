import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import urllib3
import random
from colorama import ansi, Cursor
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import sys, time, json, threading, os

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
    for attempt in range(retries):
        # Timeout más largo desde el principio: 15 segundos base + 5 por intento
        timeout_val = 15 + (attempt * 5)
        try:
            # Crear sesión segura con manejo de bloqueos si está disponible
            if BLOCK_HANDLER_AVAILABLE:
                session = create_safe_request_session(get_headers())
            else:
                session = requests.Session()
                session.headers.update(get_headers())
            
            response = session.get(WAYBACK_API, params={
                "url": domain + "/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey"
            }, timeout=timeout_val, verify=False)
            if response.status_code == 200:
                try:
                    return list(set(entry[0] for entry in response.json()[1:]))
                except Exception as parse_error:
                    sys.stdout.write(f"\033[1;33m[!] Wayback JSON parse error:\033[0m {parse_error}\n")
                    sys.stdout.flush()
            else:
                sys.stdout.write(f"\033[1;31m[!] Wayback HTTP error:\033[0m {response.status_code}\n")
                sys.stdout.flush()
        except Exception as e:
            # Solo mostrar error en reintentos (no en el primer intento)
            if attempt > 0:
                sys.stdout.write(f"\033[1;31m[!] Error Wayback Timeout (retrying {attempt+1})\033[0m: {e}\n")
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
        
        index_list = session.get(COMMONCRAWL_INDEX, timeout=15).json()
        for index in index_list[:2]:  # limit to first 2 indexes
            index_url = index['cdx-api']
            try:
                resp = session.get(index_url, params={"url": domain + "/", "output": "json"}, timeout=15)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                urls.add(data['url'])
                        except:
                            continue
            except:
                continue
    except Exception as e:
        #print(f"\033[1;31m[!]\033[0m Error fetching CommonCrawl: {e}")
        pass
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
        except Exception as e:
            # Solo mostrar error en reintentos (no en el primer intento)
            if attempt > 0:
                sys.stdout.write(f"\033[1;31m[!] Error crt.sh Timeout (retrying {attempt+1})\033[0m: {e}\n")
                sys.stdout.flush()
        time.sleep(3)
    return urls

def get_sitemap_urls(domain):
    sitemap_url = ensure_url_format(domain) + "/sitemap.xml"
    urls = set()
    try:
        response = requests.get(sitemap_url, headers=get_headers(), timeout=10, verify=False)
        if response.status_code == 200:
            tree = ET.fromstring(response.content)
            for url in tree.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                urls.add(url.text.strip())
    except Exception as e:
        sys.stdout.write("\033[1;31m[!]\033[0m sitemap.xml not found\n")
        sys.stdout.flush()
        #print(f"\033[1;31m[!]\033[0m Error fetching sitemap.xml: {e}")
    return urls

def get_robots_urls(domain):
    robots_url = ensure_url_format(domain) + ROBOTS_TXT
    urls = set()
    try:
        response = requests.get(robots_url, headers=get_headers(), timeout=8, verify=False)
        if response.status_code == 200:
            for line in response.text.splitlines():
                line = line.strip()
                if line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
                    parts = line.split(":")
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and not path.startswith("#") and path != "/":
                            full = urljoin(domain, path)
                            urls.add(full)
    except Exception as e:
        sys.stdout.write("\033[1;31m[!]\033[0m robots.txt not found\n")
        sys.stdout.flush()
        #print(f"\033[1;31m[!]\033[0m Error fetching robots.txt: {e}")
    return urls

def crawl_site(start_url, max_depth=2, threads=5):
    visited = set()
    found_urls = set()
    to_visit = [(start_url, 0)]
    stdout_lock = threading.Lock()

    def fetch_and_extract(current_url, depth):
        if current_url in visited or depth > max_depth:
            return []
        visited.add(current_url)

        # No imprimir aquí, solo procesar
        new_links = []
        try:
            response = requests.get(current_url, headers=get_headers(), timeout=7, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                parsed_href = urlparse(href)
                if parsed_href.netloc and parsed_href.netloc != urlparse(start_url).netloc:
                    continue  # skip external
                joined = urljoin(current_url, href)
                if joined not in visited:
                    new_links.append((joined, depth + 1))
                    found_urls.add(joined)
        except Exception:
            pass
        return new_links

        new_links = []
        try:
            response = requests.get(current_url, headers=get_headers(), timeout=7, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                parsed_href = urlparse(href)
                if parsed_href.netloc and parsed_href.netloc != urlparse(start_url).netloc:
                    continue  # skip external
                joined = urljoin(current_url, href)
                if joined not in visited:
                    new_links.append((joined, depth + 1))
                    found_urls.add(joined)
        except Exception:
            pass
        return new_links

    with ThreadPoolExecutor(max_workers=threads) as executor:
        total_processed = 0
        while to_visit:
            futures = []
            for _ in range(min(len(to_visit), threads)):
                url, depth = to_visit.pop()
                futures.append(executor.submit(fetch_and_extract, url, depth))
            
            # Mostrar progreso sincronizado
            for future in futures:
                try:
                    results = future.result()
                    to_visit.extend(results)
                    total_processed += 1
                    
                    # Actualizar progreso en una sola línea
                    with stdout_lock:
                        sys.stdout.write('\r' + ansi.clear_line())
                        sys.stdout.write(f"🌐 Crawling: {total_processed} URLs processed, {len(to_visit)} pending")
                        sys.stdout.flush()
                except:
                    total_processed += 1
                    continue

    # Limpiar la línea final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    
    return found_urls

def save_it(output_file, lines):
    with open(output_file, "a") as f:
        for line in lines:
            f.write(line + "\n")

def parametizer(domain, output_file=None, threads=5):
    domain = ensure_url_format(domain)
    parsed_domain = urlparse(domain).netloc.lower()

    all_urls = set()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(get_wayback_urls, domain),
            executor.submit(get_commoncrawl_urls, parsed_domain),
            executor.submit(get_crtsh_subdomains, parsed_domain),
        ]
        for future in futures:
            try:
                result = future.result()
                if isinstance(result, list) or isinstance(result, set):
                    all_urls.update(result)
            except Exception as e:
                sys.stdout.write(f"\033[1;31m[!]\033[0m Error in source thread: {e}\n")
                sys.stdout.flush()

    all_urls.update(get_sitemap_urls(domain))
    all_urls.update(get_robots_urls(domain))
    all_urls.update(crawl_site(domain, threads=threads))

    filtered = set()
    for url in all_urls:
        try:
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https") and not url.endswith(STATIC_EXTENSIONS):
                filtered.add(url)
        except:
            continue

    # Imprimir el total de URLs en la misma línea del progreso
    from .progress import spinner_lock
    with spinner_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.write(f"\033[1;36m[+]\033[0m Total URLs collected: {len(filtered)}\n")
        sys.stdout.flush()

    lines = sorted(filtered)
    if output_file:
        save_it(output_file, lines)

    return lines
