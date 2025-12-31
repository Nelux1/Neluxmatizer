# parametizer_forms.py

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, parse_qs
from colorama import Cursor, ansi
from concurrent.futures import ThreadPoolExecutor
import sys
from parametizer.progress import update_progress
import urllib3
import warnings
import random
import threading

# Silenciar todos los warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agents = [
    "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
    "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
    "Mozilla/3.01 (Macintosh; PPC)",
    "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
    "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
    "Opera/8.00 (Windows NT 5.1; U; en)"
]

STATIC_FORM_EXT = (".pdf", ".xls", ".csv", ".zip", ".doc", ".docx", ".exe")

def get_headers(custom_headers=None):
    headers = {'User-Agent': random.choice(user_agents)}
    if custom_headers:
        headers.update(custom_headers)
    return headers

def save_it(output_file, lines):
    with open(output_file, "a") as f:
        for line in lines:
            f.write(line + "\n")

def parametizer_forms(urls, output_file=None, threads=50):
    """
    Busca formularios en las URLs recibidas.
    Asume que ya fueron verificadas como vivas.
    """
    total = len(urls)
    form_urls = []
    stdout_lock = threading.Lock()

    seen_signatures = set()
    unique_urls = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.scheme.startswith("http"):
                continue
            if url.lower().endswith(STATIC_FORM_EXT):
                continue
            params = parse_qs(parsed.query)
            sig = parsed.path + '?' + '&'.join(sorted(params.keys())) if params else parsed.path
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_urls.append(url)
        except:
            continue

    def process_url(url):
        try:
            response = requests.get(url, headers=get_headers(), verify=False, timeout=5)

            # Verificar redirecciones
            if response.url != url:
                return None

            # Verificar tipo de contenido
            if 'text/html' not in response.headers.get("Content-Type", ""):
                return None

            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form")
            if form and form.find("input"):
                return url

        except Exception:
            return None

    # Procesar URLs con threads pero sincronizar la salida
    def process_url_with_progress(url):
        try:
            response = requests.get(url, headers=get_headers(), verify=False, timeout=5)

            # Verificar redirecciones
            if response.url != url:
                return None

            # Verificar tipo de contenido
            if 'text/html' not in response.headers.get("Content-Type", ""):
                return None

            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form")
            if form and form.find("input"):
                return url

        except Exception:
            return None

    # Usar ThreadPoolExecutor con progreso secuencial
    from concurrent.futures import as_completed
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Crear un diccionario para rastrear el progreso
        futures = {executor.submit(process_url_with_progress, url): url for url in unique_urls}
        
        completed = 0
        for future in as_completed(futures):
            url = futures[future]
            completed += 1
            
            # Actualizar progreso en la misma línea
            with stdout_lock:
                progress_msg = f'\r🔍 Searching forms: {url[:90]}{"..." if len(url) > 90 else ""} ({completed}/{len(unique_urls)})'
                sys.stdout.write('\r\033[K' + progress_msg)
                sys.stdout.flush()
            
            try:
                result = future.result()
                if result:
                    form_urls.append(result)
            except Exception:
                pass

    # Limpiar la línea final completamente (ANSI clear line)
    with stdout_lock:
        sys.stdout.write('\r\x1b[2K')
        sys.stdout.write(f"\033[1;36m[+]\033[0m Total form URLs found: {len(form_urls)}\n")
        sys.stdout.flush()

    if output_file:
        save_it(output_file, form_urls)

    return form_urls
