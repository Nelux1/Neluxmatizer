import requests
import random
from urllib.parse import urlparse, urljoin
from colorama import init, ansi
from threading import Lock
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import os
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.bounded_pool import run_threadpool_pending_bounded
import urllib3, sys

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

xxe_indicators = [
    "root:", "uid=", "gid=", "/etc/passwd", "neluxmatizer",
    "bin:", "daemon:", "sys:", "adm:", "lp:", "mail:", "news:", "uucp:",
    "operator:", "games:", "man:", "at:", "cron:", "ftp:", "nobody:",
    "home=", "shell=", "group:", "shadow:", "passwd:", "hosts:", "fstab:",
    "xml", "entity", "external", "dtd", "doctype", "system", "public",
    "error", "exception", "warning", "fatal", "parse", "syntax"
]

def is_xxe_response(text, payload):
    """Validación MUCHO más estricta para detectar XXE real"""
    lower = text.lower()
    
    # 1. VERIFICACIÓN PRINCIPAL: Contenido de archivos del sistema (más confiable)
    system_indicators = [
        "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:", "sys:x:3:3:",
        "adm:x:4:4:", "lp:x:7:7:", "mail:x:8:8:", "news:x:9:9:",
        "uucp:x:10:10:", "operator:x:11:0:", "games:x:12:100:",
        "man:x:13:62:", "at:x:25:25:", "cron:x:16:16:", "ftp:x:21:21:",
        "nobody:x:99:99:", "systemd-network:x:192:192:", "systemd-resolve:x:193:193:"
    ]
    
    # Si contiene contenido real de /etc/passwd, es definitivamente vulnerable
    if any(indicator in text for indicator in system_indicators):
        return True, "System file content", "HIGH"
    
    # 2. VERIFICACIÓN SECUNDARIA: Errores específicos de XML parsing
    xml_specific_errors = [
        "xml external entity", "external entity", "dtd external", 
        "doctype external", "system entity", "public entity",
        "xml parse error", "xml syntax error", "xml fatal error"
    ]
    
    # Buscar errores específicos de XML (no solo palabras sueltas)
    if any(error in lower for error in xml_specific_errors):
        return True, "XML parsing error", "MEDIUM"
    
    # 3. VERIFICACIÓN TERCIA: Contenido específico del payload
    # Verificar si el contenido del payload aparece en la respuesta
    if "neluxmatizer" in payload and "neluxmatizer" in text:
        return True, "Payload reflection", "MEDIUM"
    
    # 4. VERIFICACIÓN FINAL: Múltiples indicadores XML en contexto
    # Solo si hay al menos 4 indicadores específicos y relacionados
    xml_context_indicators = [
        "xml", "entity", "external", "dtd", "doctype", "system", "public"
    ]
    
    xml_count = sum(1 for indicator in xml_context_indicators if indicator in lower)
    if xml_count >= 4:
        # Verificar que no sean solo palabras comunes del sitio
        # Si el texto es muy largo, es menos probable que sea XXE real
        if len(text) < 5000:  # Respuestas cortas son más sospechosas
            return True, "Multiple XML indicators", "LOW"
    
    return False, "No XXE vulnerability", "NONE"

def xxe(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m Testing XML External Entity (XXE) \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()

    total_tasks = len(wordlist) * (len(urip) + len(urif))
    current = 0
    found = 0
    lock = Lock()
    vulnerable_endpoints = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    stdout_lock = Lock()

    def test_post_xml(url, payload):
        nonlocal current, found

        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            with lock:
                if base in vulnerable_endpoints:
                    current += 1
                    update_progress(current, total_tasks)
                    return

            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            baseline_payload = '<?xml version="1.0"?><data>TEST123</data>'

            # Cache de baseline para evitar requests duplicadas
            baseline_key = f"XXE-{base}"
            if baseline_key not in baseline_cache:
                try:
                    baseline_res = requests.post(base, data=baseline_payload, headers=headers, timeout=5, verify=False)
                    if baseline_res.status_code == 200:
                        baseline_cache[baseline_key] = baseline_res.text
                    else:
                        baseline_cache[baseline_key] = ""
                except requests.exceptions.Timeout:
                    baseline_cache[baseline_key] = ""
                except requests.exceptions.RequestException:
                    baseline_cache[baseline_key] = ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            
            baseline_text = baseline_cache[baseline_key]
            if not baseline_text:
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            res = requests.post(base, data=payload, headers=headers, timeout=5, verify=False)

            is_vulnerable, vuln_type, risk_level = is_xxe_response(res.text, payload)
            if (
                res.status_code == 200 and
                is_vulnerable and
                res.text != baseline_text and
                abs(len(res.text) - len(baseline_text)) > 20  # diferencia significativa
            ):
                with lock:
                    if base not in vulnerable_endpoints:
                        urls_vulnerables.append(f'{base}')
                        
                        # Salida sincronizada
                        with stdout_lock:
                            print_vulnerability(f"\033[1;32m[POST] [VULNERABLE]\033[0m {base}")
                            sys.stdout.write(f"Vulnerability Type: {vuln_type}\n")
                            sys.stdout.flush()
                            sys.stdout.write(f"Risk Level: {risk_level}\n")
                            sys.stdout.flush()
                            sys.stdout.write(f"Payload: {payload[:100]}...\n")  # Mostrar primeros 100 chars del payload
                            sys.stdout.flush()
                        
                        found += 1
                        vulnerable_endpoints.add(base)

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass
        finally:
            with lock:
                current += 1
                update_progress(current, total_tasks)

    def test_form_xml(url, payload):
        test_post_xml(url, payload)

    def _iter_xxe_tasks():
        for url in urip:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in vulnerable_endpoints:
                for payload in wordlist:
                    yield (test_post_xml, url, payload)
        for url in urif:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in vulnerable_endpoints:
                for payload in wordlist:
                    yield (test_form_xml, url, payload)

    run_threadpool_pending_bounded(_iter_xxe_tasks(), threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    print()
    if found > 0:
        sys.stdout.write(f'\033[1;36m[+] Found {found} potential XXE vulnerabilities\033[0m\n')
        sys.stdout.flush()
    else:
        sys.stdout.write('\033[1;31m[-] No XXE vulnerabilities found\033[0m\n')
        sys.stdout.flush()
    print()
    
    return urls_vulnerables
