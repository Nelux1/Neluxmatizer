import requests
import random
from urllib.parse import urlparse, urljoin
from colorama import init, ansi
from threading import Lock
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.bounded_pool import run_threadpool_pending_bounded
import urllib3

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Content-Types que los parsers XML suelen aceptar
_XML_CONTENT_TYPES = ["application/xml", "text/xml"]

# Rutas que típicamente procesan XML: SOAP, XML-RPC, APIs, upload, etc.
# Se prueban una sola vez por host único descubierto.
_XML_PROBE_PATHS = [
    "/xmlrpc.php",
    "/xmlrpc",
    "/RPC2",
    "/soap",
    "/soap/",
    "/ws",
    "/webservice",
    "/api/xml",
    "/api/soap",
    "/api/v1/xml",
    "/api/v2/xml",
    "/import",
    "/upload",
    "/process",
    "/parse",
    "/api/import",
    "/api/upload",
]

xxe_indicators = [
    "root:", "uid=", "gid=", "/etc/passwd", "neluxmatizer",
    "bin:", "daemon:", "sys:", "adm:", "lp:", "mail:", "news:", "uucp:",
    "operator:", "games:", "man:", "at:", "cron:", "ftp:", "nobody:",
    "home=", "shell=", "group:", "shadow:", "passwd:", "hosts:", "fstab:",
    "xml", "entity", "external", "dtd", "doctype", "system", "public",
    "error", "exception", "warning", "fatal", "parse", "syntax"
]

def is_xxe_response(text, payload):
    """Validación estricta para detectar XXE real"""
    lower = text.lower()

    # 1. Contenido de archivos del sistema (más confiable)
    system_indicators = [
        "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:", "sys:x:3:3:",
        "adm:x:4:4:", "lp:x:7:7:", "mail:x:8:8:", "news:x:9:9:",
        "uucp:x:10:10:", "operator:x:11:0:", "games:x:12:100:",
        "man:x:13:62:", "at:x:25:25:", "cron:x:16:16:", "ftp:x:21:21:",
        "nobody:x:99:99:", "systemd-network:x:192:192:", "systemd-resolve:x:193:193:"
    ]
    if any(indicator in text for indicator in system_indicators):
        return True, "System file content", "HIGH"

    # 2. Errores específicos de XML parsing (no palabras sueltas)
    xml_specific_errors = [
        "xml external entity", "external entity", "dtd external",
        "doctype external", "system entity", "public entity",
        "xml parse error", "xml syntax error", "xml fatal error"
    ]
    if any(error in lower for error in xml_specific_errors):
        return True, "XML parsing error", "MEDIUM"

    # 3. Reflexión del marker del payload
    if "neluxmatizer" in payload and "neluxmatizer" in text:
        return True, "Payload reflection", "MEDIUM"

    # 4. Múltiples indicadores XML en respuesta corta (último recurso).
    # Excluir respuestas HTML donde los indicadores provienen de
    # body-reflection (ej: Firebase /__/auth/handler refleja POST body
    # como var JS, causando que doctype/xml/system/entity aparezcan
    # unicode-escaped en la página HTML).
    # Si la respuesta es HTML estándar (comienza con <!DOCTYPE html> o <html>)
    # y contiene el payload parcialmente reflejado, no contabilizar como XXE.
    is_html_response = lower.lstrip().startswith("<!doctype html") or lower.lstrip().startswith("<html")
    if is_html_response:
        # En respuestas HTML, los únicos indicadores válidos son los de reglas 1 y 2 (ya probadas)
        return False, "No XXE vulnerability", "NONE"

    xml_context_indicators = [
        "xml", "entity", "external", "dtd", "doctype", "system", "public"
    ]
    xml_count = sum(1 for indicator in xml_context_indicators if indicator in lower)
    if xml_count >= 4 and len(text) < 5000:
        return True, "Multiple XML indicators", "LOW"

    return False, "No XXE vulnerability", "NONE"


def xxe(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m Testing XML External Entity (XXE) \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()

    # Calcular unique hosts para las probe paths
    unique_hosts = set()
    for url in urip + urif:
        parsed = urlparse(url)
        unique_hosts.add(f"{parsed.scheme}://{parsed.netloc}")

    # Total de tareas: URLs existentes × payloads × content-types
    #                 + hosts únicos × probe paths × payloads (primeros 2) × content-types
    n_probe_payloads = min(len(wordlist), 2)
    total_tasks = (
        len(wordlist) * (len(urip) + len(urif)) * len(_XML_CONTENT_TYPES)
        + len(unique_hosts) * len(_XML_PROBE_PATHS) * n_probe_payloads * len(_XML_CONTENT_TYPES)
    )

    current = 0
    found = 0
    lock = Lock()
    vulnerable_endpoints = set()
    baseline_cache = {}
    stdout_lock = Lock()

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()

    def _report_vuln(endpoint, vuln_type, risk_level, payload, label="POST"):
        nonlocal found
        with lock:
            if endpoint not in vulnerable_endpoints and not vuln_manager.should_skip_url(endpoint):
                vulnerable_endpoints.add(endpoint)
                urls_vulnerables.append(endpoint)
                vuln_manager.mark_as_exploited(endpoint)
                with stdout_lock:
                    print_vulnerability(f"\033[1;32m[{label}] [VULNERABLE]\033[0m {endpoint}")
                    sys.stdout.write(f"Vulnerability Type: {vuln_type}\n")
                    sys.stdout.write(f"Risk Level: {risk_level}\n")
                    sys.stdout.write(f"Payload: {payload[:100]}...\n")
                    sys.stdout.flush()
                found += 1

    def test_post_xml(url, payload, content_type="application/xml"):
        """POST XML al path base de la URL descubierta."""
        nonlocal current
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if ban.is_banned(parsed.netloc):
                return  # finally incrementa current

            with lock:
                if base in vulnerable_endpoints or vuln_manager.should_skip_url(base):
                    return  # finally incrementa current

            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            headers['Content-Type'] = content_type

            baseline_payload = '<?xml version="1.0"?><data>TEST123</data>'
            baseline_key = f"XXE-{base}-{content_type}"

            if baseline_key not in baseline_cache:
                try:
                    bl_headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    bl_headers['Content-Type'] = content_type
                    bl_res = requests.post(base, data=baseline_payload, headers=bl_headers,
                                           timeout=5, verify=False)
                    baseline_cache[baseline_key] = bl_res.text if bl_res.status_code == 200 else ""
                except Exception:
                    baseline_cache[baseline_key] = ""

            baseline_text = baseline_cache[baseline_key]
            if not baseline_text:
                return  # finally incrementa current

            res = requests.post(base, data=payload, headers=headers, timeout=5, verify=False)
            ban.record(parsed.netloc, res.status_code, res, base)

            is_vulnerable, vuln_type, risk_level = is_xxe_response(res.text, payload)
            if (
                res.status_code == 200
                and is_vulnerable
                and res.text != baseline_text
                and abs(len(res.text) - len(baseline_text)) > 20
            ):
                _report_vuln(base, vuln_type, risk_level, payload, label="POST")

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

    def test_form_xml(url, payload, content_type="application/xml"):
        test_post_xml(url, payload, content_type)

    def test_xml_probe(host_base, probe_path, payload, content_type):
        """
        Prueba un path XML-específico (xmlrpc, soap, ws, etc.) en el host.
        No requiere que el path haya sido descubierto por el crawler.
        """
        nonlocal current
        target = host_base.rstrip('/') + probe_path
        try:
            with lock:
                if target in vulnerable_endpoints or vuln_manager.should_skip_url(target):
                    return  # finally incrementa current

            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            headers['Content-Type'] = content_type

            baseline_payload = '<?xml version="1.0"?><data>TEST123</data>'
            baseline_key = f"PROBE-{target}-{content_type}"

            if baseline_key not in baseline_cache:
                try:
                    bl_headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                    bl_headers['Content-Type'] = content_type
                    bl_res = requests.post(target, data=baseline_payload, headers=bl_headers,
                                           timeout=5, verify=False)
                    # 404 y 405 indican que el endpoint no procesa XML aquí
                    if bl_res.status_code in (404, 405):
                        baseline_cache[baseline_key] = None
                    else:
                        baseline_cache[baseline_key] = bl_res.text
                except Exception:
                    baseline_cache[baseline_key] = None

            baseline_text = baseline_cache[baseline_key]
            if baseline_text is None:
                return  # finally incrementa current

            res = requests.post(target, data=payload, headers=headers, timeout=5, verify=False)

            is_vulnerable, vuln_type, risk_level = is_xxe_response(res.text, payload)
            if is_vulnerable and res.text != baseline_text and abs(len(res.text) - len(baseline_text)) > 20:
                _report_vuln(target, vuln_type, risk_level, payload, label="PROBE")

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

    def _iter_xxe_tasks():
        # URLs descubiertas: probar con ambos Content-Types
        seen_bases = set()
        for url in urip:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in vulnerable_endpoints and not vuln_manager.should_skip_url(base):
                seen_bases.add(base)
                for ct in _XML_CONTENT_TYPES:
                    for payload in wordlist:
                        yield (test_post_xml, url, payload, ct)

        for url in urif:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in vulnerable_endpoints and not vuln_manager.should_skip_url(base):
                seen_bases.add(base)
                for ct in _XML_CONTENT_TYPES:
                    for payload in wordlist:
                        yield (test_form_xml, url, payload, ct)

        # Probe paths XML-específicos por host único (primeros 2 payloads)
        probe_payloads = wordlist[:n_probe_payloads]
        for host_base in unique_hosts:
            for probe_path in _XML_PROBE_PATHS:
                for ct in _XML_CONTENT_TYPES:
                    for payload in probe_payloads:
                        yield (test_xml_probe, host_base, probe_path, payload, ct)

    run_threadpool_pending_bounded(_iter_xxe_tasks(), threads)

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
