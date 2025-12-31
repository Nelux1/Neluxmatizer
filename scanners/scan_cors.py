import requests, sys
from urllib.error import URLError
from parametizer.progress import update_progress, print_vulnerability
from parametizer.core.headers import get_headers
from colorama import Cursor, init, ansi
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import threading
import sys
import os
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager

init()

def is_cors_vulnerable(response_headers, origin):
    """
    Función ULTRA estricta para detectar SOLO vulnerabilidades CORS REALES
    """
    # Verificar Access-Control-Allow-Origin
    acao = response_headers.get('Access-Control-Allow-Origin', '')
    
    # CASO 1: Origin reflejado EXACTAMENTE (MÁS VULNERABLE - refleja el origen malicioso)
    if acao == origin:
        return True, "Origin reflection", "HIGH"
    
    # CASO 2: Wildcard (*) - SOLO vulnerable si tiene credenciales
    if acao == '*':
        acac = response_headers.get('Access-Control-Allow-Credentials', '').lower()
        if acac == 'true':
            return True, "Wildcard with credentials", "HIGH"
        else:
            # Wildcard sin credenciales - NO es vulnerable
            return False, "Wildcard without credentials", "NONE"
    
    # CASO 3: Credenciales con origin específico (redundante con caso 1, pero por seguridad)
    acac = response_headers.get('Access-Control-Allow-Credentials', '').lower()
    if acac == 'true' and acao == origin:
        return True, "Credentials with origin reflection", "HIGH"
    
    # NO hay más casos - solo estos 3 son vulnerabilidades reales
    return False, "No CORS vulnerability", "NONE"

def cors(urip, urif, urls_vulnerables, threads, custom_headers=None, random_agent=False):
    print()
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Cross-Origin Resource Sharing \033[1;36m>>>>>>>>>>>>>\033[0m\n')
    print()

    total_tasks = len(urip) + len(urif)
    current = 0
    found = []
    vulnerable_endpoints = set()  # Track vulnerable base URLs
    lock = threading.Lock()
    found_urls = set()  # Track found URLs to prevent duplicates
    
    # Cache para baselines y endpoints vulnerables
    baseline_cache = {}
    stdout_lock = threading.Lock()

    def test_url(url):
        nonlocal found, current
        try:
            # Filtrar archivos estáticos que no son vulnerabilidades CORS reales
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
                    if current < total_tasks:
                        current += 1
                        update_progress(current, total_tasks)
                return
            
            # Skip if this endpoint is already known to be vulnerable
            base_url = url.split('?')[0]
            # Verificar si ya se explotó esta URL usando el sistema unificado
            if vuln_manager.should_skip_url(base_url, base_url_only=True):
                with lock:
                    if current < total_tasks:
                        current += 1
                        update_progress(current, total_tasks)
                return

            # Test with different origins
            origins = [
                'https://evil.com',
                'http://evil.com',
                'null',
                'https://attacker.com',
                'http://attacker.com'
            ]

            for origin in origins:
                # Generar headers base con User-Agent
                base_headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)

                # Agregar Origin específico
                headers = base_headers.copy()
                headers['Origin'] = origin

                # Test GET request con cache de baseline
                baseline_key = f"GET-{base_url}"
                if baseline_key not in baseline_cache:
                    try:
                        baseline_response = requests.get(url, headers=base_headers, verify=False, timeout=5)
                        baseline_cache[baseline_key] = baseline_response.headers
                    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                        baseline_cache[baseline_key] = {}
                
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=5)
                    
                    is_vulnerable, vuln_type, risk_level = is_cors_vulnerable(response.headers, origin)
                    
                    if is_vulnerable:
                        # Verificar si ya se explotó esta URL
                        if not vuln_manager.is_already_exploited(base_url, base_url_only=True):
                            # Marcar como explotada
                            vuln_manager.mark_as_exploited(base_url, base_url_only=True)
                            
                            # Salida sincronizada
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[GET] [VULNERABLE] {url}\033[0m")
                                print(f"Origin reflected: '{origin}'")
                                print(f"ACAO: '{response.headers.get('Access-Control-Allow-Origin', '')}'")
                                print(f"ACAC: '{response.headers.get('Access-Control-Allow-Credentials', '')}'")
                                print(f"Vulnerability Type: {vuln_type}")
                                print(f"Risk Level: {risk_level}\n")
                            
                            urls_vulnerables.append(f'{url}')
                            found.append(url)
                            break  # Stop testing more origins if vulnerable
                            
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue

                # Test POST request solo si es necesario
                try:
                    response = requests.post(url, headers=headers, verify=False, timeout=5)
                    
                    is_vulnerable, vuln_type, risk_level = is_cors_vulnerable(response.headers, origin)
                    
                    if is_vulnerable:
                        if url not in found_urls:
                            found_urls.add(url)
                            vulnerable_endpoints.add(base_url)
                            
                            # Salida sincronizada
                            with stdout_lock:
                                print_vulnerability(f"\033[1;32m[POST] [VULNERABLE] {url}\033[0m")
                                print(f"Origin reflected: '{origin}'")
                                print(f"ACAO: '{response.headers.get('Access-Control-Allow-Origin', '')}'")
                                print(f"ACAC: '{response.headers.get('Access-Control-Allow-Credentials', '')}'")
                                print(f"Vulnerability Type: {vuln_type}")
                                print(f"Risk Level: {risk_level}\n")
                            
                            urls_vulnerables.append(f'{url}')
                            found.append(url)
                            break  # Stop testing more origins if vulnerable
                            
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.RequestException:
                    continue

        except Exception as e:
            # Log específico de errores para debugging
            if "timeout" in str(e).lower():
                pass  # Skip timeouts silently
            else:
                pass  # Log other errors if needed
        finally:
            with lock:
                if current < total_tasks:
                    current += 1
                    update_progress(current, total_tasks)

    # Crear tareas de manera más eficiente
    tasks = []
    
    # Agrupar tareas por URL para evitar duplicación
    for url in urip + urif:
        tasks.append((test_url, url))
    
    # Procesar TODAS las tareas en paralelo para máximo rendimiento
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Enviar todas las tareas al pool de hilos
        futures = [executor.submit(task[0], *task[1:]) for task in tasks]
        
        # Esperar a que se completen todas (pero en paralelo)
        for future in futures:
            try:
                future.result()
            except Exception:
                pass
    
    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    
        print()  # Asegurar salto de línea final
    if found:
        print(f'\n\033[1;36m[+] Found {len(found)} potential CORS vulnerabilities\033[0m\n')
    else:
        print('\n\033[1;31m[-] No CORS vulnerabilities found\033[0m\n')
    
    return urls_vulnerables
