import requests
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerability_manager import vuln_manager
from parametizer.bounded_pool import run_threadpool_in_chunks
from threading import Lock
from parametizer.core.headers import get_headers
from parametizer.progress import update_progress, print_vulnerability
from colorama import init, ansi

init()

def clickjacking(urip, urif, urls_vulnerables, threads, custom_headers, random_agent):
    print('\033[1;36m<<<<<<<<<<<<\033[0m Testing Clickjacking \033[1;36m>>>>>>>>>>>>>\033[0m')
    print()

    # Configuración
    total_tasks = len(urip) + len(urif)
    progress = 0
    found = 0
    lock = Lock()
    found_urls = set()
    
    # Cache para respuestas y sincronización de salida
    response_cache = {}
    stdout_lock = Lock()

    # Construcción del header
    # def get_headers():
    #     headers = custom_headers or {}
    #     headers.setdefault('User-Agent', 'Mozilla/5.0')
    #     return headers

    def test_url(url):
        nonlocal progress, found
        
        # Filtrar archivos estáticos que no pueden ser vulnerables a Clickjacking
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
                progress += 1
                update_progress(progress, total_tasks)
            return
        
        try:
            # Cache de respuestas para evitar requests duplicadas
            if url not in response_cache:
                headers = get_headers(random_agent=random_agent, custom_headers=custom_headers)
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                response_cache[url] = response
            else:
                response = response_cache[url]
            
            headers2 = response.headers
            
            # LÓGICA SIMPLE: Si NO tiene ninguno de los dos headers → VULNERABLE
            if 'X-Frame-Options' not in headers2 and 'Content-Security-Policy' not in headers2:
                with lock:
                    if url not in found_urls:
                        found += 1
                        found_urls.add(url)
                        
                        # Mostrar qué protección falta
                        if 'X-Frame-Options' in headers2:
                            protection_text = f"Has X-Frame-Options: {headers2['X-Frame-Options']}"
                        elif 'Content-Security-Policy' in headers2:
                            protection_text = f"Has Content-Security-Policy: {headers2['Content-Security-Policy']}"
                        else:
                            protection_text = "Missing both X-Frame-Options and Content-Security-Policy"
                        
                        # Salida sincronizada
                        with stdout_lock:
                            print_vulnerability(f"\033[1;32m[VULNERABLE]\033[0m {url}")
                            print(f"Missing protection: {protection_text}")
                        
                        urls_vulnerables.append(f'{url}')
                        #urls_vulnerables.append(f'Missing protection: {protection_text}')
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass
        finally:
            with lock:
                progress += 1
                update_progress(progress, total_tasks)

    tasks = [u for u in urip + urif if u not in found_urls]
    run_threadpool_in_chunks(test_url, tasks, threads)

    # Limpiar salida final
    with stdout_lock:
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
    
        print()
    if found > 0:
        print(f'\033[1;36m[+] Found {found} potential Clickjacking vulnerabilities\033[0m')
    else:
        print('\033[1;31m[-] No Clickjacking vulnerabilities found\033[0m')
    print()
    
    return urls_vulnerables
