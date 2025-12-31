#!/usr/bin/env python3
"""
Módulo para manejar bloqueos WAF y respuestas de rate limiting
Implementa detección, delays, bypasses y guardado de resultados parciales
"""

import time
import random
import requests
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Back, Style, init
import os
import json
from datetime import datetime

# Importar configuración
try:
    from .block_handler_config import (
        BLOCK_STATUS_CODES, WAF_INDICATOR_HEADERS, BLOCK_INDICATOR_KEYWORDS,
        MAX_BLOCKS_BEFORE_GIVING_UP, MAX_BYPASS_ATTEMPTS, BASE_DELAY_MULTIPLIER,
        MAX_DELAY_SECONDS, BYPASS_USER_AGENTS, DEFAULT_PROXY_FILE,
        PROXY_ENV_VARS, PROXY_TIMEOUT, DELAY_BASE_TIMES,
        EXPONENTIAL_DELAY_MULTIPLIER, ENABLE_VERBOSE_LOGGING
    )
    CONFIG_AVAILABLE = True
except ImportError:
    # Valores por defecto si no hay configuración
    CONFIG_AVAILABLE = False
    BLOCK_STATUS_CODES = [403, 429, 503, 509]
    WAF_INDICATOR_HEADERS = ['cf-ray', 'cf-cache-status', 'x-cdn', 'x-waf', 'x-security']
    BLOCK_INDICATOR_KEYWORDS = ['cloudflare', 'waf', 'blocked', 'rate-limit']
    MAX_BLOCKS_BEFORE_GIVING_UP = 5
    MAX_BYPASS_ATTEMPTS = 3
    BASE_DELAY_MULTIPLIER = 1.0
    MAX_DELAY_SECONDS = 60
    BYPASS_USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.68.0',
        'python-requests/2.25.1'
    ]
    DEFAULT_PROXY_FILE = "proxies.txt"
    PROXY_ENV_VARS = ['HTTP_PROXY', 'HTTPS_PROXY']
    PROXY_TIMEOUT = 15
    DELAY_BASE_TIMES = {403: 2, 429: 5, 503: 10, 509: 15}
    EXPONENTIAL_DELAY_MULTIPLIER = 1.5
    ENABLE_VERBOSE_LOGGING = True

init()

class BlockHandler:
    """
    Maneja bloqueos WAF, rate limiting y respuestas de error
    """
    
    def __init__(self, target_url: str, custom_headers: Optional[Dict] = None):
        self.target_url = target_url
        self.custom_headers = custom_headers or {}
        self.block_count = 0
        self.max_blocks = MAX_BLOCKS_BEFORE_GIVING_UP
        self.delay_multiplier = BASE_DELAY_MULTIPLIER
        self.bypass_attempts = 0
        self.max_bypass_attempts = MAX_BYPASS_ATTEMPTS
        self.is_blocked = False
        self.block_history = []
        
        # Headers de bypass desde configuración
        self.bypass_headers = [{'User-Agent': ua} for ua in BYPASS_USER_AGENTS]
        
        # Proxies de bypass (si están disponibles)
        self.bypass_proxies = []
        self._load_proxies()
    
    def _load_proxies(self):
        """Carga proxies desde archivo o variables de entorno"""
        # Intentar cargar desde archivo
        proxy_file = os.path.join(os.path.dirname(__file__), '..', DEFAULT_PROXY_FILE)
        if os.path.exists(proxy_file):
            try:
                with open(proxy_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.bypass_proxies.append(line)
            except:
                pass
        
        # Intentar desde variables de entorno
        for env_var in PROXY_ENV_VARS:
            proxy_value = os.getenv(env_var)
            if proxy_value:
                self.bypass_proxies.append(proxy_value)
    
    def detect_block(self, response: requests.Response) -> bool:
        """
        Detecta si la respuesta indica un bloqueo
        """
        # Códigos de estado que indican bloqueo desde configuración
        if response.status_code in BLOCK_STATUS_CODES:
            self.block_count += 1
            self.block_history.append({
                'timestamp': datetime.now().isoformat(),
                'status_code': response.status_code,
                'url': response.url,
                'headers': dict(response.headers)
            })
            
            if ENABLE_VERBOSE_LOGGING:
                print(f"{Fore.RED}[🚨] BLOCK DETECTED: {response.status_code} - {response.url}{Style.RESET_ALL}")
            
            # Verificar si hemos excedido el límite de bloqueos
            if self.block_count >= self.max_blocks:
                self.is_blocked = True
                print(f"{Fore.RED}[🚨] TARGET BLOCKED: Maximum blocks exceeded ({self.block_count}/{self.max_blocks}){Style.RESET_ALL}")
                return True
            
            return True
        
        # Verificar headers que indiquen bloqueo desde configuración
        for header in WAF_INDICATOR_HEADERS:
            if header in response.headers:
                header_value = response.headers[header].lower()
                if any(blocked in header_value for blocked in BLOCK_INDICATOR_KEYWORDS):
                    if ENABLE_VERBOSE_LOGGING:
                        print(f"{Fore.YELLOW}[⚠️] WAF Header detected: {header}: {response.headers[header]}{Style.RESET_ALL}")
                    return False  # No es un bloqueo directo, solo información
        
        return False
    
    def handle_block(self, response: requests.Response) -> Tuple[bool, Optional[Dict]]:
        """
        Maneja un bloqueo detectado
        Retorna: (bypass_exitoso, headers_actualizados)
        """
        if not self.detect_block(response):
            return False, None
        
        print(f"{Fore.YELLOW}[🔄] Attempting to bypass block #{self.block_count}...{Style.RESET_ALL}")
        
        # Intentar bypass con diferentes estrategias
        bypass_success = False
        updated_headers = None
        
        # Estrategia 1: Cambiar User-Agent
        if self.bypass_attempts < self.max_bypass_attempts:
            bypass_success, updated_headers = self._try_ua_bypass()
        
        # Estrategia 2: Usar proxy
        if not bypass_success and self.bypass_proxies:
            bypass_success, updated_headers = self._try_proxy_bypass()
        
        # Estrategia 3: Delay exponencial
        if not bypass_success:
            self._apply_delay()
        
        self.bypass_attempts += 1
        return bypass_success, updated_headers
    
    def _try_ua_bypass(self) -> Tuple[bool, Optional[Dict]]:
        """Intenta bypass cambiando User-Agent"""
        try:
            # Seleccionar un User-Agent aleatorio
            new_ua = random.choice(self.bypass_headers)
            updated_headers = self.custom_headers.copy()
            updated_headers.update(new_ua)
            
            print(f"{Fore.CYAN}[🔄] Trying User-Agent bypass: {new_ua['User-Agent'][:50]}...{Style.RESET_ALL}")
            
            # Probar la conexión
            test_response = requests.get(
                self.target_url,
                headers=updated_headers,
                timeout=10,
                verify=False
            )
            
            if test_response.status_code == 200:
                print(f"{Fore.GREEN}[✅] User-Agent bypass successful!{Style.RESET_ALL}")
                return True, updated_headers
            else:
                print(f"{Fore.YELLOW}[⚠️] User-Agent bypass failed: {test_response.status_code}{Style.RESET_ALL}")
                return False, None
                
        except Exception as e:
            print(f"{Fore.RED}[❌] User-Agent bypass error: {e}{Style.RESET_ALL}")
            return False, None
    
    def _try_proxy_bypass(self) -> Tuple[bool, Optional[Dict]]:
        """Intenta bypass usando proxy"""
        if not self.bypass_proxies:
            return False, None
        
        try:
            proxy = random.choice(self.bypass_proxies)
            proxies = {
                'http': proxy,
                'https': proxy
            }
            
            print(f"{Fore.CYAN}[🔄] Trying proxy bypass: {proxy}{Style.RESET_ALL}")
            
            # Probar la conexión
            test_response = requests.get(
                self.target_url,
                headers=self.custom_headers,
                proxies=proxies,
                timeout=PROXY_TIMEOUT,
                verify=False
            )
            
            if test_response.status_code == 200:
                print(f"{Fore.GREEN}[✅] Proxy bypass successful!{Style.RESET_ALL}")
                # Agregar el proxy a los headers para uso futuro
                updated_headers = self.custom_headers.copy()
                updated_headers['X-Proxy-Used'] = proxy
                return True, updated_headers
            else:
                print(f"{Fore.YELLOW}[⚠️] Proxy bypass failed: {test_response.status_code}{Style.RESET_ALL}")
                return False, None
                
        except Exception as e:
            print(f"{Fore.RED}[❌] Proxy bypass error: {e}{Style.RESET_ALL}")
            return False, None
    
    def _apply_delay(self):
        """Aplica delay exponencial"""
        # Usar delay base específico para el código de estado si está disponible
        base_delay = DELAY_BASE_TIMES.get(self.block_count, 2)
        delay = (base_delay ** self.block_count) * self.delay_multiplier
        delay = min(delay, MAX_DELAY_SECONDS)
        
        if ENABLE_VERBOSE_LOGGING:
            print(f"{Fore.YELLOW}[⏳] Applying delay: {delay:.1f} seconds...{Style.RESET_ALL}")
        time.sleep(delay)
        
        # Aumentar multiplicador para el siguiente bloqueo
        self.delay_multiplier *= EXPONENTIAL_DELAY_MULTIPLIER
    
    def is_target_blocked(self) -> bool:
        """Verifica si el target está completamente bloqueado"""
        return self.is_blocked
    
    def get_block_stats(self) -> Dict:
        """Retorna estadísticas de bloqueos"""
        return {
            'target_url': self.target_url,
            'block_count': self.block_count,
            'bypass_attempts': self.bypass_attempts,
            'is_blocked': self.is_blocked,
            'block_history': self.block_history
        }
    
    def reset_block_count(self):
        """Resetea el contador de bloqueos (útil para nuevos parámetros)"""
        self.block_count = 0
        self.bypass_attempts = 0
        self.delay_multiplier = 1.0


class ResultSaver:
    """
    Maneja el guardado de resultados parciales cuando se detectan bloqueos
    """
    
    def __init__(self, output_file: str, poc_enabled: bool = False):
        self.output_file = output_file
        self.poc_enabled = poc_enabled
        self.partial_results = []
        self.scan_start_time = datetime.now()
    
    def add_vulnerability(self, vuln: str, target_url: str):
        """Agrega una vulnerabilidad a los resultados parciales"""
        self.partial_results.append({
            'vulnerability': vuln,
            'target_url': target_url,
            'timestamp': datetime.now().isoformat()
        })
    
    def save_partial_results(self, target_url: str, reason: str):
        """
        Guarda resultados parciales cuando se detecta un bloqueo
        """
        if not self.partial_results:
            print(f"{Fore.YELLOW}[⚠️] No vulnerabilities to save for {target_url}{Style.RESET_ALL}")
            return
        
        try:
            # Crear directorio de output si no existe
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Guardar resultados parciales
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"PARTIAL SCAN RESULTS - TARGET BLOCKED\n")
                f.write(f"Target: {target_url}\n")
                f.write(f"Scan Started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Blocked At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Reason: {reason}\n")
                f.write(f"Vulnerabilities Found: {len(self.partial_results)}\n")
                f.write(f"{'='*80}\n\n")
                
                for result in self.partial_results:
                    f.write(f"[{result['timestamp']}] {result['vulnerability']}\n")
                
                f.write(f"\n{'='*80}\n")
                f.write(f"SCAN INTERRUPTED DUE TO WAF BLOCKING\n")
                f.write(f"{'='*80}\n\n")
            
            print(f"{Fore.GREEN}[💾] Partial results saved to {self.output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[📊] Saved {len(self.partial_results)} vulnerabilities{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[❌] Error saving partial results: {e}{Style.RESET_ALL}")
    
    def clear_partial_results(self):
        """Limpia los resultados parciales (útil para nuevo target)"""
        self.partial_results.clear()
        self.scan_start_time = datetime.now()
        print(f"{Fore.CYAN}🔄 Partial results cleared for new target{Style.RESET_ALL}")


def create_safe_request_session(custom_headers: Dict, block_handler: BlockHandler = None) -> requests.Session:
    """
    Crea una sesión de requests con manejo automático de bloqueos
    """
    session = requests.Session()
    
    # Configurar headers por defecto
    session.headers.update(custom_headers)
    
    # Si no hay block_handler, solo retornar la sesión básica
    if not block_handler:
        return session
    
    # Interceptor para manejar respuestas
    def response_hook(response, *args, **kwargs):
        if block_handler.detect_block(response):
            bypass_success, updated_headers = block_handler.handle_block(response)
            if bypass_success and updated_headers:
                session.headers.update(updated_headers)
                # Reintentar la petición con nuevos headers
                return session.request(response.request.method, response.request.url, **kwargs)
            elif block_handler.is_target_blocked():
                raise Exception(f"Target blocked after {block_handler.block_count} attempts")
        return response
    
    session.hooks['response'] = [response_hook]
    return session
