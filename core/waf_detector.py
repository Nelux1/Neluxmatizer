#!/usr/bin/env python3
"""
WAF Detector and Bypass Module for Neluxmatizer
Detects Web Application Firewalls and attempts bypasses
"""

import requests
import time
import random
import re
import sys
from urllib.parse import urljoin
from colorama import Fore, Style, init

init()

class WAFDetector:
    def __init__(self, target_url, custom_headers=None):
        self.target_url = target_url
        self.custom_headers = custom_headers or {}
        self.waf_detected = False
        self.waf_type = None
        self.blocked = False
        self.bypass_attempts = 0
        self.max_bypass_attempts = 5
        
        # Sistema de bloqueo inteligente
        self.block_count = 0
        self.last_block_time = 0
        self.block_threshold = 3  # Después de 3 bloqueos seguidos, activar cooldown
        self.cooldown_duration = 60  # 60 segundos de cooldown
        self.consecutive_403_503 = 0  # Contador de 403/503 seguidos
        self.max_consecutive_blocks = 5  # Máximo de bloqueos consecutivos antes de dar por terminado
        
        # Headers de bypass comunes
        self.bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Forwarded-Server': 'localhost'},
            {'X-HTTP-Host-Override': 'localhost'},
            {'Forwarded': 'for=127.0.0.1;by=127.0.0.1'},
            {'X-Forwarded-For': '0.0.0.0'},
            {'X-Forwarded-For': '::1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Forwarded-For': '172.16.0.1'},
            {'X-Forwarded-For': '192.168.0.1'},
        ]
        
        # Headers específicos para Wordfence
        self.wordfence_bypass_headers = [
            {'X-Forwarded-For': '8.8.8.8'},  # Google DNS
            {'X-Forwarded-For': '1.1.1.1'},  # Cloudflare DNS
            {'X-Real-IP': '8.8.8.8'},
            {'X-Forwarded-For': '208.67.222.222'},  # OpenDNS
            {'X-Forwarded-For': '9.9.9.9'},  # Quad9 DNS
            {'CF-Connecting-IP': '8.8.8.8'},  # Cloudflare
            {'X-Forwarded-For': '185.199.108.153'},  # GitHub
            {'X-Forwarded-For': '151.101.1.69'},  # Reddit
        ]
        
        # User-Agents de bypass
        self.bypass_user_agents = [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
            'Mozilla/5.0 (compatible; FacebookExternalHit/1.1; +http://www.facebook.com/externalhit_uatext.php)',
            'Mozilla/5.0 (compatible; Twitterbot/1.0)',
            'Mozilla/5.0 (compatible; LinkedInBot/1.0)',
            'Mozilla/5.0 (compatible; WhatsApp/2.0)',
            'Mozilla/5.0 (compatible; TelegramBot/1.0)',
        ]

    def detect_waf(self):
        """Detecta si hay un WAF activo"""
        #print(f"{Fore.YELLOW}🔍 Detecting WAF protection...{Style.RESET_ALL}")
        
        try:
            # Request normal para baseline
            headers = self.custom_headers.copy()
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            response = requests.get(self.target_url, headers=headers, verify=False, timeout=10)
            
            # Detectar WAF por headers de respuesta
            waf_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-connecting-ip'],
                'aws_waf': ['x-amz-cf-pop', 'x-amz-cf-id', 'x-amz-waf-id'],
                'akamai': ['x-akamai-transformed', 'x-akamai-ssl'],
                'fastly': ['x-fastly', 'fastly-ssl'],
                'incapsula': ['x-iinfo', 'x-cdn'],
                'sucuri': ['x-sucuri', 'x-sucuri-ip'],
                'f5_bigip': ['x-wa-info', 'x-asg'],
                'barracuda': ['barra_counter_session', 'barracuda_'],
                'fortinet': ['x-fortinet', 'fortigate'],
                'palo_alto': ['x-pan', 'pan-'],
                'checkpoint': ['x-chk', 'checkpoint'],
                'cisco_asa': ['x-asa', 'cisco'],
                'juniper': ['x-juniper', 'juniper'],
                'nginx_plus': ['x-nginx-plus', 'nginx-plus'],
                'apache_modsecurity': ['mod_security', 'modsecurity'],
                'imperva': ['x-iw', 'incapsula'],
                'cloudflare_enterprise': ['cf-enterprise', 'cf-enterprise-id'],
                'azure_waf': ['x-azure-ref', 'x-azure-'],
                'gcp_cloud_armor': ['x-cloud-trace-context', 'x-goog-'],
                'alibaba_cloud': ['x-alicloud', 'x-ali-'],
            }
            
            # Verificar headers de respuesta
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if any(indicator.lower() in header.lower() for header in response.headers.keys()):
                        self.waf_detected = True
                        self.waf_type = waf_name.upper()
                        # No imprimir aquí - solo detectar silenciosamente
                        return True
            
            # Verificar por contenido de respuesta (páginas de bloqueo)
            block_indicators = [
                'access denied', 'blocked', 'forbidden', 'unauthorized',
                'security check', 'captcha', 'challenge', 'verification',
                'cloudflare', 'incapsula', 'sucuri', 'akamai',
                'rate limit', 'too many requests', 'quota exceeded',
                'blocked by', 'firewall', 'waf', 'ddos protection'
            ]
            
            response_text = response.text.lower()
            for indicator in block_indicators:
                if indicator in response_text:
                    self.waf_detected = True
                    self.waf_type = "UNKNOWN_WAF"
                    # No imprimir aquí - solo detectar silenciosamente
                    return True
            
            # Verificar por códigos de estado sospechosos
            if response.status_code in [403, 429, 503, 509]:
                self.waf_detected = True
                self.waf_type = f"WAF_STATUS_{response.status_code}"
                #print(f"{Fore.RED}[🚨] WAF DETECTED: {self.waf_type} (by status code){Style.RESET_ALL}")
                return True
            
            #print(f"{Fore.GREEN}[✅] No WAF detected{Style.RESET_ALL}")
            return False
            
        except Exception as e:
            #sys.stdout.write(f"{Fore.RED}[❌] Error detecting WAF: {e}{Style.RESET_ALL}\n")
            #sys.stdout.flush()
            pass
            return False

    def test_bypass(self):
        """Intenta bypassear el WAF"""
        if not self.waf_detected:
            return True
            
        sys.stdout.write(f"{Fore.YELLOW}[🔄] Attempting WAF bypass...{Style.RESET_ALL}\n")
        sys.stdout.flush()
        
        # Si es Wordfence, usar técnicas específicas
        if self.waf_type == "WORDFENCE":
            sys.stdout.write(f"{Fore.YELLOW}[🔄] Using Wordfence-specific bypass techniques...{Style.RESET_ALL}\n")
            sys.stdout.flush()
            return self._wordfence_bypass()
        
        # Bypass estándar para otros WAFs
        for attempt in range(self.max_bypass_attempts):
            self.bypass_attempts += 1
            sys.stdout.write(f"{Fore.CYAN}[🔄] Bypass attempt {attempt + 1}/{self.max_bypass_attempts}{Style.RESET_ALL}\n")
            sys.stdout.flush()
            
            try:
                # Combinar diferentes técnicas de bypass
                headers = self.custom_headers.copy()
                
                # Rotar User-Agent
                headers['User-Agent'] = random.choice(self.bypass_user_agents)
                
                # Agregar headers de bypass
                bypass_header = random.choice(self.bypass_headers)
                headers.update(bypass_header)
                
                # Agregar headers adicionales
                headers.update({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                })
                
                # Delay aleatorio para evitar rate limiting
                time.sleep(random.uniform(1, 3))
                
                response = requests.get(self.target_url, headers=headers, verify=False, timeout=15)
                
                # Verificar si el bypass funcionó
                if response.status_code == 200 and not self._is_blocked_page(response.text):
                    sys.stdout.write(f"{Fore.GREEN}[✅] WAF bypass successful!{Style.RESET_ALL}\n")
                    sys.stdout.flush()
                    return True
                else:
                    sys.stdout.write(f"{Fore.YELLOW}[⚠️] Bypass attempt {attempt + 1} failed (Status: {response.status_code}){Style.RESET_ALL}\n")
                    sys.stdout.flush()
                    
            except Exception as e:
                sys.stdout.write(f"{Fore.RED}[❌] Bypass attempt {attempt + 1} error: {e}{Style.RESET_ALL}\n")
                sys.stdout.flush()
                continue
        
        sys.stdout.write(f"{Fore.RED}[🚨] All bypass attempts failed!{Style.RESET_ALL}\n")
        sys.stdout.flush()
        self.blocked = True
        return False
    
    def _wordfence_bypass(self):
        """Técnicas específicas de bypass para Wordfence"""
        sys.stdout.write(f"{Fore.YELLOW}[🔄] Starting Wordfence-specific bypass...{Style.RESET_ALL}\n")
        sys.stdout.flush()
        
        # Técnica 1: Simular Googlebot
        try:
            headers = self.custom_headers.copy()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'X-Forwarded-For': '66.249.66.1',  # IP real de Googlebot
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
            })
            
            sys.stdout.write(f"{Fore.YELLOW}[🔄] Attempting Googlebot simulation...{Style.RESET_ALL}\n")
            sys.stdout.flush()
            response = requests.get(self.target_url, headers=headers, verify=False, timeout=15)
            
            if response.status_code == 200 and not self._is_blocked_page(response.text):
                sys.stdout.write(f"{Fore.GREEN}[✅] Wordfence bypass successful with Googlebot!{Style.RESET_ALL}\n")
                sys.stdout.flush()
                return True
                
        except Exception as e:
            sys.stdout.write(f"{Fore.RED}[❌] Googlebot bypass failed: {e}{Style.RESET_ALL}\n")
            sys.stdout.flush()
        
        # Técnica 2: Headers de CDN legítimos
        for cdn_header in self.wordfence_bypass_headers:
            try:
                headers = self.custom_headers.copy()
                headers.update(cdn_header)
                headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                
                sys.stdout.write(f"{Fore.YELLOW}[🔄] Attempting CDN header bypass: {list(cdn_header.keys())[0]}...{Style.RESET_ALL}\n")
                sys.stdout.flush()
                response = requests.get(self.target_url, headers=headers, verify=False, timeout=15)
                
                if response.status_code == 200 and not self._is_blocked_page(response.text):
                    sys.stdout.write(f"{Fore.GREEN}[✅] Wordfence bypass successful with CDN header!{Style.RESET_ALL}\n")
                    sys.stdout.flush()
                    return True
                    
            except Exception as e:
                sys.stdout.write(f"{Fore.RED}[❌] CDN header bypass failed: {e}{Style.RESET_ALL}\n")
                sys.stdout.flush()
                continue
        
        # Técnica 3: Delay largo y reintento
        sys.stdout.write(f"{Fore.YELLOW}[⏳] Applying long delay (30s) before final attempt...{Style.RESET_ALL}\n")
        sys.stdout.flush()
        time.sleep(30)
        
        try:
            headers = self.custom_headers.copy()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'X-Forwarded-For': '13.107.21.200',  # IP de Bingbot
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            
            response = requests.get(self.target_url, headers=headers, verify=False, timeout=15)
                
            if response.status_code == 200 and not self._is_blocked_page(response.text):
                sys.stdout.write(f"{Fore.GREEN}[✅] Wordfence bypass successful with Bingbot!{Style.RESET_ALL}\n")
                sys.stdout.flush()
                return True
                
        except Exception as e:
            sys.stdout.write(f"{Fore.RED}[❌] Final Wordfence bypass attempt failed: {e}{Style.RESET_ALL}\n")
            sys.stdout.flush()
        
        sys.stdout.write(f"{Fore.RED}[🚨] All Wordfence bypass attempts failed!{Style.RESET_ALL}\n")
        sys.stdout.flush()
        self.blocked = True
        return False

    def _is_blocked_page(self, content):
        """Verifica si la página es una página de bloqueo"""
        block_patterns = [
            r'access denied',
            r'blocked',
            r'forbidden',
            r'security check',
            r'captcha',
            r'challenge',
            r'verification required',
            r'rate limit',
            r'too many requests',
            r'quota exceeded',
            r'firewall',
            r'waf',
            r'ddos protection'
        ]
        
        content_lower = content.lower()
        for pattern in block_patterns:
            if re.search(pattern, content_lower):
                return True
        return False

    def check_rate_limit(self):
        """Verifica si estamos siendo rate limited"""
        try:
            headers = self.custom_headers.copy()
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            response = requests.get(self.target_url, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 429:
                sys.stdout.write(f"{Fore.RED}[🚨] RATE LIMITED! Status 429{Style.RESET_ALL}\n")
                sys.stdout.flush()
                return True
            elif 'rate limit' in response.text.lower() or 'too many requests' in response.text.lower():
                sys.stdout.write(f"{Fore.RED}[🚨] RATE LIMITED! Detected in content{Style.RESET_ALL}\n")
                sys.stdout.flush()
                return True
                
            return False
            
        except Exception:
            return False
    
    def check_blocking_pattern(self, status_code, response_text=""):
        """Verifica patrones de bloqueo y aplica cooldown inteligente"""
        current_time = time.time()
        
        # Detectar bloqueos 403/503
        if status_code in [403, 503]:
            self.consecutive_403_503 += 1
            self.block_count += 1
            self.last_block_time = current_time
            
            sys.stdout.write(f"{Fore.RED}[🚨] BLOCKED! Status {status_code} (Consecutive: {self.consecutive_403_503}){Style.RESET_ALL}\n")
            sys.stdout.flush()
            
            # Verificar si es Wordfence específicamente
            if 'wordfence' in response_text.lower() or '爬虫每分钟未找到页面的最大错误数' in response_text:
                sys.stdout.write(f"{Fore.RED}[🚨] WORDFENCE DETECTED! Applying specific bypass...{Style.RESET_ALL}\n")
                sys.stdout.flush()
                self.waf_type = "WORDFENCE"
                self.waf_detected = True
            
            # Si superamos el umbral de bloqueos consecutivos
            if self.consecutive_403_503 >= self.max_consecutive_blocks:
                sys.stdout.write(f"{Fore.RED}[🚨] MAXIMUM CONSECUTIVE BLOCKS REACHED! Stopping for this target{Style.RESET_ALL}\n")
                sys.stdout.flush()
                self.blocked = True
                return "STOP_SCANNING"
            
            # Si superamos el umbral de bloqueos, activar cooldown
            if self.block_count >= self.block_threshold:
                cooldown_time = self.cooldown_duration
                sys.stdout.write(f"{Fore.YELLOW}[⏳] BLOCKING PATTERN DETECTED! Activating {cooldown_time}s cooldown...{Style.RESET_ALL}\n")
                sys.stdout.flush()
                time.sleep(cooldown_time)
                self.block_count = 0  # Resetear contador después del cooldown
                return "COOLDOWN_ACTIVATED"
            
            # Delay progresivo para bloqueos menores
            delay = min(self.consecutive_403_503 * 2, 10)  # 2s, 4s, 6s, 8s, 10s máximo
            sys.stdout.write(f"{Fore.YELLOW}[⏳] Applying {delay}s delay due to blocking...{Style.RESET_ALL}\n")
            sys.stdout.flush()
            time.sleep(delay)
            return "DELAY_APPLIED"
        
        else:
            # Si no es bloqueo, resetear contadores
            if status_code == 200:
                self.consecutive_403_503 = 0
                self.block_count = 0
        
        return "CONTINUE"

    def get_status(self):
        """Retorna el estado actual del WAF"""
        return {
            'waf_detected': self.waf_detected,
            'waf_type': self.waf_type,
            'blocked': self.blocked,
            'bypass_attempts': self.bypass_attempts,
            'can_continue': not self.blocked
        }

    def print_status(self):
        """Imprime solo la detección simple del WAF"""
        if self.waf_detected:
            sys.stdout.write(f"{Fore.RED}[🚨] WAF DETECTED: {self.waf_type} (by content){Style.RESET_ALL}\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{Fore.GREEN}[+] No WAF detected{Style.RESET_ALL}\n")
            sys.stdout.flush()

    def print_blocking_alert(self):
        """Imprime alerta solo cuando el WAF realmente bloquea"""
        if self.waf_detected:
            sys.stdout.write(f"{Fore.RED}[🚨] WAF BLOCKING DETECTED: {self.waf_type} - Requests are being blocked{Style.RESET_ALL}\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{Fore.RED}[🚨] BLOCKING DETECTED: Unknown firewall blocking requests{Style.RESET_ALL}\n")
            sys.stdout.flush()

def test_waf_detection():
    """Función de prueba para el detector de WAF"""
    test_urls = [
        "https://httpbin.org/status/200",
        "https://example.com",
        "https://httpbin.org/status/403"
    ]
    
    for url in test_urls:
        sys.stdout.write(f"\n{Fore.CYAN}Testing: {url}{Style.RESET_ALL}\n")
        sys.stdout.flush()
        detector = WAFDetector(url)
        detector.detect_waf()
        detector.test_bypass()
        detector.print_status()

if __name__ == "__main__":
    test_waf_detection()
