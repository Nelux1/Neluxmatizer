#!/usr/bin/env python3
"""
WAF Configuration for Neluxmatizer
Customize WAF detection and bypass behavior
"""

# Configuración general del WAF
WAF_CONFIG = {
    # Número máximo de intentos de bypass
    'max_bypass_attempts': 5,
    
    # Delay entre intentos de bypass (segundos)
    'bypass_delay_min': 1,
    'bypass_delay_max': 3,
    
    # Timeout para requests (segundos)
    'request_timeout': 15,
    
    # Headers adicionales para bypass
    'additional_bypass_headers': {
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Port': '443',
        'X-Forwarded-Host': 'localhost',
        'X-Forwarded-Server': 'localhost',
        'X-HTTP-Host-Override': 'localhost',
        'X-Original-URL': '/',
        'X-Rewrite-URL': '/',
        'X-Custom-IP-Authorization': '127.0.0.1',
    },
    
    # User-Agents adicionales para bypass
    'additional_user_agents': [
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
        'Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 6.1; Trident/7.0)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    ],
    
    # Técnicas de bypass habilitadas
    'bypass_techniques': {
        'header_rotation': True,
        'user_agent_rotation': True,
        'ip_spoofing': True,
        'delay_randomization': True,
        'accept_header_variation': True,
        'language_header_variation': True,
    },
    
    # Headers de Accept para variación
    'accept_headers': [
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8;q=0.5',
    ],
    
    # Headers de Accept-Language para variación
    'language_headers': [
        'en-US,en;q=0.5',
        'en-US,en;q=0.9,es;q=0.8',
        'en-US,en;q=0.9,fr;q=0.8',
        'en-US,en;q=0.9,de;q=0.8',
        'en-US,en;q=0.9,it;q=0.8',
        'en-US,en;q=0.9,pt;q=0.8',
        'en-US,en;q=0.9,ru;q=0.8',
        'en-US,en;q=0.9,ja;q=0.8',
        'en-US,en;q=0.9,ko;q=0.8',
        'en-US,en;q=0.9,zh;q=0.8',
    ],
    
    # Configuración de rate limiting
    'rate_limit_config': {
        'check_interval': 10,  # segundos entre checks
        'max_requests_per_minute': 60,
        'backoff_multiplier': 2,
        'max_backoff': 300,  # 5 minutos
    },
    
    # Configuración de logging
    'logging': {
        'enable_debug': False,
        'log_bypass_attempts': True,
        'log_waf_detection': True,
        'log_rate_limiting': True,
    },
    
    # Configuración de evasión
    'evasion_config': {
        'randomize_delays': True,
        'use_proxy_rotation': False,
        'proxy_list': [],  # Lista de proxies para rotación
        'session_persistence': True,
        'cookie_manipulation': True,
    },
    
    # Configuración de detección
    'detection_config': {
        'check_headers': True,
        'check_content': True,
        'check_status_codes': True,
        'check_response_time': True,
        'suspicious_response_time': 10,  # segundos
    },
}

# Configuración específica por tipo de WAF
WAF_SPECIFIC_CONFIG = {
    'cloudflare': {
        'bypass_headers': [
            {'CF-Connecting-IP': '127.0.0.1'},
            {'CF-IPCountry': 'US'},
            {'CF-Visitor': '{"scheme":"https"}'},
            {'CF-Device-Type': 'desktop'},
            {'CF-Browser': 'chrome'},
        ],
        'user_agents': [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        ],
        'max_attempts': 10,
    },
    
    'aws_waf': {
        'bypass_headers': [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Proto': 'https'},
        ],
        'user_agents': [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        ],
        'max_attempts': 8,
    },
    
    'akamai': {
        'bypass_headers': [
            {'X-Akamai-Transformed': '7'},
            {'X-Akamai-Origin-Hop': '1'},
        ],
        'user_agents': [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        ],
        'max_attempts': 6,
    },
    
    'fastly': {
        'bypass_headers': [
            {'X-Fastly': '1'},
            {'X-Fastly-Client-IP': '127.0.0.1'},
        ],
        'user_agents': [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        ],
        'max_attempts': 6,
    },
}

# Configuración de alertas
ALERT_CONFIG = {
    'waf_detected': {
        'color': 'red',
        'icon': '🚨',
        'message': 'WAF DETECTED: {waf_type}',
        'sound': False,
    },
    
    'waf_bypassed': {
        'color': 'green',
        'icon': '✅',
        'message': 'WAF BYPASSED: {waf_type}',
        'sound': False,
    },
    
    'waf_blocked': {
        'color': 'red',
        'icon': '💀',
        'message': 'WAF BLOCKED: Cannot continue scanning',
        'sound': True,
    },
    
    'rate_limited': {
        'color': 'yellow',
        'icon': '⚠️',
        'message': 'RATE LIMITED: Slowing down requests',
        'sound': False,
    },
}

# Configuración de bypass avanzado
ADVANCED_BYPASS_CONFIG = {
    'http_method_rotation': True,
    'url_encoding_variations': True,
    'parameter_pollution': True,
    'header_injection': True,
    'cookie_manipulation': True,
    'session_fixation': True,
    'time_based_evasion': True,
    'fragmentation_attack': True,
}

# Configuración de monitoreo
MONITORING_CONFIG = {
    'enable_real_time_monitoring': True,
    'monitor_response_times': True,
    'monitor_status_codes': True,
    'monitor_block_patterns': True,
    'alert_on_suspicious_activity': True,
    'log_all_requests': False,
    'save_blocked_responses': True,
}
