#!/usr/bin/env python3
"""
Archivo de configuración para el Sistema de Manejo de Bloqueos WAF
Permite personalizar comportamientos sin modificar el código principal
"""

# =============================================================================
# CONFIGURACIÓN DE DETECCIÓN DE BLOQUEOS
# =============================================================================

# Códigos de estado HTTP que indican bloqueo
BLOCK_STATUS_CODES = [403, 429, 503, 509, 451]

# Headers HTTP que pueden indicar presencia de WAF
WAF_INDICATOR_HEADERS = [
    'cf-ray',           # Cloudflare
    'cf-cache-status',  # Cloudflare
    'x-cdn',           # CDN genérico
    'x-waf',           # WAF genérico
    'x-security',      # Seguridad
    'server',          # Servidor
    'via',             # Proxy
    'x-powered-by',    # Tecnología
    'x-amz-cf-id',     # AWS CloudFront
    'x-akamai-transformed', # Akamai
    'x-fastly',        # Fastly
    'x-vercel-cache'   # Vercel
]

# Palabras clave en headers que indican bloqueo
BLOCK_INDICATOR_KEYWORDS = [
    'cloudflare', 'waf', 'blocked', 'rate-limit', 'throttled',
    'security', 'firewall', 'ddos', 'bot', 'suspicious',
    'captcha', 'challenge', 'verify', 'block'
]

# =============================================================================
# CONFIGURACIÓN DE BYPASS
# =============================================================================

# Número máximo de bloqueos antes de considerar el target como bloqueado
MAX_BLOCKS_BEFORE_GIVING_UP = 5

# Número máximo de intentos de bypass por bloqueo
MAX_BYPASS_ATTEMPTS = 3

# Multiplicador base para delays exponenciales
BASE_DELAY_MULTIPLIER = 1.0

# Delay máximo en segundos (para evitar esperas muy largas)
MAX_DELAY_SECONDS = 60

# =============================================================================
# CONFIGURACIÓN DE USER-AGENTS PARA BYPASS
# =============================================================================

BYPASS_USER_AGENTS = [
    # Navegadores modernos
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    
    # Navegadores alternativos
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    
    # Herramientas de línea de comandos
    'curl/7.88.1',
    'wget/1.21.4',
    'python-requests/2.31.0',
    
    # Bots legítimos
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    
    # Dispositivos móviles
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
]

# =============================================================================
# CONFIGURACIÓN DE PROXIES
# =============================================================================

# Archivo de proxies por defecto
DEFAULT_PROXY_FILE = "proxies.txt"

# Variables de entorno para proxies
PROXY_ENV_VARS = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']

# Timeout para peticiones a través de proxy (más alto por latencia)
PROXY_TIMEOUT = 15

# =============================================================================
# CONFIGURACIÓN DE DELAYS
# =============================================================================

# Delays base en segundos para diferentes tipos de bloqueo
DELAY_BASE_TIMES = {
    403: 2,    # Forbidden - delay corto
    429: 5,    # Too Many Requests - delay medio
    503: 10,   # Service Unavailable - delay largo
    509: 15,   # Bandwidth Limit Exceeded - delay muy largo
    451: 3     # Unavailable For Legal Reasons - delay corto
}

# Multiplicador para delays exponenciales
EXPONENTIAL_DELAY_MULTIPLIER = 1.5

# =============================================================================
# CONFIGURACIÓN DE LOGGING
# =============================================================================

# Habilitar logging detallado
ENABLE_VERBOSE_LOGGING = True

# Colores para diferentes tipos de mensajes
LOG_COLORS = {
    'BLOCK': 'RED',
    'BYPASS': 'YELLOW',
    'SUCCESS': 'GREEN',
    'INFO': 'CYAN',
    'WARNING': 'YELLOW',
    'ERROR': 'RED'
}

# =============================================================================
# CONFIGURACIÓN AVANZADA
# =============================================================================

# Habilitar rotación automática de IPs (requiere proxies)
ENABLE_IP_ROTATION = False

# Habilitar fingerprinting de WAF para bypass más inteligente
ENABLE_WAF_FINGERPRINTING = True

# Habilitar machine learning para patrones de bypass (experimental)
ENABLE_ML_BYPASS = False

# Tamaño máximo del historial de bloqueos (para evitar uso excesivo de memoria)
MAX_BLOCK_HISTORY_SIZE = 100

# =============================================================================
# CONFIGURACIÓN DE RETRY
# =============================================================================

# Número máximo de reintentos automáticos
MAX_AUTO_RETRIES = 3

# Delay entre reintentos automáticos
AUTO_RETRY_DELAY = 2

# Backoff exponencial para reintentos
ENABLE_EXPONENTIAL_BACKOFF = True

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN
# =============================================================================

def get_config():
    """Retorna la configuración completa como diccionario"""
    return {
        'block_status_codes': BLOCK_STATUS_CODES,
        'waf_indicator_headers': WAF_INDICATOR_HEADERS,
        'block_indicator_keywords': BLOCK_INDICATOR_KEYWORDS,
        'max_blocks': MAX_BLOCKS_BEFORE_GIVING_UP,
        'max_bypass_attempts': MAX_BYPASS_ATTEMPTS,
        'base_delay_multiplier': BASE_DELAY_MULTIPLIER,
        'max_delay_seconds': MAX_DELAY_SECONDS,
        'bypass_user_agents': BYPASS_USER_AGENTS,
        'default_proxy_file': DEFAULT_PROXY_FILE,
        'proxy_env_vars': PROXY_ENV_VARS,
        'proxy_timeout': PROXY_TIMEOUT,
        'delay_base_times': DELAY_BASE_TIMES,
        'exponential_delay_multiplier': EXPONENTIAL_DELAY_MULTIPLIER,
        'enable_verbose_logging': ENABLE_VERBOSE_LOGGING,
        'log_colors': LOG_COLORS,
        'enable_ip_rotation': ENABLE_IP_ROTATION,
        'enable_waf_fingerprinting': ENABLE_WAF_FINGERPRINTING,
        'enable_ml_bypass': ENABLE_ML_BYPASS,
        'max_block_history_size': MAX_BLOCK_HISTORY_SIZE,
        'max_auto_retries': MAX_AUTO_RETRIES,
        'auto_retry_delay': AUTO_RETRY_DELAY,
        'enable_exponential_backoff': ENABLE_EXPONENTIAL_BACKOFF
    }

def update_config(new_config):
    """Actualiza la configuración con nuevos valores"""
    global BLOCK_STATUS_CODES, WAF_INDICATOR_HEADERS, BLOCK_INDICATOR_KEYWORDS
    global MAX_BLOCKS_BEFORE_GIVING_UP, MAX_BYPASS_ATTEMPTS, BASE_DELAY_MULTIPLIER
    global MAX_DELAY_SECONDS, BYPASS_USER_AGENTS, DEFAULT_PROXY_FILE
    global PROXY_ENV_VARS, PROXY_TIMEOUT, DELAY_BASE_TIMES
    global EXPONENTIAL_DELAY_MULTIPLIER, ENABLE_VERBOSE_LOGGING, LOG_COLORS
    global ENABLE_IP_ROTATION, ENABLE_WAF_FINGERPRINTING, ENABLE_ML_BYPASS
    global MAX_BLOCK_HISTORY_SIZE, MAX_AUTO_RETRIES, AUTO_RETRY_DELAY
    global ENABLE_EXPONENTIAL_BACKOFF
    
    for key, value in new_config.items():
        if key in globals():
            globals()[key.upper()] = value

def print_config():
    """Imprime la configuración actual"""
    config = get_config()
    print("🔒 CONFIGURACIÓN ACTUAL DEL SISTEMA DE BLOQUEOS")
    print("=" * 60)
    
    for key, value in config.items():
        if isinstance(value, list):
            print(f"{key}: {len(value)} elementos")
        else:
            print(f"{key}: {value}")
    
    print("=" * 60)

if __name__ == "__main__":
    print_config()
