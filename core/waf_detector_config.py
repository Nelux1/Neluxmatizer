#!/usr/bin/env python3
"""
Configuración para el detector WAF
Permite personalizar el comportamiento de detección sin bloquear el escaneo
"""

# =============================================================================
# COMPORTAMIENTO DEL DETECTOR WAF
# =============================================================================

# Modo de operación del detector WAF
WAF_DETECTOR_MODE = "INFORMATIVE"  # "INFORMATIVE", "BLOCKING", "ADAPTIVE"

# En modo INFORMATIVE: Solo informa, no bloquea
# En modo BLOCKING: Bloquea si detecta WAF (comportamiento anterior)
# En modo ADAPTIVE: Detecta WAF y ajusta estrategias automáticamente

# =============================================================================
# CONFIGURACIÓN DE DETECCIÓN
# =============================================================================

# Headers específicos de WAF para detección
WAF_SPECIFIC_HEADERS = {
    'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
    'aws': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-cf-region'],
    'akamai': ['x-akamai-transformed', 'x-akamai-origin-hop'],
    'fastly': ['x-fastly', 'x-fastly-ssl', 'x-fastly-ssl-provider'],
    'vercel': ['x-vercel-cache', 'x-vercel-cache-status'],
    'generic': ['x-waf', 'x-security', 'x-protection', 'x-firewall']
}

# Patrones de respuesta que indican WAF
WAF_RESPONSE_PATTERNS = [
    'access denied',
    'forbidden',
    'blocked',
    'security',
    'firewall',
    'ddos protection',
    'rate limit',
    'captcha',
    'challenge',
    'verify'
]

# =============================================================================
# CONFIGURACIÓN DE BYPASS
# =============================================================================

# Habilitar bypass automático durante detección
ENABLE_AUTO_BYPASS = False

# Número de intentos de bypass durante detección
DETECTION_BYPASS_ATTEMPTS = 1

# Timeout para peticiones de bypass
BYPASS_TIMEOUT = 5

# =============================================================================
# CONFIGURACIÓN DE LOGGING
# =============================================================================

# Nivel de detalle en los logs
WAF_LOG_LEVEL = "INFO"  # "DEBUG", "INFO", "WARNING", "ERROR"

# Mostrar detalles técnicos del WAF
SHOW_WAF_TECHNICAL_DETAILS = True

# Mostrar recomendaciones de bypass
SHOW_BYPASS_RECOMMENDATIONS = True

# =============================================================================
# CONFIGURACIÓN AVANZADA
# =============================================================================

# Habilitar fingerprinting detallado del WAF
ENABLE_DETAILED_FINGERPRINTING = True

# Habilitar análisis de patrones de respuesta
ENABLE_RESPONSE_PATTERN_ANALYSIS = True

# Habilitar detección de evasión automática
ENABLE_AUTO_EVASION_DETECTION = False

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN
# =============================================================================

def get_waf_config():
    """Retorna la configuración completa del detector WAF"""
    return {
        'detector_mode': WAF_DETECTOR_MODE,
        'waf_headers': WAF_SPECIFIC_HEADERS,
        'response_patterns': WAF_RESPONSE_PATTERNS,
        'enable_auto_bypass': ENABLE_AUTO_BYPASS,
        'detection_bypass_attempts': DETECTION_BYPASS_ATTEMPTS,
        'bypass_timeout': BYPASS_TIMEOUT,
        'log_level': WAF_LOG_LEVEL,
        'show_technical_details': SHOW_WAF_TECHNICAL_DETAILS,
        'show_bypass_recommendations': SHOW_BYPASS_RECOMMENDATIONS,
        'enable_detailed_fingerprinting': ENABLE_DETAILED_FINGERPRINTING,
        'enable_response_pattern_analysis': ENABLE_RESPONSE_PATTERN_ANALYSIS,
        'enable_auto_evasion_detection': ENABLE_AUTO_EVASION_DETECTION
    }

def is_informative_mode():
    """Verifica si el detector está en modo informativo"""
    return WAF_DETECTOR_MODE == "INFORMATIVE"

def is_blocking_mode():
    """Verifica si el detector está en modo bloqueante"""
    return WAF_DETECTOR_MODE == "BLOCKING"

def is_adaptive_mode():
    """Verifica si el detector está en modo adaptativo"""
    return WAF_DETECTOR_MODE == "ADAPTIVE"

def should_show_technical_details():
    """Verifica si se deben mostrar detalles técnicos"""
    return SHOW_WAF_TECHNICAL_DETAILS

def should_show_bypass_recommendations():
    """Verifica si se deben mostrar recomendaciones de bypass"""
    return SHOW_BYPASS_RECOMMENDATIONS

def print_waf_config():
    """Imprime la configuración actual del detector WAF"""
    config = get_waf_config()
    print("🔒 CONFIGURACIÓN DEL DETECTOR WAF")
    print("=" * 50)
    
    for key, value in config.items():
        if isinstance(value, dict):
            print(f"{key}: {len(value)} categorías")
        elif isinstance(value, list):
            print(f"{key}: {len(value)} elementos")
        else:
            print(f"{key}: {value}")
    
    print("=" * 50)
    print(f"Modo actual: {WAF_DETECTOR_MODE}")
    
    if is_informative_mode():
        print("✅ Modo INFORMATIVO: Solo informa, no bloquea")
    elif is_blocking_mode():
        print("🚨 Modo BLOQUEANTE: Bloquea si detecta WAF")
    elif is_adaptive_mode():
        print("🔄 Modo ADAPTATIVO: Ajusta estrategias automáticamente")

if __name__ == "__main__":
    print_waf_config()
