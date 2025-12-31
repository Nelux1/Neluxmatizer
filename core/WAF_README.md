# 🔒 WAF Detection & Bypass System

## 📋 Overview

El sistema de detección y bypass de WAF (Web Application Firewall) de Neluxmatizer es una herramienta avanzada que:

- **Detecta automáticamente** diferentes tipos de WAFs
- **Intenta bypasses** usando múltiples técnicas
- **Se detiene automáticamente** si no puede evadir la protección
- **Proporciona alertas claras** sobre el estado de la protección

## 🚀 Features

### 🔍 **WAF Detection**
- **Headers Analysis**: Detecta WAFs por headers de respuesta
- **Content Analysis**: Identifica páginas de bloqueo
- **Status Code Analysis**: Detecta códigos de estado sospechosos
- **Response Time Monitoring**: Identifica delays sospechosos

### 🛡️ **WAF Types Supported**
- **Cloudflare** - Detección completa con bypass específico
- **AWS WAF** - Headers y técnicas de evasión
- **Akamai** - Bypass de transformaciones
- **Fastly** - Evasión de CDN
- **Incapsula/Sucuri** - Técnicas de bypass
- **F5 BigIP** - Evasión de load balancer
- **ModSecurity** - Bypass de reglas
- **Y muchos más...**

### 🔄 **Bypass Techniques**
- **Header Rotation**: Rotación de headers de bypass
- **User-Agent Spoofing**: Simulación de bots legítimos
- **IP Spoofing**: Headers de IP falsificados
- **Delay Randomization**: Delays aleatorios entre requests
- **Accept Header Variation**: Variación de headers de aceptación
- **Language Header Variation**: Rotación de idiomas

## 📁 Files

### `waf_detector.py`
- **Clase principal** `WAFDetector`
- **Detección automática** de WAFs
- **Sistema de bypass** con múltiples intentos
- **Monitoreo en tiempo real** del estado

### `waf_config.py`
- **Configuración personalizable** del sistema
- **Técnicas específicas** por tipo de WAF
- **Configuración de bypass** avanzado
- **Sistema de alertas** configurable

## 🎯 Usage

### **Integración Automática**
El detector de WAF se ejecuta **automáticamente** en cada escaneo:

```bash
python3 neluxmatizer.py -u https://target.com -a -poc
```

### **Detección Manual**
```python
from waf_detector import WAFDetector

detector = WAFDetector("https://target.com")
if detector.detect_waf():
    print("WAF detected!")
    if detector.test_bypass():
        print("Bypass successful!")
    else:
        print("Cannot bypass WAF")
```

## 🔧 Configuration

### **Configuración Básica**
```python
# En waf_config.py
WAF_CONFIG = {
    'max_bypass_attempts': 5,        # Intentos de bypass
    'bypass_delay_min': 1,           # Delay mínimo (segundos)
    'bypass_delay_max': 3,           # Delay máximo (segundos)
    'request_timeout': 15,           # Timeout de requests
}
```

### **Configuración Específica por WAF**
```python
WAF_SPECIFIC_CONFIG = {
    'cloudflare': {
        'max_attempts': 10,          # Más intentos para Cloudflare
        'bypass_headers': [...],     # Headers específicos
        'user_agents': [...],        # User-Agents específicos
    }
}
```

## 📊 WAF Status Report

### **Sin WAF Detectado**
```
🔒 WAF STATUS REPORT
==================================================
✅ No WAF detected - Safe to continue
==================================================
```

### **WAF Detectado y Bypasseado**
```
🔒 WAF STATUS REPORT
==================================================
🚨 WAF Detected: CLOUDFLARE
🔄 Bypass Attempts: 3
✅ Status: BYPASSED - Can continue scanning
==================================================
```

### **WAF Bloqueando**
```
🔒 WAF STATUS REPORT
==================================================
🚨 WAF Detected: CLOUDFLARE
🔄 Bypass Attempts: 5
❌ Status: BLOCKED - Cannot continue
💡 Recommendation: Stop scanning, WAF is blocking all requests
==================================================
```

## 🚨 Alertas y Notificaciones

### **Tipos de Alertas**
- **🚨 WAF DETECTED**: Se detectó protección
- **🔄 BYPASS ATTEMPT**: Intento de bypass en progreso
- **✅ WAF BYPASSED**: Bypass exitoso
- **❌ WAF BLOCKED**: No se puede evadir
- **⚠️ RATE LIMITED**: Rate limiting detectado

### **Colores de Alerta**
- **🔴 Rojo**: WAF detectado, bloqueado
- **🟡 Amarillo**: Bypass en progreso, rate limiting
- **🟢 Verde**: Sin WAF, bypass exitoso
- **🔵 Azul**: Información, estado

## 🛠️ Advanced Bypass Techniques

### **Header Injection**
- **X-Forwarded-For**: IP falsificada
- **X-Real-IP**: IP real falsificada
- **X-Originating-IP**: IP de origen
- **X-Remote-IP**: IP remota
- **X-Client-IP**: IP del cliente

### **User-Agent Spoofing**
- **Googlebot**: Simulación de crawler de Google
- **Bingbot**: Simulación de crawler de Bing
- **Social Media Bots**: Facebook, Twitter, LinkedIn
- **Browser Emulation**: Chrome, Firefox, Safari, Edge

### **Timing Evasion**
- **Random Delays**: Delays aleatorios entre requests
- **Progressive Backoff**: Aumento gradual de delays
- **Session Persistence**: Mantenimiento de sesiones
- **Cookie Manipulation**: Manipulación de cookies

## 📈 Monitoring & Logging

### **Real-Time Monitoring**
- **Response Times**: Monitoreo de tiempos de respuesta
- **Status Codes**: Análisis de códigos de estado
- **Block Patterns**: Detección de patrones de bloqueo
- **Rate Limiting**: Monitoreo de límites de tasa

### **Logging Options**
```python
'logging': {
    'enable_debug': False,           # Logs de debug
    'log_bypass_attempts': True,     # Log de intentos de bypass
    'log_waf_detection': True,       # Log de detección
    'log_rate_limiting': True,       # Log de rate limiting
}
```

## 🔒 Security Considerations

### **Ethical Usage**
- **Solo usar** en sistemas autorizados
- **Respetar** límites de rate limiting
- **No abusar** de técnicas de bypass
- **Documentar** todas las actividades

### **Legal Compliance**
- **Permisos explícitos** del propietario
- **Cumplimiento** de leyes locales
- **Respeto** de términos de servicio
- **Reporte responsable** de vulnerabilidades

## 🚀 Future Enhancements

### **Planned Features**
- **Machine Learning**: Detección inteligente de WAFs
- **Proxy Rotation**: Rotación automática de proxies
- **Advanced Evasion**: Técnicas de evasión más sofisticadas
- **WAF Fingerprinting**: Identificación precisa de versiones
- **Automated Bypass**: Bypass automático sin intervención

### **Integration Plans**
- **Burp Suite**: Plugin para Burp
- **OWASP ZAP**: Integración con ZAP
- **Metasploit**: Módulo de Metasploit
- **Nmap**: Script de NSE

## 📞 Support & Contributing

### **Issues & Bugs**
- **GitHub Issues**: Reportar problemas
- **Feature Requests**: Solicitar nuevas funcionalidades
- **Bug Reports**: Reportar errores

### **Contributing**
- **Pull Requests**: Contribuciones de código
- **Documentation**: Mejoras en documentación
- **Testing**: Pruebas y validación
- **Feedback**: Comentarios y sugerencias

## 📚 References

### **WAF Documentation**
- [Cloudflare WAF](https://developers.cloudflare.com/waf/)
- [AWS WAF](https://docs.aws.amazon.com/waf/)
- [Akamai Kona](https://www.akamai.com/products/security)
- [Fastly WAF](https://docs.fastly.com/products/waf)

### **Bypass Techniques**
- [OWASP WAF Bypass](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Client_Side_Testing/10-Testing_WebSockets)
- [WAF Bypass Methods](https://github.com/0xInfection/Awesome-WAF)
- [Security Research Papers](https://www.blackhat.com/)

---

**⚠️ Disclaimer**: Esta herramienta es para uso ético y autorizado únicamente. Los usuarios son responsables de cumplir con todas las leyes y regulaciones aplicables.
