#!/usr/bin/env python3
"""
Auth Manager - Maneja autenticación continua para scans
"""

import re
from urllib.parse import urlparse

class AuthManager:
    """Maneja cookies de sesión y tokens de autorización para scans autenticados"""
    
    def __init__(self, cookies=None, auth_token=None):
        self.cookies = {}
        self.auth_token = auth_token
        self.session_headers = {}
        
        if cookies:
            self.parse_cookies(cookies)
        
        if auth_token:
            self.set_auth_token(auth_token)
    
    def parse_cookies(self, cookie_string):
        """Parsea string de cookies en diccionario"""
        try:
            # Formato: "name1=value1; name2=value2"
            cookie_pairs = cookie_string.split(';')
            
            for pair in cookie_pairs:
                pair = pair.strip()
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    self.cookies[name.strip()] = value.strip()
            
            print(f"🍪 Parsed {len(self.cookies)} cookies: {list(self.cookies.keys())}")
            
        except Exception as e:
            print(f"❌ Error parsing cookies: {e}")
    
    def set_auth_token(self, token):
        """Configura token de autorización Bearer"""
        self.auth_token = token
        self.session_headers['Authorization'] = f'Bearer {token}'
        print(f"🔑 Authorization Bearer token configured")
    
    def get_session_headers(self, base_headers=None):
        """Retorna headers con autenticación para requests"""
        headers = base_headers.copy() if base_headers else {}
        
        # Agregar token de autorización si existe
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        return headers
    
    def get_cookies_dict(self):
        """Retorna diccionario de cookies para requests"""
        return self.cookies.copy()
    
    def is_authenticated(self):
        """Verifica si hay autenticación configurada"""
        return bool(self.cookies or self.auth_token)
    
    def get_auth_info(self):
        """Retorna información de autenticación configurada"""
        info = []
        
        if self.cookies:
            info.append(f"Cookies: {len(self.cookies)} configured")
        
        if self.auth_token:
            info.append(f"Bearer Token: {self.auth_token[:20]}...")
        
        return " | ".join(info) if info else "No authentication"
    
    def validate_cookies(self, url):
        """Valida que las cookies sean válidas para la URL"""
        if not self.cookies:
            return True
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Verificar cookies de dominio
            for cookie_name in self.cookies:
                # Aquí podrías agregar validaciones específicas
                # Por ejemplo, verificar que las cookies no hayan expirado
                pass
            
            return True
            
        except Exception as e:
            print(f"❌ Error validating cookies for {url}: {e}")
            return False
    
    def refresh_session(self, response_headers):
        """Actualiza cookies de sesión desde headers de respuesta"""
        try:
            if 'Set-Cookie' in response_headers:
                new_cookies = response_headers['Set-Cookie']
                self.parse_cookies(new_cookies)
                print(f"🔄 Session cookies refreshed")
                
        except Exception as e:
            print(f"❌ Error refreshing session: {e}")
    
    def clear_auth(self):
        """Limpia toda la autenticación"""
        self.cookies.clear()
        self.auth_token = None
        self.session_headers.clear()
        print(f"🧹 Authentication cleared")
