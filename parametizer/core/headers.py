# set_headers.py
import random
import sys

#Como usar el modulo?
#from core.set_headers import get_headers  # o simplemente `from headers import get_headers`
#headers = get_headers(custom_headers, random_agent)


# Lista de 25 User-Agents variados y actuales
user_agents = [
    # Navegadores modernos
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.70 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Edge y Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Safari/537.36 Edg/124.0.2478.67",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 OPR/110.0.0.0",
    # Móviles - Android
    "Mozilla/5.0 (Linux; Android 13; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    # Móviles - iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # CLI tools
    "curl/8.0.1",
    "Wget/1.21.3",
    "python-requests/2.31.0",
    "httpie/3.2.1",
    "PostmanRuntime/7.36.3",
    # Navegadores alternativos
    "Brave/124.0.6367.78",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/124.0.6367.78 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vivaldi/6.5.3206.47",
    # Headless / Bots
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/124.0.6367.78 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    # Otros dispositivos
    "Mozilla/5.0 (PlayStation 5 3.00) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    "Mozilla/5.0 (SmartTV; Linux; Tizen 6.5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/6.5",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Safari/534.57.2"
]

def get_headers(random_agent=False, custom_headers=None):
    headers = {}

    # Si hay headers personalizados, los agregamos primero
    if custom_headers:
        headers.update(custom_headers)

    # Si el usuario quiere un User-Agent aleatorio, y no hay uno personalizado
    if "User-Agent" not in headers and random_agent:
        headers["User-Agent"] = random.choice(user_agents)

    # Si no hay ningún User-Agent en absoluto, usamos uno por defecto
    if "User-Agent" not in headers:
        headers["User-Agent"] = user_agents[0]

    return headers


def parse_headers(header_string):
    """
    Convierte una cadena tipo 'Key1: Value1,Key2: Value2'
    en un diccionario {Key1: Value1, Key2: Value2}
    """
    headers = {}
    if header_string:
        try:
            parts = header_string.split(",")
            for part in parts:
                key, value = part.split(":", 1)
                headers[key.strip()] = value.strip()
        except ValueError:
            sys.stdout.write("[!] Error: Formato de headers inválido. Usa: 'Key: Value,Key2: Value2'\n")
        sys.stdout.flush()
    return headers