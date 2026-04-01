#!/usr/bin/env python3
"""
Advanced Parameter Discovery Module - Inspired by Arjun
Optimized for high-performance parameter fuzzing with multiple threads
"""

import requests
import time
import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import sys
from typing import Dict, List, Tuple, Optional
import re

class ParameterDiscovery:
    def __init__(self, target_url: str, headers: Dict = None, max_threads: int = 100):
        self.target_url = target_url
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Apply limits only for discovery: minimum 20, maximum 200
        if max_threads < 20:
            self.max_threads = 20
        elif max_threads > 200:
            self.max_threads = 200
        else:
            self.max_threads = max_threads
        self.param_wordlist = []
        self.discovered_params = []
        self.baseline = None
        self.lock = threading.Lock()
        self.counter = 0
        self.total_params = 0
        
        # Performance optimizations
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.timeout = 10  # Reduced to 10 seconds for better performance
        
        self.load_wordlists()
    
    def load_wordlists(self):
        """Load comprehensive parameter wordlists for maximum coverage"""
        # Core parameters
        core_params = [
            'id', 'page', 'search', 'q', 'query', 'keyword', 'term', 'filter', 'sort',
            'order', 'limit', 'offset', 'start', 'end', 'from', 'to', 'date', 'time',
            'category', 'tag', 'type', 'status', 'mode', 'view', 'format', 'lang',
            'locale', 'country', 'region', 'city', 'zip', 'lat', 'lng', 'radius',
            'price', 'min_price', 'max_price', 'brand', 'model', 'year', 'color',
            'size', 'weight', 'height', 'width', 'depth', 'material', 'condition'
        ]
        
        # API and authentication parameters
        api_params = [
            'api_key', 'token', 'auth', 'key', 'secret', 'password', 'username',
            'user', 'email', 'phone', 'mobile', 'account', 'session', 'cookie',
            'csrf', 'xsrf', 'nonce', 'challenge', 'captcha', 'verification',
            'confirm', 'validate', 'verify', 'check', 'test', 'debug', 'log'
        ]
        
        # File and upload parameters
        file_params = [
            'file', 'upload', 'image', 'photo', 'picture', 'video', 'audio',
            'document', 'attachment', 'media', 'content', 'data', 'payload',
            'input', 'form', 'submit', 'action', 'method', 'enctype'
        ]
        
        # Advanced parameters
        advanced_params = [
            'callback', 'jsonp', 'redirect', 'url', 'link', 'href', 'src',
            'target', 'window', 'popup', 'modal', 'dialog', 'overlay',
            'notification', 'alert', 'message', 'error', 'warning', 'info',
            'success', 'fail', 'result', 'output', 'response', 'data',
            'json', 'xml', 'html', 'text', 'plain', 'raw', 'binary'
        ]
        
        # Parameter variations and combinations
        variations = []
        for param in core_params + api_params + file_params + advanced_params:
            variations.extend([
                param,
                f"{param}_id",
                f"{param}_name", 
                f"{param}_type",
                f"{param}_value",
                f"{param}_key",
                f"{param}_code",
                f"{param}_hash",
                f"{param}_token",
                f"{param}_param",
                f"{param}_field",
                f"{param}_input",
                f"{param}_data"
            ])
        
        # Add common abbreviations and short forms
        short_forms = ['p', 's', 'q', 'i', 'u', 'a', 'c', 't', 'd', 'f', 'v', 'r', 'x', 'y', 'z']
        
        self.param_wordlist = list(set(core_params + api_params + file_params + advanced_params + variations + short_forms))
        self.total_params = len(self.param_wordlist)
        
        #print(f"📚 Loaded {self.total_params} parameters for discovery")
    
    def get_baseline(self) -> Dict:
        """Get baseline response for comparison with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Use shorter timeout for baseline
                timeout_val = 3 + (attempt * 2)  # 3, 5, 7 seconds
                response = self.session.get(self.target_url, timeout=timeout_val)
                return {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_hash': hashlib.md5(response.content).hexdigest()[:8],
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }
            except Exception as e:
                if attempt < max_retries - 1:
                    # Silent retry - no need to spam the user
                    time.sleep(1)  # Shorter wait
                else:
                    # Only show a simple message when all attempts fail
                    #sys.stdout.write(f"⚠️ Continuing without baseline comparison\n")
                    #sys.stdout.flush()
                    # Return a default baseline to allow discovery to continue
                    pass
                    return {
                        'status_code': 200,
                        'content_length': 0,
                        'content_hash': 'default',
                        'headers': {},
                        'response_time': 0.0
                    }
    
    def test_parameter(self, param: str) -> Optional[Dict]:
        """Test a single parameter with optimized performance"""
        try:
            # Test with a unique value that's unlikely to exist
            test_value = f"nelux_test_{int(time.time() * 1000)}"
            
            # Prepare test data
            if '?' in self.target_url:
                test_url = f"{self.target_url}&{param}={test_value}"
            else:
                test_url = f"{self.target_url}?{param}={test_value}"
            
            # Make request with optimized settings
            response = self.session.get(
                test_url, 
                timeout=3,  # Very short timeout for parameter testing
                allow_redirects=False  # Faster without redirects
            )
            
            # Quick validation
            if response.status_code != 200:
                return None
            
            # Calculate differences efficiently
            content_length = len(response.content)
            content_hash = hashlib.md5(response.content).hexdigest()[:8]
            
            # Check if parameter is valid based on response differences
            if self._is_parameter_valid(param, test_value, response, content_length, content_hash):
                with self.lock:
                    self.counter += 1
                    self._print_progress(param)
                
                return {
                    'parameter': param,
                    'test_value': test_value,
                    'status_code': response.status_code,
                    'content_length': content_length,
                    'content_hash': content_hash,
                    'difference_score': self._calculate_difference(response, content_length, content_hash),
                    'parameter_type': self._classify_parameter(param, response)
                }
            
            return None
            
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception as e:
            return None
    
    def _is_parameter_valid(self, param: str, test_value: str, response, content_length: int, content_hash: str) -> bool:
        """Determine if parameter is valid based on response analysis"""
        if not self.baseline:
            return False
        
        # Check for significant differences
        status_diff = abs(response.status_code - self.baseline['status_code'])
        length_diff = abs(content_length - self.baseline['content_length'])
        hash_diff = content_hash != self.baseline['content_hash']
        
        # Parameter is valid if:
        # 1. Status code changed significantly
        # 2. Content length changed significantly (>5% difference for better detection)
        # 3. Content hash changed (different content)
        # 4. Response contains error messages or validation feedback
        
        if status_diff > 0:
            return True
        
        # More sensitive length detection
        if self.baseline['content_length'] > 0:
            length_ratio = length_diff / self.baseline['content_length']
            if length_ratio > 0.05:  # 5% difference
                return True
        elif length_diff > 100:  # If baseline is 0, any significant length is valid
            return True
        
        if hash_diff:
            return True
        
        # Check for error messages or validation feedback
        content_lower = response.text.lower()
        error_indicators = ['error', 'invalid', 'required', 'missing', 'parameter', 'unknown', 'not found', 'undefined']
        if any(indicator in content_lower for indicator in error_indicators):
            return True
        
        # Check if the test value appears in the response (reflection)
        if test_value in response.text:
            return True
        
        return False
    
    def _calculate_difference(self, response, content_length: int, content_hash: str) -> int:
        """Calculate difference score for parameter validation"""
        if not self.baseline:
            return 0
        
        score = 0
        
        # Status code difference
        status_diff = abs(response.status_code - self.baseline['status_code'])
        score += status_diff * 10
        
        # Content length difference
        length_diff = abs(content_length - self.baseline['content_length'])
        if length_diff > 0:
            score += min(length_diff // 100, 50)  # Cap at 50 points
        
        # Content hash difference
        if content_hash != self.baseline['content_hash']:
            score += 100
        
        # Response time difference
        time_diff = abs(response.elapsed.total_seconds() - self.baseline['response_time'])
        if time_diff > 0.1:  # More than 100ms difference
            score += 20
        
        return score
    
    def _classify_parameter(self, param: str, response) -> str:
        """Classify discovered parameter type"""
        param_lower = param.lower()
        content_lower = response.text.lower()
        
        if any(x in param_lower for x in ['id', 'key', 'hash', 'token']):
            return 'identifier'
        elif any(x in param_lower for x in ['search', 'q', 'query', 'keyword']):
            return 'search'
        elif any(x in param_lower for x in ['page', 'limit', 'offset', 'start']):
            return 'pagination'
        elif any(x in param_lower for x in ['filter', 'sort', 'order', 'category']):
            return 'filtering'
        elif any(x in param_lower for x in ['file', 'upload', 'image', 'media']):
            return 'file'
        elif any(x in param_lower for x in ['api', 'auth', 'token', 'key']):
            return 'authentication'
        else:
            return 'general'
    
    def _print_progress(self, param: str):
        """Print progress inline with the existing system"""
        progress = f"\r🔍 Discovering parameters... Found: {self.counter}/{self.total_params} | Latest: {param[:30]}..."
        # Limpiar la línea completamente antes de escribir
        sys.stdout.write(f"\r\033[K{progress}")
        sys.stdout.flush()
    
    def discover_parameters(self) -> List[Dict]:
        """Discover parameters using high-performance threading"""
        
        # Get baseline
        self.baseline = self.get_baseline()
        if not self.baseline:
            # Continue with discovery even without baseline
            self.baseline = {
                'status_code': 200,
                'content_length': 0,
                'content_hash': 'default',
                'headers': {},
                'response_time': 0.0
            }
        
        # Keep user-specified thread count even if baseline fails
        # The user knows what they're doing with their thread count
        
        #print(f"📊 Baseline: Status {self.baseline['status_code']}, Length {self.baseline['content_length']}, Hash {self.baseline['content_hash']}")
        
        #sys.stdout.write(f"🔍 Starting parameter discovery with {self.max_threads} threads...\n")
        #sys.stdout.flush()
        
        # Use ThreadPoolExecutor for maximum performance
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all tasks at once for maximum parallelism
                future_to_param = {
                    executor.submit(self.test_parameter, param): param 
                    for param in self.param_wordlist
                }
                
                # Process completed tasks
                for future in as_completed(future_to_param):
                    try:
                        # Check for interruption before processing each result
                        from parametizer.interrupt import check_interruption
                        if check_interruption():
                            # Cancel all pending tasks
                            for f in future_to_param.keys():
                                f.cancel()
                            return self.discovered_params
                        
                        result = future.result()
                        if result:
                            self.discovered_params.append(result)
                    except Exception as e:
                        continue
        except KeyboardInterrupt:
            from parametizer.interrupt import is_interrupted
            if is_interrupted():
                return self.discovered_params
            else:
                raise
        except Exception as e:
            sys.stdout.write(f"\n⚠️ Parameter discovery error: {e}\n")
            sys.stdout.write(f"⚠️ Continuing with {len(self.discovered_params)} parameters found so far\n")
            sys.stdout.flush()
        
        # Final progress update (clear line completely)
        sys.stdout.write(f"\r\033[K")
        sys.stdout.flush()
        
        # Resumen en pantalla lo hace scan_lista (totales + discovery)

        return self.discovered_params
    
    def generate_attack_urls(self) -> List[str]:
        """Generate attack URLs with discovered parameters"""
        if not self.discovered_params:
            return []
        
        attack_urls = []
        base_url = self.target_url
        
        for param_info in self.discovered_params:
            param = param_info['parameter']
            
            # Generate various payload types for each parameter
            payloads = self._generate_payloads(param)
            
            for payload in payloads:
                if '?' in base_url:
                    attack_url = f"{base_url}&{param}={payload}"
                else:
                    attack_url = f"{base_url}?{param}={payload}"
                
                attack_urls.append(attack_url)
        
        return attack_urls
    
    def _generate_payloads(self, param: str) -> List[str]:
        """Generate attack payloads based on parameter type"""
        # Basic injection payloads
        basic_payloads = [
            "'", '"', '`', ';', '--', '/*', '*/', '{{', '}}', '${', '}',
            '<script>alert(1)</script>', 'javascript:alert(1)',
            '1 OR 1=1', '1 UNION SELECT 1', '1; DROP TABLE users',
            '../../../etc/passwd', 'file:///etc/passwd',
            'http://localhost:8080', 'http://169.254.169.254/latest/meta-data/'
        ]
        
        # Parameter-specific payloads
        if 'id' in param.lower():
            basic_payloads.extend(['1', '0', '-1', '999999', 'null', 'undefined'])
        elif 'search' in param.lower() or 'q' in param.lower():
            basic_payloads.extend(['test', 'admin', 'user', 'password', 'secret'])
        elif 'file' in param.lower() or 'upload' in param.lower():
            basic_payloads.extend(['test.txt', 'test.php', 'test.jpg', 'test.pdf'])
        
        return basic_payloads[:10]  # Limit to 10 payloads per parameter
    
    def save_results(self, filename: str = None):
        """Save discovery results to file"""
        if not filename:
            timestamp = int(time.time())
            filename = f"param_discovery_{timestamp}.json"
        
        results = {
            'target_url': self.target_url,
            'discovery_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_parameters_tested': self.total_params,
            'discovered_parameters': self.discovered_params,
            'attack_urls': self.generate_attack_urls(),
            'baseline': self.baseline
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            sys.stdout.write(f"💾 Results saved to {filename}\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f"❌ Error saving results: {e}\n")
            sys.stdout.flush()
    
    def get_discovered_urls(self) -> List[str]:
        """Get discovered URLs in the format needed for scanners"""
        discovered_urls = []
        
        for param_info in self.discovered_params:
            param = param_info['parameter']
            
            # Create URL with discovered parameter
            if '?' in self.target_url:
                discovered_url = f"{self.target_url}&{param}=test"
            else:
                discovered_url = f"{self.target_url}?{param}=test"
            
            discovered_urls.append(discovered_url)
        
        return discovered_urls

def main():
    """Test the parameter discovery module"""
    target_url = "http://httpbin.org/get"
    
    sys.stdout.write("🧪 Testing Parameter Discovery Module\n")
    sys.stdout.flush()
    sys.stdout.write(f"🎯 Target: {target_url}\n")
    sys.stdout.flush()
    sys.stdout.write("=" * 50 + "\n")
    sys.stdout.flush()
    
    # Initialize with high thread count
    discovery = ParameterDiscovery(target_url, max_threads=200)
    
    # Discover parameters
    start_time = time.time()
    discovered = discovery.discover_parameters()
    end_time = time.time()
    
    sys.stdout.write(f"\n⏱️  Discovery completed in {end_time - start_time:.2f} seconds\n")
    sys.stdout.flush()
    sys.stdout.write(f"🎯 Found {len(discovered)} parameters\n")
    sys.stdout.flush()
    
    if discovered:
        sys.stdout.write("\n📋 Discovered Parameters:\n")
        sys.stdout.flush()
        for param_info in discovered[:10]:  # Show first 10
            sys.stdout.write(f"  • {param_info['parameter']} ({param_info['parameter_type']}) - Score: {param_info['difference_score']}\n")
            sys.stdout.flush()
        
        if len(discovered) > 10:
            sys.stdout.write(f"  ... and {len(discovered) - 10} more\n")
            sys.stdout.flush()
    
    # Generate attack URLs
    attack_urls = discovery.generate_attack_urls()
    sys.stdout.write(f"\n⚔️  Generated {len(attack_urls)} attack URLs\n")
    sys.stdout.flush()
    
    # Save results
    discovery.save_results()
    
    # Get discovered URLs for scanner integration
    discovered_urls = discovery.get_discovered_urls()
    sys.stdout.write(f"\n🔗 Discovered URLs ready for scanning: {len(discovered_urls)}\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
