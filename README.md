# 🔍 Neluxmatizer - Advanced Web Vulnerability Scanner

A comprehensive web application security scanner with advanced WAF (Web Application Firewall) detection, bypass capabilities, and automated vulnerability discovery.

## 🚀 Features

### 🔒 **WAF Detection & Bypass System**
- **Intelligent WAF Detection**: Automatically detects Cloudflare, AWS WAF, Akamai, and other major WAFs
- **Informative Mode**: WAF detection doesn't block scanning - allows complete reconnaissance
- **Active Block Handling**: Monitors for 403/429 responses during attacks and applies bypass strategies
- **Exponential Backoff**: Smart delay system with increasing wait times
- **User-Agent Rotation**: Automatic User-Agent switching to evade detection
- **Proxy Support**: Configurable proxy usage for bypass attempts
- **Partial Result Saving**: Saves discovered vulnerabilities even if scan is interrupted

### 🎯 **Vulnerability Scanners**
- **XSS (Cross-Site Scripting)**: Comprehensive XSS payload testing
- **SQL Injection**: Advanced SQLi detection with multiple techniques
- **LFI (Local File Inclusion)**: Path traversal and file inclusion testing
- **RCE (Remote Code Execution)**: Command injection vulnerability detection
- **SSRF (Server-Side Request Forgery)**: Internal network access testing
- **XXE (XML External Entity)**: XML parsing vulnerability detection
- **SSTI (Server-Side Template Injection)**: Template injection testing
- **Open Redirect**: URL redirection vulnerability detection
- **CRLF Injection**: HTTP header injection testing
- **Clickjacking**: Frame injection and UI redressing detection
- **CORS Misconfiguration**: Cross-Origin Resource Sharing testing

### 🔍 **Advanced Discovery**
- **Parameter Discovery**: Finds GET/POST parameters from multiple sources
- **Form Discovery**: Automatically discovers and analyzes web forms
- **JavaScript Analysis**: Extracts parameters from client-side code
- **Sitemap Analysis**: Processes XML sitemaps for URL discovery
- **Wayback Machine Integration**: Historical URL discovery
- **CommonCrawl Integration**: Large-scale web archive scanning
- **Certificate Transparency**: Subdomain discovery via SSL certificates
- **Robots.txt Analysis**: Respects and analyzes robots.txt files

### 📊 **Output & Reporting**
- **Multiple Output Formats**: Text, JSON, and custom formats
- **Proof of Concept (PoC) Generation**: Creates HTML files demonstrating vulnerabilities
- **Screenshot Capture**: Automatic screenshots of successful exploits
- **Detailed Logging**: Comprehensive scan logs with timestamps
- **Progress Tracking**: Real-time progress indicators
- **Statistics Reporting**: Summary of findings and scan metrics

### ⚙️ **Configuration & Customization**
- **Threading Control**: Configurable thread count for performance
- **Custom Headers**: User-defined HTTP headers
- **Timeout Settings**: Adjustable request timeouts
- **Proxy Configuration**: Support for HTTP/HTTPS proxies
- **WAF Bypass Settings**: Configurable bypass strategies
- **Output Customization**: Flexible output formatting

## 🛠️ Installation

### Prerequisites
```bash
# Python 3.7+ required
python3 --version

# Ensure pip is available
pip3 --version
```

### Quick Installation
```bash
# Clone or download the tool
git clone <repository-url>
cd neluxmatizer

# Run the installation script
./install.sh

# Or install manually
pip3 install -r requirements.txt
chmod +x neluxmatizer.py
```

### Installation Options

#### Option 1: Automated Installation (Recommended)
```bash
# Make install script executable
chmod +x install.sh

# Run installation script
./install.sh
```

The script offers 4 installation methods:
1. **Global installation** (requires sudo) - Installs for all users
2. **Virtual environment** (recommended) - Isolated Python environment
3. **User directory** (no sudo) - Installs in `~/.local/`
4. **Manual setup** - Shows instructions for manual installation

The script automatically:
- ✅ Checks Python version (requires 3.7+)
- ✅ Verifies pip3 availability
- ✅ Creates necessary directories (`output/poc`, `reports`)
- ✅ Makes `neluxmatizer.py` executable
- ✅ Installs all dependencies from `requirements.txt`

#### Option 2: Manual Installation
```bash
# Install all dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x neluxmatizer.py

# Create output directories
mkdir -p output/poc reports
```

#### Option 3: Virtual Environment (Recommended for Development)
```bash
# Create virtual environment
python3 -m venv neluxmatizer_env
source neluxmatizer_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python neluxmatizer.py -u https://target.com

# Deactivate when done
deactivate
```

### Quick Start
```bash
# Basic usage
python3 neluxmatizer.py -u https://target.com

# Check help
python3 neluxmatizer.py -h
```

## 📖 Usage Examples

### Basic Scanning
```bash
# Single URL scan
python3 neluxmatizer.py -u https://example.com

# Multiple URLs from file
python3 neluxmatizer.py -l urls.txt

# Specific vulnerability scan
python3 neluxmatizer.py -u https://example.com -xss -sql

# Scan with custom wordlist
python3 neluxmatizer.py -u https://example.com -xss -w custom_payloads.txt
```

### Advanced Scanning
```bash
# All vulnerabilities with output and PoC
python3 neluxmatizer.py -u https://example.com -a -o results.txt -poc

# High-thread scanning with custom headers
python3 neluxmatizer.py -u https://example.com -t 100 -H "X-Custom: value"

# Scan with authentication
python3 neluxmatizer.py -u https://example.com -a -A "Bearer token123" -poc

# Scan with cookies and random user agent
python3 neluxmatizer.py -u https://example.com -a -C "session=abc123" -ra -poc

# Exclude specific vulnerabilities from scan
python3 neluxmatizer.py -u https://example.com -a -E xss,click -poc
```

### SSRF Scanning with OOB Detection
```bash
# SSRF scan with custom OOB domain
python3 neluxmatizer.py -u https://example.com -ssrf -obd https://your-subdomain.oastify.com -poc

# SSRF scan with OOB domain from file list
python3 neluxmatizer.py -l urls.txt -ssrf -obd https://yeg07ov7627nnddkrmu01nas7jda11pq.oastify.com -poc -t 100
```

### Targeted Vulnerability Scans
```bash
# XSS scan with PoC generation
python3 neluxmatizer.py -u https://example.com -xss -poc

# SQL Injection scan
python3 neluxmatizer.py -u https://example.com -sql -t 50

# Clickjacking scan with interactive PoC
python3 neluxmatizer.py -u https://example.com -click -poc -t 100

# Multiple specific vulnerabilities
python3 neluxmatizer.py -u https://example.com -xss -sql -lfi -rce -poc
```

## 🔧 Command Line Options

### Basic Options
- `-u, --url`: Target URL to scan
- `-l, --list`: File containing list of URLs (supports `~` for home directory)
- `-t, --threads`: Number of threads (default: 30)
- `-o, --output`: Output file for results
- `-poc, --poc`: Generate Proof of Concept files (HTML + interactive demos)
- `-v`: Show version information
- `-w, --wordlist`: Custom wordlist of payloads

### Vulnerability Scanners
- `-a, --all`: Scan all vulnerabilities
- `-xss`: Cross-Site Scripting scan
- `-sql`: SQL Injection scan
- `-lfi`: Local File Inclusion scan
- `-rce`: Remote Code Execution scan
- `-ssrf`: Server-Side Request Forgery scan
- `-xxe`: XML External Entity scan
- `-ssti`: Server-Side Template Injection scan
- `-redirect`: Open Redirect scan
- `-crlf`: CRLF Injection scan
- `-click`: Clickjacking scan
- `-cors`: CORS Misconfiguration scan
- `-E, --exceptions`: Exclude specific vulnerabilities from scan (comma-separated, e.g., `-E xss,sqli`)

### SSRF Specific Options
- `-obd, --oob-domain`: Custom OOB (Out-of-Band) domain for SSRF detection
  - Example: `-obd https://your-subdomain.oastify.com`
  - Required for accurate SSRF detection with OOB interaction

### Authentication & Headers
- `-H, --headers`: Custom HTTP headers (format: `'Header1: value1,Header2: value2'`)
- `-C, --cookies`: Session cookies (format: `'name1=value1; name2=value2'`)
- `-A, --auth`: Authorization Bearer token for continuous authentication
- `-ra, --random-agent`: Use random User-Agent for all attack requests

## 🏗️ Architecture

### Core Components
- **`neluxmatizer.py`**: Main entry point, argument parser, and orchestration
- **`scanners/`**: Individual vulnerability scanner modules
  - `scan_lista.py`: Orchestrates all vulnerability scans
  - `vulnerability_manager.py`: Manages vulnerability storage and reporting
- **`parametizer/`**: Parameter and form discovery system
  - `param_discovery.py`: Discovers GET/POST parameters
  - `params.py`, `params_f.py`, `params_p.py`: Parameter testing modules
  - `core/headers.py`: HTTP header parsing
  - `core/save_it.py`: Output saving functionality
- **`core/`**: Core functionality including WAF detection and block handling
  - `waf_detector.py`: WAF detection and fingerprinting
  - `block_handler.py`: Block detection and bypass strategies
  - `waf_config.py`, `block_handler_config.py`: Configuration management
- **`poc_generator.py`**: Proof of Concept generation system with interactive HTML demos

### WAF Detection System
- **`core/waf_detector.py`**: WAF detection and fingerprinting
  - Detects Cloudflare, AWS WAF, Akamai, and other major WAFs
  - Informative mode (doesn't block scanning)
- **`core/block_handler.py`**: Block detection and bypass strategies
  - Monitors for 403/429 responses during attacks
  - Applies exponential backoff and User-Agent rotation
  - Proxy support for bypass attempts

### Scanner Modules
Each scanner is a separate module in the `scanners/` directory:
- `scan_xss.py`: Cross-Site Scripting vulnerability detection
- `scan_sqli.py`: SQL injection testing with multiple techniques
- `scan_lfi.py`: Local file inclusion and path traversal
- `scan_rce.py`: Remote code execution and command injection
- `scan_ssrf.py`: Server-side request forgery with OOB detection and false positive filtering
- `scan_xxe.py`: XML external entity injection
- `scan_ssti.py`: Server-side template injection
- `scan_redirect.py`: Open redirect detection
- `scan_crlf.py`: CRLF injection and HTTP header injection
- `scan_clickjacking.py`: Clickjacking and frame injection detection
- `scan_cors.py`: CORS misconfiguration testing

## 🔒 WAF Bypass System

### Detection Phase
1. **Informative Detection**: Identifies WAF presence without blocking
2. **Fingerprinting**: Determines WAF type and capabilities
3. **Baseline Establishment**: Creates baseline for normal responses

### Attack Phase
1. **Active Monitoring**: Monitors for 403/429 responses during attacks
2. **Automatic Bypass**: Applies bypass strategies when blocks detected
3. **Exponential Backoff**: Increases delays between retries
4. **User-Agent Rotation**: Changes User-Agent to evade detection
5. **Proxy Usage**: Routes requests through configured proxies

### Bypass Strategies
- **Header Manipulation**: Modifies HTTP headers
- **Request Timing**: Adjusts request timing and delays
- **User-Agent Rotation**: Cycles through different User-Agents
- **Proxy Rotation**: Uses multiple proxy servers
- **Request Pattern Variation**: Varies request patterns

## 📊 Output Formats

### Text Output
```
[+] Target: https://example.com
[+] XSS Vulnerability Found
    Parameter: search
    Payload: <script>alert('XSS')</script>
    URL: https://example.com/search?q=<script>alert('XSS')</script>
```

### JSON Output
```json
{
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "XSS",
      "parameter": "search",
      "payload": "<script>alert('XSS')</script>",
      "url": "https://example.com/search?q=<script>alert('XSS')</script>"
    }
  ]
}
```

### PoC Files
- **HTML Files**: Interactive proof of concept pages with:
  - **XSS PoCs**: Executable payloads with copy-to-clipboard functionality
  - **Clickjacking PoCs**: Interactive iframe demonstrations with navigable vulnerable sites
  - **SSRF PoCs**: OOB interaction evidence and request details
  - **Other Vulnerability PoCs**: Context-specific demonstrations
- **Screenshots**: Visual evidence of successful exploits (when available)
- **Detailed Reports**: Comprehensive vulnerability reports with timestamps

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before scanning any target. The authors are not responsible for any misuse of this tool.

### Ethical Usage
- Only scan targets you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Do not use for malicious purposes
- Follow responsible disclosure practices

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd neluxmatizer

# Install development dependencies
pip3 install -r requirements.txt

# Run tests
python3 -m pytest tests/
```

## 📁 Project Structure

```
neluxmatizer/
├── neluxmatizer.py          # Main entry point
├── poc_generator.py          # PoC HTML generation
├── install.sh                # Automated installation script
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── scanners/                 # Vulnerability scanner modules
│   ├── scan_lista.py        # Scan orchestrator
│   ├── scan_xss.py          # XSS scanner
│   ├── scan_sqli.py         # SQLi scanner
│   ├── scan_ssrf.py         # SSRF scanner
│   └── ...                  # Other scanners
├── parametizer/              # Parameter discovery
│   ├── param_discovery.py   # Parameter discovery
│   └── core/                # Core utilities
├── core/                     # WAF detection and handling
│   ├── waf_detector.py      # WAF detection
│   └── block_handler.py     # Block handling
├── output/                   # Generated output
│   ├── poc/                 # PoC HTML files
│   └── *.txt                # Scan results
└── reports/                  # Detailed reports
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: `FileNotFoundError` when using `-l` or `-w` flags
- **Solution**: Use absolute paths or paths relative to current directory. The `~` home directory expansion is supported.

**Issue**: SSRF false positives
- **Solution**: Use `-obd` flag with a custom OOB domain. The tool now includes false positive filtering.

**Issue**: PoC files not generating
- **Solution**: Ensure you use the `-poc` flag. Check that `output/poc/` directory exists and is writable.

**Issue**: Import errors
- **Solution**: Ensure all dependencies are installed: `pip3 install -r requirements.txt`

**Issue**: Permission denied on `install.sh`
- **Solution**: Make it executable: `chmod +x install.sh`

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with Python 3
- Uses BeautifulSoup for HTML parsing
- Colorama for terminal coloring
- Requests for HTTP operations
- Selenium for screenshot capture
- Community contributors and security researchers

## 📞 Support

- **GitHub**: [Repository URL]
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Version**: Check current version with `python3 neluxmatizer.py -v`

---

**🔍 Neluxmatizer** - Advanced web vulnerability scanning with intelligent WAF bypass capabilities.

**Version**: 1.0 | **Author**: Marcos Suarez | **For**: Pentesters
