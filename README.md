# BurpSuite-like Web Application Vulnerability Scanner

A comprehensive web application security testing toolkit inspired by BurpSuite, built in Python.

## Features

- **Proxy**: HTTP/HTTPS traffic interception with TLS support
- **Crawler**: Intelligent web crawling with SPA support (Playwright)
- **Scanner**: Active and passive vulnerability checks
  - XSS detection
  - SQL injection detection
  - CORS misconfiguration checks
  - SSL/TLS security analysis
  - Security headers checks
- **Repeater**: Manual HTTP request editing and replay
- **Intruder**: Parameterized fuzzing engine with multiple attack strategies
- **Sequencer**: Statistical analysis of token entropy
- **Collaborator**: Out-of-band interaction testing (OAST)
- **Extender API**: Plugin framework for custom checks
- **Reporting**: Comprehensive vulnerability reports (HTML, PDF, JSON)
- **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins support

## Architecture

```
scanner/
├── core/              # Core architecture and interfaces
├── proxy/             # HTTP/HTTPS proxy server
├── crawler/           # Web crawler and spider
├── scanner/           # Vulnerability scanner engine
├── repeater/          # Request repeater tool
├── intruder/          # Fuzzing engine
├── sequencer/         # Token entropy analyzer
├── collaborator/      # OAST service
├── extender/          # Plugin API and framework
├── reporting/         # Report generation
└── utils/             # Utility functions
```

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (for crawler)
playwright install chromium

# Optional: Install PDF generation support (requires C++ build tools on Windows)
# pip install -r requirements-optional.txt
```

## Usage

### Command-Line Interface

```bash
# Start proxy server
python -m scanner.cli proxy --host 127.0.0.1 --port 8080

# Crawl a website
python -m scanner.cli crawl https://example.com --max-depth 10

# Scan for vulnerabilities
python -m scanner.cli scan https://example.com --format html --output report.html

# Generate report from stored findings
python -m scanner.cli report --format pdf --output report.pdf
```

### Python API

```python
from scanner.proxy.server import ProxyServer
from scanner.crawler.spider import WebSpider
from scanner.scanner.engine import ScanEngine
from scanner.reporting.generator import ReportGenerator

# Start proxy
server = ProxyServer(host='127.0.0.1', port=8080)
server.start()

# Crawl a website
spider = WebSpider()
results = spider.crawl('https://example.com')

# Scan for vulnerabilities
engine = ScanEngine()
vulnerabilities = engine.scan('https://example.com')

# Generate report
generator = ReportGenerator()
report_path = generator.generate(
    vulnerabilities,
    Path('report.html'),
    format='html',
    target='https://example.com'
)
```

### Using the Intruder/Fuzzer

```python
from scanner.intruder.intruder import Intruder
from scanner.intruder.strategies import ClusterBombStrategy
from scanner.core.interfaces import HttpRequest, HttpMethod

intruder = Intruder()

# Create base request
request = HttpRequest(
    method=HttpMethod.GET,
    url='https://example.com/api/search?id=1&query=test',
    headers={'User-Agent': 'Scanner/1.0'}
)

# Define fuzzing positions
positions = {
    'id': ['1', '2', '3', "' OR '1'='1"],
    'query': ['test', '<script>alert(1)</script>', "' OR '1'='1"]
}

# Execute fuzzing attack
results = intruder.fuzz(request, positions, strategy=ClusterBombStrategy())
```

### Using the Repeater

```python
from scanner.repeater.repeater import Repeater
from scanner.core.interfaces import HttpRequest, HttpMethod

repeater = Repeater()

# Create request
request = HttpRequest(
    method=HttpMethod.POST,
    url='https://example.com/api/login',
    headers={'Content-Type': 'application/json'},
    body=b'{"username": "admin", "password": "test"}'
)

# Send request
response = repeater.send_request(request)

# Edit and resend
modified = repeater.edit_request(request, set_headers={'X-Custom-Header': 'value'})
new_response = repeater.send_request(modified)

# Compare responses
diff = repeater.compare_responses(response, new_response)
```

### Using the Sequencer

```python
from scanner.sequencer.sequencer import Sequencer

sequencer = Sequencer()

# Add tokens for analysis
tokens = ['session1', 'session2', 'session3', ...]
sequencer.add_tokens(tokens)

# Analyze
results = sequencer.analyze()
print(f"Entropy: {results['entropy']}")
print(f"Predictability Score: {results['predictability_score']}")
print(f"Recommendations: {results['recommendations']}")
```

### Using the Collaborator/OAST

```python
from scanner.collaborator.service import CollaboratorService

collaborator = CollaboratorService(domain='collaborator.example.com')

# Generate payload
payload = collaborator.generate_payload(payload_type='dns')
# Use payload in injection: payload
# Wait...
# Check for interactions
interactions = collaborator.check_interactions(payload_id)
```

## Plugin Development

### Creating a Custom Plugin

```python
from scanner.extender.plugin import Plugin, PluginContext
from scanner.core.interfaces import Vulnerability, Severity

class MyCustomPlugin(Plugin):
    def get_name(self) -> str:
        return "Custom Security Check"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def handle_event(self, event: str, data: dict):
        if event == 'response_received':
            request = data.get('request')
            response = data.get('response')
            
            # Your custom check logic
            if self._check_custom_issue(request, response):
                return Vulnerability(
                    title="Custom Vulnerability",
                    description="Description of the issue",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    request=request,
                    response=response
                )
        
        return None
    
    def _check_custom_issue(self, request, response):
        # Custom detection logic
        return False
```

See `examples/example_plugin.py` for a complete example.

## Configuration

Create a `config.yaml` file:

```yaml
proxy:
  host: "127.0.0.1"
  port: 8080
  tls_intercept: true
  exclude_domains: []

crawler:
  respect_robots_txt: true
  max_depth: 10
  max_pages: 1000
  follow_external_links: false
  use_headless_browser: true

scanner:
  active_checks: true
  passive_checks: true
  max_concurrent_checks: 10

intruder:
  max_threads: 10
  rate_limit: 0.1

storage_path: "scans"
log_level: "INFO"
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run security scan
  run: |
    python -m scanner.cli scan https://example.com --format json --output results.json
```

See `.github/workflows/scan.yml` for a complete example.

## Reporting

Reports include:
- Executive summary with severity breakdown
- Detailed vulnerability descriptions
- Request/response snippets
- CVSS scoring
- CWE mapping
- OWASP Top 10 mapping
- Compliance mapping (PCI-DSS, HIPAA, GDPR)
- Remediation recommendations

## Security Considerations

⚠️ **Important**: This tool is for authorized security testing only. Always obtain proper authorization before scanning any target.

- Use TLS interception certificates only for testing environments
- Active checks may impact target systems
- Fuzzing should be used with rate limiting
- Review and validate all findings before reporting

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## License

MIT License

