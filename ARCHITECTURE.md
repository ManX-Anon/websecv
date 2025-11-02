# Architecture Documentation

## Overview

This document describes the architecture of the BurpSuite-like Web Application Vulnerability Scanner.

## Core Components

### 1. Proxy Module (`scanner/proxy/`)

**Purpose**: Intercept and log HTTP/HTTPS traffic with TLS support

**Components**:
- `server.py`: Main proxy server implementation
- `handler.py`: Connection handler for individual requests
- `tls.py`: TLS certificate management for MITM interception

**Features**:
- HTTP/HTTPS proxy server
- TLS interception with custom CA certificates
- Request/response logging
- Request filtering and exclusion

**Data Flow**:
```
Client → Proxy Server → Handler → Target Server
                           ↓
                      Log to Storage
```

### 2. Crawler Module (`scanner/crawler/`)

**Purpose**: Discover hidden endpoints and crawl websites

**Components**:
- `spider.py`: Web spider implementation with SPA support
- `discoverer.py`: Endpoint discovery utilities

**Features**:
- Respects robots.txt (configurable)
- Extracts URLs from HTML, JS, CSS, JSON
- Headless browser support (Playwright) for SPA crawling
- JavaScript endpoint discovery
- Parameter discovery from JavaScript

**Data Structures**:
- `visited_urls`: Set of crawled URLs
- `discovered_endpoints`: Set of discovered API endpoints
- Endpoint graph stored in database

### 3. Scanner Engine (`scanner/scanner/`)

**Purpose**: Active and passive vulnerability detection

**Components**:
- `engine.py`: Main scanner engine
- `checks/`: Vulnerability check modules
  - `xss.py`: XSS vulnerability checks
  - `sql_injection.py`: SQL injection checks
  - `cors.py`: CORS misconfiguration checks
  - `ssl.py`: SSL/TLS security checks
  - `headers.py`: Security headers checks

**Features**:
- Modular check system
- Active checks (make additional requests)
- Passive checks (analyze request/response)
- Confidence scoring
- Concurrent check execution

**Check Registration**:
```python
engine = ScanEngine()
engine.register_check(CustomCheck())
```

### 4. Repeater (`scanner/repeater/`)

**Purpose**: Manual HTTP request editing and replay

**Features**:
- Raw request editing
- Form-based editing
- Response comparison
- Request history
- Diff view

### 5. Intruder/Fuzzer (`scanner/intruder/`)

**Purpose**: Parameterized fuzzing engine

**Components**:
- `intruder.py`: Main fuzzing engine
- `payloads.py`: Payload generators
- `strategies.py`: Attack strategies

**Attack Strategies**:
- **Sniper**: One payload per position, sequentially
- **Battering Ram**: Same payload for all positions
- **Pitchfork**: Parallel payload iteration
- **Cluster Bomb**: All combinations of payloads

**Payload Types**:
- XSS payloads
- SQL injection payloads
- Command injection payloads
- Custom wordlists
- Number ranges
- Encoded variants

### 6. Sequencer (`scanner/sequencer/`)

**Purpose**: Statistical analysis of token entropy

**Features**:
- Shannon entropy calculation
- Chi-square randomness test
- Bit distribution analysis
- Predictability scoring

**Statistical Tests**:
- Chi-square test for randomness
- Bit distribution analysis
- Pattern detection (sequential, repeating)

### 7. Collaborator/OAST (`scanner/collaborator/`)

**Purpose**: Out-of-band Application Security Testing

**Components**:
- `service.py`: OAST service implementation
- `server.py`: HTTP/DNS server for interactions

**Features**:
- DNS interaction detection
- HTTP interaction detection
- Payload correlation
- Unique payload generation

### 8. Extender API (`scanner/extender/`)

**Purpose**: Plugin framework for custom checks

**Components**:
- `api.py`: Extender API implementation
- `plugin.py`: Base plugin class
- `loader.py`: Dynamic plugin loader

**Plugin Interface**:
```python
class CustomPlugin(Plugin):
    def get_name(self) -> str:
        return "Custom Check"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def handle_event(self, event: str, data: dict):
        # Custom logic
        pass
```

### 9. Reporting (`scanner/reporting/`)

**Purpose**: Generate vulnerability reports

**Formats**:
- HTML reports
- PDF reports
- JSON reports

**Features**:
- Executive summary
- OWASP Top 10 mapping
- Compliance mapping (PCI-DSS, HIPAA, GDPR)
- CVSSv3.1 scoring
- Technical details with request/response snippets

## Storage Schema

### Database Tables

**requests**:
- id (PRIMARY KEY)
- method, url, headers, body, timestamp
- response_status, response_headers, response_body, response_timestamp

**vulnerabilities**:
- id (PRIMARY KEY)
- title, description, severity, confidence
- request_id (FOREIGN KEY)
- evidence, remediation, cwe_id, cvss_score
- created_at

**endpoints**:
- id (PRIMARY KEY)
- url, method, parameters
- discovered_at

## Configuration

Configuration is managed through `scanner/core/config.py`:

- `ProxyConfig`: Proxy server settings
- `CrawlerConfig`: Crawler behavior
- `ScannerConfig`: Scanner settings
- `IntruderConfig`: Fuzzing configuration

Configuration can be loaded from YAML or JSON files.

## Concurrency Management

- **Proxy**: Multi-threaded connection handling
- **Crawler**: Async/await with Playwright
- **Scanner**: ThreadPoolExecutor for concurrent checks
- **Intruder**: ThreadPoolExecutor with rate limiting

## Security Considerations

1. **TLS Interception**: Requires user to install custom CA certificate
2. **Sandboxing**: Plugins run in sandbox with resource limits
3. **Rate Limiting**: Built-in rate limiting for fuzzing
4. **Safe Testing**: Active checks should be used with caution

## Extension Points

1. **Custom Checks**: Implement `PassiveCheck` or `ActiveCheck`
2. **Plugins**: Extend `Plugin` base class
3. **Payloads**: Add custom payload generators
4. **Strategies**: Implement custom attack strategies
5. **Report Formats**: Add new report generators

## Data Flow

### Scan Workflow

```
1. Crawl target → Discover endpoints
2. Proxy intercepts → Log requests/responses
3. Scanner analyzes → Detect vulnerabilities
4. Generate report → Export findings
```

### Fuzzing Workflow

```
1. Base request → Define positions
2. Generate payloads → Apply strategy
3. Execute requests → Collect responses
4. Analyze results → Identify issues
```

## CI/CD Integration

GitHub Actions workflow included (`.github/workflows/scan.yml`):
- Automated scanning
- JSON report generation
- Artifact upload
- Critical vulnerability detection

## Future Enhancements

- Web UI (Flask/FastAPI)
- Real-time collaboration
- AI-assisted parameter discovery
- Advanced false positive reduction
- Plugin marketplace
- Multi-user support

