"""
Core interfaces for scanner components
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HttpRequest:
    """HTTP request representation"""
    method: HttpMethod
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    timestamp: Optional[float] = None
    
    def to_raw(self) -> bytes:
        """Convert to raw HTTP request bytes"""
        lines = [f"{self.method.value} {self.url} HTTP/1.1"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if self.body:
            lines.append(self.body.decode('utf-8', errors='ignore'))
        return "\r\n".join(lines).encode()
    
    @classmethod
    def from_raw(cls, raw: bytes) -> 'HttpRequest':
        """Parse raw HTTP request"""
        # Simplified parser - in production use proper HTTP parser
        parts = raw.split(b"\r\n\r\n", 1)
        headers_raw = parts[0].decode('utf-8', errors='ignore')
        body = parts[1] if len(parts) > 1 else None
        
        lines = headers_raw.split("\r\n")
        request_line = lines[0]
        method, url, version = request_line.split(" ", 2)
        
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        
        return cls(
            method=HttpMethod(method),
            url=url,
            headers=headers,
            body=body
        )


@dataclass
class HttpResponse:
    """HTTP response representation"""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    timestamp: Optional[float] = None
    
    def to_raw(self) -> bytes:
        """Convert to raw HTTP response bytes"""
        lines = [f"HTTP/1.1 {self.status_code}"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append(self.body.decode('utf-8', errors='ignore'))
        return "\r\n".join(lines).encode()
    
    @classmethod
    def from_raw(cls, raw: bytes) -> 'HttpResponse':
        """Parse raw HTTP response"""
        parts = raw.split(b"\r\n\r\n", 1)
        headers_raw = parts[0].decode('utf-8', errors='ignore')
        body = parts[1] if len(parts) > 1 else b""
        
        lines = headers_raw.split("\r\n")
        status_line = lines[0]
        version, status_code, reason = status_line.split(" ", 2)
        
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        
        return cls(
            status_code=int(status_code),
            headers=headers,
            body=body
        )


@dataclass
class Vulnerability:
    """Vulnerability finding"""
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    request: HttpRequest
    response: HttpResponse
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[int] = None
    cvss_score: Optional[float] = None


class IProxy(ABC):
    """Proxy interface"""
    
    @abstractmethod
    def start(self, host: str = "127.0.0.1", port: int = 8080):
        """Start the proxy server"""
        pass
    
    @abstractmethod
    def stop(self):
        """Stop the proxy server"""
        pass
    
    @abstractmethod
    def get_history(self) -> List[tuple[HttpRequest, HttpResponse]]:
        """Get request/response history"""
        pass
    
    @abstractmethod
    def set_intercept(self, enabled: bool):
        """Enable/disable request interception"""
        pass


class ICrawler(ABC):
    """Crawler interface"""
    
    @abstractmethod
    def crawl(self, start_url: str, max_depth: int = 10) -> Dict[str, Any]:
        """Crawl starting from start_url"""
        pass
    
    @abstractmethod
    def discover_endpoints(self, url: str) -> List[str]:
        """Discover endpoints from a URL"""
        pass


class IScanner(ABC):
    """Scanner interface"""
    
    @abstractmethod
    def scan(self, target: str) -> List[Vulnerability]:
        """Scan target for vulnerabilities"""
        pass
    
    @abstractmethod
    def register_check(self, check: 'IVulnCheck'):
        """Register a vulnerability check"""
        pass


class IVulnCheck(ABC):
    """Vulnerability check interface"""
    
    @abstractmethod
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for vulnerability"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get check name"""
        pass


class IPlugin(ABC):
    """Plugin interface"""
    
    @abstractmethod
    def get_name(self) -> str:
        """Get plugin name"""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Get plugin version"""
        pass
    
    @abstractmethod
    def initialize(self, context: 'PluginContext'):
        """Initialize plugin with context"""
        pass
    
    @abstractmethod
    def cleanup(self):
        """Cleanup plugin resources"""
        pass


@dataclass
class PluginContext:
    """Context passed to plugins"""
    proxy: Optional[IProxy] = None
    crawler: Optional[ICrawler] = None
    scanner: Optional[IScanner] = None
    storage: Optional['Storage'] = None

