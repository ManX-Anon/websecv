"""
Path Traversal vulnerability check
"""

import re
from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class PathTraversalCheck(ActiveCheck):
    """Check for path traversal vulnerabilities"""
    
    PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '/etc/passwd',
        'C:\\windows\\win.ini',
    ]
    
    FILE_INDICATORS = {
        'unix': ['root:x:', '/bin/', '/usr/bin/'],
        'windows': ['[fonts]', '[extensions]', 'C:\\windows'],
    }
    
    def get_name(self) -> str:
        return "Path Traversal Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for path traversal vulnerability"""
        params = self._extract_parameters(request)
        response_body = response.body.decode('utf-8', errors='ignore').lower()
        
        for param, value in params.items():
            if any(keyword in param.lower() for keyword in ['file', 'path', 'dir', 'document', 'page']):
                # Check if file system indicators are present
                for os_type, indicators in self.FILE_INDICATORS.items():
                    for indicator in indicators:
                        if indicator.lower() in response_body:
                            return Vulnerability(
                                title="Path Traversal Vulnerability",
                                description=f"Parameter '{param}' appears vulnerable to path traversal attacks. "
                                           "The application may allow access to arbitrary files on the server.",
                                severity=Severity.HIGH,
                                confidence=0.8,
                                request=request,
                                response=response,
                                evidence=f"File system indicator detected: {indicator}",
                                remediation="Validate and sanitize file paths. Use basename() or equivalent. "
                                           "Whitelist allowed directories. Implement proper access controls.",
                                cwe_id=22,
                                cvss_score=8.5
                            )
        
        return None
    
    def _extract_parameters(self, request: HttpRequest) -> dict:
        """Extract parameters from request"""
        params = {}
        from urllib.parse import parse_qs
        
        if '?' in request.url:
            query = request.url.split('?', 1)[1]
            parsed = parse_qs(query)
            params.update({k: v[0] if isinstance(v, list) and len(v) > 0 else v 
                          for k, v in parsed.items()})
        
        if request.body:
            body_str = request.body.decode('utf-8', errors='ignore')
            if 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
                parsed = parse_qs(body_str)
                params.update({k: v[0] if isinstance(v, list) and len(v) > 0 else v 
                              for k, v in parsed.items()})
        
        return params

