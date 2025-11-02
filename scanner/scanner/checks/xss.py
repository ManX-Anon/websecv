"""
XSS (Cross-Site Scripting) vulnerability check
"""

import re
from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class XSSCheck(ActiveCheck):
    """Check for XSS vulnerabilities"""
    
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
    ]
    
    def get_name(self) -> str:
        return "XSS Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for XSS vulnerability"""
        # Check if response reflects user input
        body_str = response.body.decode('utf-8', errors='ignore')
        
        # Check parameters in request
        for param, value in self._extract_parameters(request).items():
            # Test with XSS payload
            for payload in self.PAYLOADS:
                if payload in body_str:
                    # Check if payload is reflected without encoding
                    if self._is_reflected(body_str, payload):
                        return Vulnerability(
                            title="Cross-Site Scripting (XSS) Vulnerability",
                            description=f"User input is reflected in response without proper encoding. "
                                       f"Parameter '{param}' is vulnerable to XSS injection.",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            request=request,
                            response=response,
                            evidence=f"Payload '{payload}' was reflected in response",
                            remediation="Sanitize and encode all user input before rendering in HTML. "
                                       "Use Content Security Policy (CSP) headers.",
                            cwe_id=79,
                            cvss_score=7.3
                        )
        
        return None
    
    def _extract_parameters(self, request: HttpRequest) -> dict:
        """Extract parameters from request"""
        params = {}
        
        # Extract from URL query string
        if '?' in request.url:
            query = request.url.split('?', 1)[1]
            for pair in query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        
        # Extract from POST body
        if request.body:
            body_str = request.body.decode('utf-8', errors='ignore')
            if 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
                for pair in body_str.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        params[key] = value
        
        return params
    
    def _is_reflected(self, body: str, payload: str) -> bool:
        """Check if payload is reflected in response body"""
        # Simple check - payload appears in body
        # In production, would check for encoding/escaping
        return payload in body

