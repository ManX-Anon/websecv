"""
Open Redirect vulnerability check
"""

from typing import Optional
from urllib.parse import urlparse

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import PassiveCheck


class OpenRedirectCheck(PassiveCheck):
    """Check for open redirect vulnerabilities"""
    
    TEST_DOMAINS = [
        'http://evil.com',
        'https://attacker.com',
        '//evil.com',
    ]
    
    def get_name(self) -> str:
        return "Open Redirect Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for open redirect vulnerability"""
        params = self._extract_parameters(request)
        response_headers = response.headers
        
        # Check redirect headers
        location = response_headers.get('Location', '')
        
        if location:
            parsed_location = urlparse(location)
            parsed_request = urlparse(request.url)
            
            # Check if redirect is to external domain
            if parsed_location.netloc and parsed_location.netloc != parsed_request.netloc:
                # Check if it's a user-controlled redirect
                for param, value in params.items():
                    if any(keyword in param.lower() for keyword in ['redirect', 'url', 'link', 'next', 'return', 'goto']):
                        if value in location or location.startswith(value):
                            return Vulnerability(
                                title="Open Redirect Vulnerability",
                                description=f"Parameter '{param}' allows redirecting to external domains. "
                                           "This can be used for phishing attacks.",
                                severity=Severity.MEDIUM,
                                confidence=0.8,
                                request=request,
                                response=response,
                                evidence=f"Redirect to external domain: {location}",
                                remediation="Validate redirect URLs. Whitelist allowed domains. "
                                           "Use relative URLs or validate domain matches.",
                                cwe_id=601,
                                cvss_score=6.1
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
        
        return params

