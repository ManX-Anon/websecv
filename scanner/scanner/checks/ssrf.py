"""
Server-Side Request Forgery (SSRF) vulnerability check
"""

import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class SSRFCheck(ActiveCheck):
    """Check for SSRF vulnerabilities"""
    
    INTERNAL_IPS = [
        '127.0.0.1', 'localhost', '0.0.0.0',
        '169.254.169.254',  # AWS metadata
        '192.168.0.0/16',
        '10.0.0.0/8',
        '172.16.0.0/12',
    ]
    
    METADATA_ENDPOINTS = [
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
    ]
    
    def get_name(self) -> str:
        return "SSRF Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for SSRF vulnerability"""
        import requests
        
        # Check if request has URL parameter
        params = self._extract_parameters(request)
        
        for param, value in params.items():
            if any(keyword in param.lower() for keyword in ['url', 'link', 'uri', 'endpoint', 'api']):
                # Test with internal IP
                test_url = 'http://127.0.0.1:80/'
                try:
                    # Replace parameter value
                    modified_params = params.copy()
                    modified_params[param] = test_url
                    
                    # Make request with SSRF payload
                    test_response = requests.get(
                        request.url,
                        params=modified_params,
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    # Check if internal content is reflected
                    if self._detect_internal_access(test_response):
                        return Vulnerability(
                            title="Server-Side Request Forgery (SSRF)",
                            description=f"Parameter '{param}' appears vulnerable to SSRF attacks. "
                                       "The application may be making server-side requests to user-controlled URLs.",
                            severity=Severity.HIGH,
                            confidence=0.7,
                            request=request,
                            response=response,
                            evidence=f"Parameter '{param}' accepts URLs and may allow internal network access",
                            remediation="Validate and whitelist allowed URLs. Block internal IPs and metadata endpoints. "
                                       "Use URL validation libraries. Implement request timeout limits.",
                            cwe_id=918,
                            cvss_score=8.2
                        )
                except:
                    pass
        
        return None
    
    def _extract_parameters(self, request: HttpRequest) -> dict:
        """Extract parameters from request"""
        params = {}
        from urllib.parse import parse_qs
        
        if '?' in request.url:
            query = request.url.split('?', 1)[1]
            params.update(parse_qs(query))
            # Flatten list values
            params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v 
                     for k, v in params.items()}
        
        return params
    
    def _detect_internal_access(self, response) -> bool:
        """Detect if response indicates internal network access"""
        body = response.text.lower() if hasattr(response, 'text') else ''
        
        # Check for internal IP indicators
        indicators = [
            '127.0.0.1',
            'localhost',
            'private ip',
            'metadata',
            'cloud provider',
        ]
        
        return any(indicator in body for indicator in indicators)

