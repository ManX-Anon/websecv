"""
Security headers check
"""

from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import PassiveCheck


class SecurityHeadersCheck(PassiveCheck):
    """Check for missing security headers"""
    
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': Severity.HIGH,
            'description': 'HSTS header prevents protocol downgrade attacks',
        },
    }
    
    RECOMMENDED_HEADERS = {
        'Content-Security-Policy': {
            'severity': Severity.MEDIUM,
            'description': 'CSP helps prevent XSS attacks',
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': 'Prevents clickjacking attacks',
        },
        'X-Content-Type-Options': {
            'severity': Severity.LOW,
            'description': 'Prevents MIME type sniffing',
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'Enables XSS filter in older browsers',
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Controls referrer information sent',
        },
    }
    
    def get_name(self) -> str:
        return "Security Headers Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for missing security headers"""
        from urllib.parse import urlparse
        
        parsed = urlparse(request.url)
        if parsed.scheme != 'https':
            # Skip HSTS for non-HTTPS
            required = {k: v for k, v in self.REQUIRED_HEADERS.items() 
                       if k != 'Strict-Transport-Security'}
        else:
            required = self.REQUIRED_HEADERS
        
        headers = response.headers
        missing = []
        
        # Check required headers
        for header, info in required.items():
            if header not in headers:
                missing.append((header, info, True))
        
        # Check recommended headers
        for header, info in self.RECOMMENDED_HEADERS.items():
            if header not in headers:
                missing.append((header, info, False))
        
        if missing:
            required_missing = [m for m in missing if m[2]]
            recommended_missing = [m for m in missing if not m[2]]
            
            if required_missing:
                # Return highest severity from required headers
                header, info, _ = max(required_missing, key=lambda x: x[1]['severity'].value)
                return Vulnerability(
                    title=f"Missing Security Header: {header}",
                    description=f"Response is missing the {header} header. {info['description']}",
                    severity=info['severity'],
                    confidence=1.0,
                    request=request,
                    response=response,
                    evidence=f"Missing header: {header}",
                    remediation=f"Add {header} header to all responses.",
                    cwe_id=693,
                    cvss_score=5.3 if info['severity'] == Severity.HIGH else 3.1
                )
            elif recommended_missing:
                # Return highest severity from recommended headers
                header, info, _ = max(recommended_missing, key=lambda x: x[1]['severity'].value)
                return Vulnerability(
                    title=f"Missing Recommended Security Header: {header}",
                    description=f"Response is missing the recommended {header} header. {info['description']}",
                    severity=info['severity'],
                    confidence=0.8,
                    request=request,
                    response=response,
                    evidence=f"Missing recommended header: {header}",
                    remediation=f"Consider adding {header} header to improve security.",
                    cwe_id=693,
                    cvss_score=3.1 if info['severity'] == Severity.MEDIUM else 2.5
                )
        
        return None

