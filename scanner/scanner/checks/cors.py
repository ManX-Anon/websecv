"""
CORS (Cross-Origin Resource Sharing) vulnerability check
"""

from typing import Optional
from urllib.parse import urlparse

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import PassiveCheck


class CORSCheck(PassiveCheck):
    """Check for insecure CORS configuration"""
    
    def get_name(self) -> str:
        return "CORS Security Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check CORS headers for misconfiguration"""
        headers = response.headers
        
        # Check for CORS headers
        acao = headers.get('Access-Control-Allow-Origin', '').strip()
        acac = headers.get('Access-Control-Allow-Credentials', '').strip()
        acam = headers.get('Access-Control-Allow-Methods', '').strip()
        
        if not acao:
            return None  # No CORS headers, not an issue
        
        # Check for wildcard with credentials
        if acao == '*' and acac.lower() == 'true':
            return Vulnerability(
                title="Insecure CORS Configuration: Wildcard with Credentials",
                description="Access-Control-Allow-Origin is set to '*' while "
                           "Access-Control-Allow-Credentials is 'true'. This allows "
                           "any origin to access the resource with credentials.",
                severity=Severity.HIGH,
                confidence=1.0,
                request=request,
                response=response,
                evidence=f"Access-Control-Allow-Origin: {acao}, "
                       f"Access-Control-Allow-Credentials: {acac}",
                remediation="Set Access-Control-Allow-Origin to a specific trusted origin "
                           "instead of '*', or remove Access-Control-Allow-Credentials.",
                cwe_id=942,
                cvss_score=7.5
            )
        
        # Check for null origin
        if acao == 'null':
            return Vulnerability(
                title="Insecure CORS Configuration: Null Origin",
                description="Access-Control-Allow-Origin is set to 'null', which can be "
                           "exploited by sandboxed documents.",
                severity=Severity.MEDIUM,
                confidence=0.8,
                request=request,
                response=response,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Set Access-Control-Allow-Origin to a specific trusted origin.",
                cwe_id=942,
                cvss_score=5.3
            )
        
        # Check for overly permissive methods
        if acam and '*' in acam:
            return Vulnerability(
                title="Insecure CORS Configuration: Wildcard Methods",
                description="Access-Control-Allow-Methods contains wildcard, allowing "
                           "all HTTP methods.",
                severity=Severity.MEDIUM,
                confidence=0.7,
                request=request,
                response=response,
                evidence=f"Access-Control-Allow-Methods: {acam}",
                remediation="Specify only the necessary HTTP methods in "
                           "Access-Control-Allow-Methods.",
                cwe_id=942,
                cvss_score=5.3
            )
        
        # Check if origin is reflected without validation
        origin = request.headers.get('Origin', '')
        if origin and origin == acao:
            # Validate if origin should be trusted
            parsed_origin = urlparse(origin)
            parsed_request = urlparse(request.url)
            
            if parsed_origin.netloc != parsed_request.netloc:
                # Origin is reflected - might be OK if validated, but worth flagging
                return Vulnerability(
                    title="Potentially Insecure CORS: Reflected Origin",
                    description=f"Access-Control-Allow-Origin reflects the request origin '{origin}' "
                               "without apparent validation. Ensure origin is validated against a whitelist.",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    request=request,
                    response=response,
                    evidence=f"Access-Control-Allow-Origin: {acao} (reflected from Origin header)",
                    remediation="Validate the Origin header against a whitelist of trusted origins.",
                    cwe_id=942,
                    cvss_score=5.3
                )
        
        return None

