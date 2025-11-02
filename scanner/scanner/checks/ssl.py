"""
SSL/TLS security check
"""

import ssl
import socket
from typing import Optional
from datetime import datetime

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import PassiveCheck


class SSLCheck(PassiveCheck):
    """Check for SSL/TLS configuration issues"""
    
    def get_name(self) -> str:
        return "SSL/TLS Security Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check SSL/TLS configuration"""
        from urllib.parse import urlparse
        
        parsed = urlparse(request.url)
        if parsed.scheme != 'https':
            return None  # Not HTTPS, skip SSL check
        
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        return Vulnerability(
                            title="SSL Certificate Expiring Soon",
                            description=f"SSL certificate for {hostname} expires in {days_until_expiry} days.",
                            severity=Severity.MEDIUM if days_until_expiry < 7 else Severity.LOW,
                            confidence=1.0,
                            request=request,
                            response=response,
                            evidence=f"Certificate expires on {cert['notAfter']}",
                            remediation="Renew SSL certificate before expiration.",
                            cwe_id=295,
                            cvss_score=3.7 if days_until_expiry < 7 else 2.5
                        )
                    
                    # Check TLS version (would need to check negotiated version)
                    # This is simplified
                    
        except ssl.SSLError as e:
            return Vulnerability(
                title="SSL/TLS Connection Error",
                description=f"Failed to establish SSL connection to {hostname}: {str(e)}",
                severity=Severity.HIGH,
                confidence=0.9,
                request=request,
                response=response,
                evidence=str(e),
                remediation="Review SSL/TLS configuration and ensure valid certificate is installed.",
                cwe_id=319,
                cvss_score=7.5
            )
        except Exception as e:
            # Connection errors, etc.
            pass
        
        return None

