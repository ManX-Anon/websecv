"""
XML External Entity (XXE) vulnerability check
"""

import re
from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class XXECheck(ActiveCheck):
    """Check for XXE vulnerabilities"""
    
    XXE_PAYLOADS = [
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
    ]
    
    def get_name(self) -> str:
        return "XXE Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for XXE vulnerability"""
        # Check if request contains XML
        content_type = request.headers.get('Content-Type', '')
        body = request.body.decode('utf-8', errors='ignore') if request.body else ''
        
        if 'xml' not in content_type.lower() and not body.strip().startswith('<?xml'):
            return None
        
        # Check if XXE patterns are reflected
        response_body = response.body.decode('utf-8', errors='ignore')
        
        # Look for file system indicators
        file_indicators = [
            '/etc/passwd',
            '/etc/shadow',
            'root:x:',
            'windows',
            '[fonts]',
            '[extensions]',
        ]
        
        for indicator in file_indicators:
            if indicator.lower() in response_body.lower():
                return Vulnerability(
                    title="XML External Entity (XXE) Injection",
                    description="The application is vulnerable to XXE attacks. XML entities can be used to "
                               "read local files or access internal services.",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    request=request,
                    response=response,
                    evidence=f"File system indicator detected: {indicator}",
                    remediation="Disable XML external entity processing. Use safe XML parsers. "
                               "Whitelist allowed XML structures. Use JSON instead of XML when possible.",
                    cwe_id=611,
                    cvss_score=9.1
                )
        
        # Check for error messages that might indicate XXE
        if 'xml' in response_body.lower() and any(word in response_body.lower() 
            for word in ['entity', 'external', 'failed to load', 'parse error']):
            return Vulnerability(
                title="Potential XXE Vulnerability",
                description="XML parsing errors may indicate XXE vulnerability. Manual verification recommended.",
                severity=Severity.HIGH,
                confidence=0.6,
                request=request,
                response=response,
                evidence="XML parsing errors detected",
                remediation="Disable XML external entity processing. Use safe XML parsers.",
                cwe_id=611,
                cvss_score=7.5
            )
        
        return None

