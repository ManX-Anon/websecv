"""
Command Injection vulnerability check
"""

import re
from typing import Optional
import time

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class CommandInjectionCheck(ActiveCheck):
    """Check for command injection vulnerabilities"""
    
    PAYLOADS = [
        '; ls',
        '| whoami',
        '& dir',
        '`id`',
        '$(whoami)',
        '; cat /etc/passwd',
        '| type C:\\windows\\win.ini',
    ]
    
    TIME_BASED_PAYLOADS = [
        '; sleep 5',
        '| ping -c 5 127.0.0.1',
    ]
    
    COMMAND_OUTPUT_INDICATORS = [
        'uid=', 'gid=', 'groups=',
        'total ', 'Directory of',
        'Volume Serial Number',
        'Microsoft Windows',
    ]
    
    def get_name(self) -> str:
        return "Command Injection Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for command injection vulnerability"""
        params = self._extract_parameters(request)
        response_body = response.body.decode('utf-8', errors='ignore').lower()
        
        for param, value in params.items():
            # Check if command output indicators are present
            for indicator in self.COMMAND_OUTPUT_INDICATORS:
                if indicator.lower() in response_body:
                    return Vulnerability(
                        title="Command Injection Vulnerability",
                        description=f"Parameter '{param}' appears vulnerable to command injection attacks. "
                                   "The application may be executing user-controlled commands.",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        request=request,
                        response=response,
                        evidence=f"Command output indicator detected: {indicator}",
                        remediation="Validate and sanitize all input. Use parameterized commands. "
                                   "Avoid shell execution. Use safe APIs that don't invoke shell.",
                        cwe_id=78,
                        cvss_score=9.8
                    )
            
            # Check for error messages that might indicate command execution
            error_patterns = [
                r'sh:\s+\w+:.*not found',
                r'/bin/sh:.*:.*not found',
                r'command not found',
                r'cmd\.exe',
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return Vulnerability(
                        title="Potential Command Injection",
                        description=f"Parameter '{param}' may be vulnerable to command injection. "
                                   "Command execution errors detected.",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        request=request,
                        response=response,
                        evidence=f"Command execution error pattern detected",
                        remediation="Validate and sanitize all input. Avoid shell execution.",
                        cwe_id=78,
                        cvss_score=8.1
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

