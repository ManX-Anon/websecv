"""
Insecure Direct Object Reference (IDOR) vulnerability check
"""

import re
from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class IDORCheck(ActiveCheck):
    """Check for IDOR vulnerabilities"""
    
    def get_name(self) -> str:
        return "IDOR Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for IDOR vulnerability"""
        import requests
        
        # Extract ID-like parameters
        params = self._extract_parameters(request)
        
        id_params = {}
        for param, value in params.items():
            if any(keyword in param.lower() for keyword in ['id', 'user', 'account', 'file', 'document', 'resource']):
                if value.isdigit() or self._looks_like_id(value):
                    id_params[param] = value
        
        if not id_params:
            return None
        
        # Try accessing another user's resource
        for param, value in id_params.items():
            try:
                # Try incrementing/decrementing the ID
                if value.isdigit():
                    test_value = str(int(value) + 1)
                else:
                    continue
                
                # Create modified request
                modified_params = params.copy()
                modified_params[param] = test_value
                
                # Test if we can access other resources
                test_response = requests.get(
                    request.url.split('?')[0],
                    params=modified_params,
                    headers=request.headers,
                    timeout=10,
                    allow_redirects=False
                )
                
                # If we get successful response for different ID, it might be IDOR
                if test_response.status_code == 200 and test_response.content != response.body:
                    return Vulnerability(
                        title="Insecure Direct Object Reference (IDOR)",
                        description=f"Parameter '{param}' may allow access to other users' resources by "
                                   "manipulating the identifier. Authorization checks may be missing.",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        request=request,
                        response=response,
                        evidence=f"Different resource accessible with modified {param}",
                        remediation="Implement proper authorization checks. Use indirect object references. "
                                   "Verify user permissions for each resource access.",
                        cwe_id=639,
                        cvss_score=7.5
                    )
            except:
                continue
        
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
    
    def _looks_like_id(self, value: str) -> bool:
        """Check if value looks like an ID"""
        # UUID pattern
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, value, re.IGNORECASE):
            return True
        
        # Hash-like
        if len(value) >= 16 and value.isalnum():
            return True
        
        return False

