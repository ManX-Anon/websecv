"""
SQL Injection vulnerability check
"""

import re
from typing import Optional

from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity
from .base import ActiveCheck


class SQLInjectionCheck(ActiveCheck):
    """Check for SQL injection vulnerabilities"""
    
    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' OR '1'='1",
        "admin'--",
        "admin'/*",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]
    
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*\Wmysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid pg_result",
        r"Npgsql\.",
        r"SQLite.*error",
        r"SQLite3::",
        r"Warning.*\Wsqlite_",
        r"Warning.*\WSQLite3",
        r"Microsoft Access Driver",
        r"Microsoft Access.*error",
        r"ODBC.*error",
        r"SQLServerException",
        r"ODBC SQL Server Driver",
    ]
    
    def get_name(self) -> str:
        return "SQL Injection Check"
    
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check for SQL injection vulnerability"""
        body_str = response.body.decode('utf-8', errors='ignore')
        status_code = response.status_code
        
        # Check for SQL error messages
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_str, re.IGNORECASE):
                return Vulnerability(
                    title="SQL Injection Vulnerability",
                    description="SQL error messages are exposed in responses, indicating potential SQL injection vulnerability.",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    request=request,
                    response=response,
                    evidence=f"SQL error pattern detected: {pattern}",
                    remediation="Use parameterized queries/prepared statements. Validate and sanitize all user input. "
                               "Implement least privilege database access. Avoid exposing database errors to users.",
                    cwe_id=89,
                    cvss_score=9.8
                )
        
        # Check for time-based SQL injection patterns
        # (would require timing analysis in production)
        
        # Check for boolean-based SQL injection
        params = self._extract_parameters(request)
        for param, value in params.items():
            # Test with SQL injection payloads
            if any(payload in value for payload in ["' OR ", "' AND ", "'; --"]):
                # Check response differences
                if status_code == 200 and len(body_str) > 0:
                    return Vulnerability(
                        title="Potential SQL Injection Vulnerability",
                        description=f"Parameter '{param}' contains SQL injection patterns. "
                                   "Manual verification recommended.",
                        severity=Severity.HIGH,
                        confidence=0.6,
                        request=request,
                        response=response,
                        evidence=f"SQL injection pattern detected in parameter: {param}",
                        remediation="Use parameterized queries/prepared statements. Validate input.",
                        cwe_id=89,
                        cvss_score=7.5
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

