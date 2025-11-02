"""
Vulnerability chaining analysis
"""

from typing import List, Dict, Any
from scanner.core.interfaces import Vulnerability


class VulnerabilityChainer:
    """Analyze vulnerability chains and attack paths"""
    
    def analyze_chains(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """Analyze potential vulnerability chains"""
        chains = []
        
        # Group by URL
        by_url = {}
        for vuln in vulnerabilities:
            url = vuln.request.url
            if url not in by_url:
                by_url[url] = []
            by_url[url].append(vuln)
        
        # Look for chains
        # Example: XSS + CSRF can lead to account takeover
        xss_vulns = [v for v in vulnerabilities if v.cwe_id == 79]  # XSS
        csrf_vulns = [v for v in vulnerabilities if v.cwe_id == 352]  # CSRF
        auth_bypass = [v for v in vulnerabilities if 'authentication' in v.title.lower() or 'authorization' in v.title.lower()]
        
        if xss_vulns and csrf_vulns:
            chains.append({
                'title': 'XSS + CSRF Chain',
                'description': 'Cross-site scripting combined with CSRF could lead to unauthorized actions',
                'severity': 'high',
                'vulnerabilities': len(xss_vulns) + len(csrf_vulns),
            })
        
        if auth_bypass and xss_vulns:
            chains.append({
                'title': 'Authentication Bypass + XSS Chain',
                'description': 'Authentication issues combined with XSS could lead to account compromise',
                'severity': 'critical',
                'vulnerabilities': len(auth_bypass) + len(xss_vulns),
            })
        
        return chains

