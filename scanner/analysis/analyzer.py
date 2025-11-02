"""
Vulnerability analysis and false positive reduction
"""

from typing import List, Dict, Any
from scanner.core.interfaces import Vulnerability


class VulnerabilityAnalyzer:
    """Analyze vulnerabilities for patterns and false positives"""
    
    def analyze(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Analyze vulnerabilities"""
        analysis = {
            'total': len(vulnerabilities),
            'by_severity': {},
            'by_cwe': {},
            'false_positive_candidates': [],
            'high_confidence': [],
            'patterns': {},
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.value
            analysis['by_severity'][severity] = analysis['by_severity'].get(severity, 0) + 1
            
            # Count by CWE
            if vuln.cwe_id:
                cwe_key = f"CWE-{vuln.cwe_id}"
                analysis['by_cwe'][cwe_key] = analysis['by_cwe'].get(cwe_key, 0) + 1
            
            # High confidence vulnerabilities
            if vuln.confidence >= 0.8:
                analysis['high_confidence'].append({
                    'title': vuln.title,
                    'severity': vuln.severity.value,
                    'confidence': vuln.confidence,
                })
            
            # Low confidence may be false positives
            if vuln.confidence < 0.5:
                analysis['false_positive_candidates'].append({
                    'title': vuln.title,
                    'confidence': vuln.confidence,
                })
        
        # Pattern detection
        analysis['patterns'] = self._detect_patterns(vulnerabilities)
        
        return analysis
    
    def _detect_patterns(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Detect patterns in vulnerabilities"""
        patterns = {
            'common_urls': {},
            'common_cwes': {},
            'severity_distribution': {},
        }
        
        # Common vulnerable URLs
        url_counts = {}
        for vuln in vulnerabilities:
            # Extract base URL
            from urllib.parse import urlparse
            parsed = urlparse(vuln.request.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            url_counts[base_url] = url_counts.get(base_url, 0) + 1
        
        patterns['common_urls'] = dict(sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Common CWEs
        cwe_counts = {}
        for vuln in vulnerabilities:
            if vuln.cwe_id:
                cwe_counts[vuln.cwe_id] = cwe_counts.get(vuln.cwe_id, 0) + 1
        
        patterns['common_cwes'] = dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        return patterns

