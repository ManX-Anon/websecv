"""
SARIF (Static Analysis Results Interchange Format) report generator
"""

from typing import List, Dict, Any
from datetime import datetime
from scanner.core.interfaces import Vulnerability


class SARIFGenerator:
    """Generate SARIF format reports"""
    
    def generate(self, vulnerabilities: List[Vulnerability], target: str) -> Dict[str, Any]:
        """Generate SARIF report"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "WebSecV",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ManX-Anon/websecv"
                    }
                },
                "results": []
            }]
        }
        
        for vuln in vulnerabilities:
            result = {
                "ruleId": f"CWE-{vuln.cwe_id}" if vuln.cwe_id else "vulnerability",
                "message": {
                    "text": vuln.title
                },
                "level": self._severity_to_level(vuln.severity.value),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.request.url
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }],
                "properties": {
                    "cwe": vuln.cwe_id,
                    "cvss": vuln.cvss_score,
                    "confidence": vuln.confidence
                }
            }
            
            sarif["runs"][0]["results"].append(result)
        
        return sarif
    
    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note',
        }
        return mapping.get(severity, 'note')

