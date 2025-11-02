"""
Impact analysis for vulnerabilities
"""

from typing import List, Dict, Any
from scanner.core.interfaces import Vulnerability


class ImpactAnalyzer:
    """Analyze impact of vulnerabilities"""
    
    def analyze_impact(self, vulnerabilities: List[Vulnerability], target: str) -> Dict[str, Any]:
        """Analyze overall impact"""
        impact = {
            'critical_impact': [],
            'data_exposure_risk': False,
            'authentication_compromise': False,
            'availability_impact': False,
            'compliance_issues': [],
        }
        
        for vuln in vulnerabilities:
            # Critical impact
            if vuln.severity.value == 'critical':
                impact['critical_impact'].append({
                    'title': vuln.title,
                    'cwe': vuln.cwe_id,
                })
            
            # Data exposure risk
            if any(keyword in vuln.title.lower() for keyword in ['sql', 'injection', 'path traversal', 'xxe', 'ssrf']):
                impact['data_exposure_risk'] = True
            
            # Authentication compromise
            if any(keyword in vuln.title.lower() for keyword in ['authentication', 'session', 'csrf', 'xss']):
                impact['authentication_compromise'] = True
            
            # Availability impact (DoS)
            if any(keyword in vuln.title.lower() for keyword in ['dos', 'denial', 'resource exhaustion']):
                impact['availability_impact'] = True
            
            # Compliance issues
            if vuln.cwe_id in [89, 79, 798]:  # SQL Injection, XSS, Hardcoded credentials
                if vuln.cwe_id == 89:
                    impact['compliance_issues'].append('PCI-DSS')
                    impact['compliance_issues'].append('HIPAA')
                if vuln.cwe_id == 79:
                    impact['compliance_issues'].append('PCI-DSS')
                if vuln.cwe_id == 798:
                    impact['compliance_issues'].append('PCI-DSS')
                    impact['compliance_issues'].append('HIPAA')
                    impact['compliance_issues'].append('GDPR')
        
        impact['compliance_issues'] = list(set(impact['compliance_issues']))
        
        return impact

