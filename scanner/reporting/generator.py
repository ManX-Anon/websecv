"""
Report generator
"""

import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

from scanner.core.interfaces import Vulnerability, Severity
from .formats import HTMLReportGenerator, PDFReportGenerator, JSONReportGenerator
from .csv import CSVReportGenerator
from .xml import XMLReportGenerator
from .sarif import SARIFGenerator

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate vulnerability reports"""
    
    def __init__(self):
        self.generators = {
            'html': HTMLReportGenerator(),
            'pdf': PDFReportGenerator(),
            'json': JSONReportGenerator(),
            'csv': CSVReportGenerator(),
            'xml': XMLReportGenerator(),
            'sarif': SARIFGenerator(),
        }
    
    def generate(
        self,
        vulnerabilities: List[Vulnerability],
        output_path: Path,
        format: str = 'html',
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generate a report"""
        if format not in self.generators:
            raise ValueError(f"Unsupported format: {format}")
        
        generator = self.generators[format]
        
        # Special handling for SARIF
        if format == 'sarif':
            sarif_data = generator.generate(vulnerabilities, target)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_data, f, indent=2)
            return output_path
        else:
            return generator.generate(vulnerabilities, output_path, target, metadata)
    
    def generate_executive_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate executive summary"""
        summary = {
            'total_findings': len(vulnerabilities),
            'by_severity': {},
            'by_cwe': {},
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            if vuln.cwe_id:
                summary['by_cwe'][vuln.cwe_id] = summary['by_cwe'].get(vuln.cwe_id, 0) + 1
            
            if vuln.severity == Severity.CRITICAL:
                summary['critical_count'] += 1
            elif vuln.severity == Severity.HIGH:
                summary['high_count'] += 1
            elif vuln.severity == Severity.MEDIUM:
                summary['medium_count'] += 1
            elif vuln.severity == Severity.LOW:
                summary['low_count'] += 1
            else:
                summary['info_count'] += 1
        
        return summary
    
    def map_to_owasp_top10(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Map vulnerabilities to OWASP Top 10"""
        mapping = {
            'A01:2021-Broken Access Control': [],
            'A02:2021-Cryptographic Failures': [],
            'A03:2021-Injection': [],
            'A04:2021-Insecure Design': [],
            'A05:2021-Security Misconfiguration': [],
            'A06:2021-Vulnerable Components': [],
            'A07:2021-Authentication Failures': [],
            'A08:2021-Software and Data Integrity': [],
            'A09:2021-Security Logging Failures': [],
            'A10:2021-Server-Side Request Forgery': [],
        }
        
        # Map based on CWE ID
        cwe_to_owasp = {
            79: 'A03:2021-Injection',  # XSS
            89: 'A03:2021-Injection',   # SQL Injection
            352: 'A01:2021-Broken Access Control',  # CSRF
            287: 'A01:2021-Broken Access Control',  # Authentication Bypass
            798: 'A02:2021-Cryptographic Failures',  # Hardcoded Credentials
            434: 'A03:2021-Injection',  # Unrestricted Upload
            502: 'A06:2021-Vulnerable Components',  # Deserialization
            863: 'A01:2021-Broken Access Control',  # Incorrect Authorization
        }
        
        for vuln in vulnerabilities:
            if vuln.cwe_id and vuln.cwe_id in cwe_to_owasp:
                category = cwe_to_owasp[vuln.cwe_id]
                mapping[category].append(vuln)
            else:
                # Default to most common
                mapping['A05:2021-Security Misconfiguration'].append(vuln)
        
        return mapping
    
    def map_to_compliance(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Map vulnerabilities to compliance frameworks"""
        compliance = {
            'PCI-DSS': [],
            'HIPAA': [],
            'GDPR': [],
            'SOC 2': [],
        }
        
        # Simple mapping based on severity and type
        for vuln in vulnerabilities:
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                if vuln.cwe_id in [89, 798]:  # SQL Injection, Hardcoded Credentials
                    compliance['PCI-DSS'].append(vuln)
                    compliance['HIPAA'].append(vuln)
                    compliance['GDPR'].append(vuln)
                if vuln.cwe_id == 79:  # XSS
                    compliance['PCI-DSS'].append(vuln)
        
        return compliance

