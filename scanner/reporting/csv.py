"""
CSV report generator
"""

import csv
from typing import List
from pathlib import Path
from scanner.core.interfaces import Vulnerability


class CSVReportGenerator:
    """Generate CSV reports"""
    
    def generate(self, vulnerabilities: List[Vulnerability], output_path: Path) -> Path:
        """Generate CSV report"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Title',
                'Severity',
                'Confidence',
                'CWE ID',
                'CVSS Score',
                'URL',
                'Method',
                'Description',
                'Evidence',
                'Remediation'
            ])
            
            # Write vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.title,
                    vuln.severity.value,
                    f"{vuln.confidence * 100:.0f}%",
                    vuln.cwe_id or '',
                    vuln.cvss_score or '',
                    vuln.request.url,
                    vuln.request.method.value,
                    vuln.description[:200],
                    vuln.evidence or '',
                    vuln.remediation or ''
                ])
        
        return output_path

