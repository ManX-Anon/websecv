"""
Report format generators
"""

import json
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

from scanner.core.interfaces import Vulnerability

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """Generate HTML reports"""
    
    def generate(
        self,
        vulnerabilities: List[Vulnerability],
        output_path: Path,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generate HTML report"""
        from jinja2 import Template
        
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .severity { font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target:</strong> {{ target or 'N/A' }}</p>
    <p><strong>Generated:</strong> {{ timestamp }}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Findings:</strong> {{ total_findings }}</p>
        <p><strong>Critical:</strong> {{ critical_count }}</p>
        <p><strong>High:</strong> {{ high_count }}</p>
        <p><strong>Medium:</strong> {{ medium_count }}</p>
        <p><strong>Low:</strong> {{ low_count }}</p>
    </div>
    
    <h2>Findings</h2>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ vuln.severity.value }}">
        <h3>{{ vuln.title }}</h3>
        <p><strong>Severity:</strong> <span class="severity">{{ vuln.severity.value.upper() }}</span></p>
        <p><strong>Confidence:</strong> {{ (vuln.confidence * 100)|int }}%</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.remediation %}
        <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
        {% endif %}
        {% if vuln.cwe_id %}
        <p><strong>CWE ID:</strong> {{ vuln.cwe_id }}</p>
        {% endif %}
        {% if vuln.cvss_score %}
        <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
        {% endif %}
        <p><strong>URL:</strong> {{ vuln.request.url }}</p>
        <p><strong>Method:</strong> {{ vuln.request.method.value }}</p>
    </div>
    {% endfor %}
</body>
</html>
        """
        
        template = Template(template_str)
        summary = self._generate_summary(vulnerabilities)
        
        html = template.render(
            target=target,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            vulnerabilities=vulnerabilities,
            total_findings=len(vulnerabilities),
            critical_count=summary['critical_count'],
            high_count=summary['high_count'],
            medium_count=summary['medium_count'],
            low_count=summary['low_count'],
        )
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Generated HTML report: {output_path}")
        return output_path
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Generate summary statistics"""
        from scanner.core.interfaces import Severity
        
        summary = {
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
        }
        
        for vuln in vulnerabilities:
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


class PDFReportGenerator:
    """Generate PDF reports"""
    
    def generate(
        self,
        vulnerabilities: List[Vulnerability],
        output_path: Path,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generate PDF report"""
        # Use HTML generator and convert to PDF
        html_gen = HTMLReportGenerator()
        html_path = output_path.with_suffix('.html')
        html_gen.generate(vulnerabilities, html_path, target, metadata)
        
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(output_path))
            logger.info(f"Generated PDF report: {output_path}")
            return output_path
        except ImportError:
            logger.warning("WeasyPrint not available, falling back to HTML")
            return html_path


class JSONReportGenerator:
    """Generate JSON reports"""
    
    def generate(
        self,
        vulnerabilities: List[Vulnerability],
        output_path: Path,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generate JSON report"""
        report = {
            'target': target,
            'generated': datetime.now().isoformat(),
            'metadata': metadata or {},
            'summary': {
                'total': len(vulnerabilities),
                'by_severity': {}
            },
            'vulnerabilities': []
        }
        
        # Calculate summary
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            report['summary']['by_severity'][severity] = report['summary']['by_severity'].get(severity, 0) + 1
        
        for vuln in vulnerabilities:
            report['vulnerabilities'].append({
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity.value,
                'confidence': vuln.confidence,
                'url': vuln.request.url,
                'method': vuln.request.method.value,
                'status_code': vuln.response.status_code,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
                'cwe_id': vuln.cwe_id,
                'cvss_score': vuln.cvss_score,
            })
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Generated JSON report: {output_path}")
        return output_path

