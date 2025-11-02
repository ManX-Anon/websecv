"""
XML report generator
"""

from typing import List
from pathlib import Path
from datetime import datetime
from scanner.core.interfaces import Vulnerability
import xml.etree.ElementTree as ET
from xml.dom import minidom


class XMLReportGenerator:
    """Generate XML reports"""
    
    def generate(self, vulnerabilities: List[Vulnerability], output_path: Path, target: str = None) -> Path:
        """Generate XML report"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        root = ET.Element("scan_results")
        root.set("target", target or "unknown")
        root.set("timestamp", datetime.now().isoformat())
        root.set("total_vulnerabilities", str(len(vulnerabilities)))
        
        # Statistics
        stats = ET.SubElement(root, "statistics")
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        for severity, count in by_severity.items():
            stat = ET.SubElement(stats, "severity")
            stat.set("level", severity)
            stat.set("count", str(count))
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for vuln in vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            
            ET.SubElement(vuln_elem, "title").text = vuln.title
            ET.SubElement(vuln_elem, "severity").text = vuln.severity.value
            ET.SubElement(vuln_elem, "confidence").text = f"{vuln.confidence * 100:.0f}%"
            
            if vuln.cwe_id:
                ET.SubElement(vuln_elem, "cwe_id").text = str(vuln.cwe_id)
            if vuln.cvss_score:
                ET.SubElement(vuln_elem, "cvss_score").text = str(vuln.cvss_score)
            
            ET.SubElement(vuln_elem, "description").text = vuln.description
            if vuln.evidence:
                ET.SubElement(vuln_elem, "evidence").text = vuln.evidence
            if vuln.remediation:
                ET.SubElement(vuln_elem, "remediation").text = vuln.remediation
            
            # Request details
            request_elem = ET.SubElement(vuln_elem, "request")
            ET.SubElement(request_elem, "url").text = vuln.request.url
            ET.SubElement(request_elem, "method").text = vuln.request.method.value
            
            # Response details
            response_elem = ET.SubElement(vuln_elem, "response")
            ET.SubElement(response_elem, "status_code").text = str(vuln.response.status_code)
        
        # Pretty print
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_str)
        
        return output_path

