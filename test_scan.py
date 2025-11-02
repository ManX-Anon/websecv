"""Test scan on vulnerable website"""

from scanner.scanner.engine import ScanEngine
from scanner.core.config import Config
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    target = 'http://testhtml5.vulnweb.com'
    
    print(f"\n{'='*60}")
    print(f"Scanning: {target}")
    print(f"{'='*60}\n")
    
    # Create scanner engine
    config = Config()
    engine = ScanEngine(config.scanner)
    
    # Run scan
    print("Starting scan...")
    vulnerabilities = engine.scan(target)
    
    # Display results
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n")
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. [{vuln.severity.value.upper()}] {vuln.title}")
            print(f"   CWE ID: {vuln.cwe_id or 'N/A'}")
            print(f"   CVSS Score: {vuln.cvss_score or 'N/A'}")
            print(f"   Confidence: {vuln.confidence * 100:.0f}%")
            print(f"   Description: {vuln.description[:200]}...")
            if vuln.evidence:
                print(f"   Evidence: {vuln.evidence[:100]}...")
            print()
    else:
        print("No vulnerabilities found.")
    
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()

