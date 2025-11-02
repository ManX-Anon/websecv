"""
Example: Basic vulnerability scanning
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.crawler.spider import WebSpider
from scanner.scanner.engine import ScanEngine
from scanner.reporting.generator import ReportGenerator
from scanner.core.config import Config, CrawlerConfig, ScannerConfig
from scanner.core.storage import DatabaseStorage


def main(target_url: str):
    """Run a basic vulnerability scan"""
    
    # Initialize components
    config = Config()
    storage = DatabaseStorage()
    
    # Step 1: Crawl the target
    print(f"Step 1: Crawling {target_url}...")
    crawler_config = CrawlerConfig(
        max_depth=5,
        max_pages=50,
        use_headless_browser=True
    )
    spider = WebSpider(crawler_config, storage)
    crawl_results = spider.crawl(target_url)
    print(f"  Discovered {len(crawl_results['discovered_endpoints'])} endpoints")
    
    # Step 2: Scan for vulnerabilities
    print(f"\nStep 2: Scanning for vulnerabilities...")
    scanner_config = ScannerConfig(
        active_checks=True,
        passive_checks=True,
        max_concurrent_checks=5
    )
    engine = ScanEngine(scanner_config, storage)
    
    # Note: In production, this would scan discovered endpoints
    # For now, this is a placeholder
    vulnerabilities = engine.scan(target_url)
    print(f"  Found {len(vulnerabilities)} vulnerabilities")
    
    # Step 3: Generate report
    print(f"\nStep 3: Generating report...")
    generator = ReportGenerator()
    report_path = generator.generate(
        vulnerabilities,
        Path('scan_report.html'),
        format='html',
        target=target_url
    )
    print(f"  Report saved: {report_path}")
    
    # Display summary
    summary = generator.generate_executive_summary(vulnerabilities)
    print(f"\nScan Summary:")
    print(f"  Total Findings: {summary['total_findings']}")
    print(f"  Critical: {summary['critical_count']}")
    print(f"  High: {summary['high_count']}")
    print(f"  Medium: {summary['medium_count']}")
    print(f"  Low: {summary['low_count']}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python example_scan.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    main(target_url)

