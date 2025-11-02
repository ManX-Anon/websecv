"""
Command-line interface for the scanner
"""

import click
import logging
from pathlib import Path

from scanner.core.config import Config, load_config
from scanner.core.storage import DatabaseStorage
from scanner.proxy.server import ProxyServer
from scanner.crawler.spider import WebSpider
from scanner.scanner.engine import ScanEngine
from scanner.reporting.generator import ReportGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
@click.pass_context
def cli(ctx, config):
    """Web Application Vulnerability Scanner"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config) if config else Config()
    ctx.obj['storage'] = DatabaseStorage()


@cli.command()
@click.option('--host', default='127.0.0.1', help='Proxy host')
@click.option('--port', default=8080, type=int, help='Proxy port')
@click.pass_context
def proxy(ctx, host, port):
    """Start the proxy server"""
    config = ctx.obj['config']
    storage = ctx.obj['storage']
    
    server = ProxyServer(config.proxy, storage)
    click.echo(f"Starting proxy on {host}:{port}")
    try:
        server.start(host, port)
    except KeyboardInterrupt:
        click.echo("\nStopping proxy...")
        server.stop()


@cli.command()
@click.argument('url')
@click.option('--max-depth', default=10, type=int, help='Maximum crawl depth')
@click.pass_context
def crawl(ctx, url, max_depth):
    """Crawl a website"""
    config = ctx.obj['config']
    storage = ctx.obj['storage']
    
    spider = WebSpider(config.crawler, storage)
    click.echo(f"Crawling {url}...")
    results = spider.crawl(url, max_depth)
    
    click.echo(f"\nCrawl completed:")
    click.echo(f"  Visited URLs: {results['total_pages']}")
    click.echo(f"  Discovered endpoints: {len(results['discovered_endpoints'])}")


@cli.command()
@click.argument('target')
@click.option('--output', type=click.Path(), help='Output file path')
@click.option('--format', type=click.Choice(['html', 'pdf', 'json']), default='html')
@click.pass_context
def scan(ctx, target, output, format):
    """Scan a target for vulnerabilities"""
    config = ctx.obj['config']
    storage = ctx.obj['storage']
    
    engine = ScanEngine(config.scanner, storage)
    click.echo(f"Scanning {target}...")
    
    # This would integrate with crawler/proxy to get requests
    vulnerabilities = engine.scan(target)
    
    click.echo(f"\nScan completed:")
    click.echo(f"  Total findings: {len(vulnerabilities)}")
    
    if vulnerabilities:
        # Generate report
        if not output:
            output = Path(f"report_{target.replace('://', '_').replace('/', '_')}.{format}")
        
        generator = ReportGenerator()
        report_path = generator.generate(
            vulnerabilities,
            Path(output),
            format=format,
            target=target
        )
        
        click.echo(f"  Report saved: {report_path}")


@cli.command()
@click.option('--format', type=click.Choice(['html', 'pdf', 'json']), default='html')
@click.option('--output', type=click.Path(), default='report', help='Output file path')
@click.pass_context
def report(ctx, format, output):
    """Generate report from stored vulnerabilities"""
    storage = ctx.obj['storage']
    
    vulnerabilities = storage.get_vulnerabilities()
    click.echo(f"Generating report for {len(vulnerabilities)} findings...")
    
    generator = ReportGenerator()
    report_path = generator.generate(
        vulnerabilities,
        Path(output),
        format=format
    )
    
    click.echo(f"Report saved: {report_path}")


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, type=int, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def web(ctx, host, port, debug):
    """Start the web application"""
    from scanner.web.app import create_app
    
    app = create_app()
    click.echo(f"Starting web application on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    cli()

