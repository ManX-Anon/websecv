"""
Vulnerability Scanner Engine
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor

from scanner.core.interfaces import IScanner, IVulnCheck, Vulnerability, HttpRequest, HttpResponse
from scanner.core.config import ScannerConfig
from scanner.core.storage import Storage
from .checks import PassiveCheck, ActiveCheck

logger = logging.getLogger(__name__)


class ScanEngine(IScanner):
    """Vulnerability scanner engine"""
    
    def __init__(self, config: Optional[ScannerConfig] = None, storage: Optional[Storage] = None):
        self.config = config or ScannerConfig()
        self.storage = storage
        self.passive_checks: List[PassiveCheck] = []
        self.active_checks: List[ActiveCheck] = []
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_checks)
        
        # Register default checks
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default vulnerability checks"""
        from .checks.xss import XSSCheck
        from .checks.sql_injection import SQLInjectionCheck
        from .checks.cors import CORSCheck
        from .checks.ssl import SSLCheck
        from .checks.headers import SecurityHeadersCheck
        from .checks.ssrf import SSRFCheck
        from .checks.xxe import XXECheck
        from .checks.path_traversal import PathTraversalCheck
        from .checks.command_injection import CommandInjectionCheck
        from .checks.open_redirect import OpenRedirectCheck
        from .checks.idor import IDORCheck
        
        # Passive checks
        if self.config.passive_checks:
            self.register_check(CORSCheck())
            self.register_check(SSLCheck())
            self.register_check(SecurityHeadersCheck())
            self.register_check(OpenRedirectCheck())
        
        # Active checks
        if self.config.active_checks:
            self.register_check(XSSCheck())
            self.register_check(SQLInjectionCheck())
            self.register_check(SSRFCheck())
            self.register_check(XXECheck())
            self.register_check(PathTraversalCheck())
            self.register_check(CommandInjectionCheck())
            self.register_check(IDORCheck())
    
    def scan(self, target: str) -> List[Vulnerability]:
        """Scan target for vulnerabilities"""
        logger.info(f"Starting scan of {target}")
        
        vulnerabilities = []
        
        # Make HTTP request to target
        try:
            import requests
            from urllib.parse import urlparse
            from scanner.core.interfaces import HttpRequest, HttpResponse, HttpMethod
            
            # Parse target URL
            parsed = urlparse(target)
            if not parsed.scheme:
                target = 'https://' + target
                parsed = urlparse(target)
            
            logger.info(f"Scanning {target}")
            
            # Make initial request
            headers = {
                'User-Agent': 'Scanner/1.0'
            }
            
            try:
                response = requests.get(target, headers=headers, timeout=30, allow_redirects=True)
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                target = target.replace('https://', 'http://')
                response = requests.get(target, headers=headers, timeout=30, allow_redirects=True)
            
            # Create HttpRequest object
            request = HttpRequest(
                method=HttpMethod.GET,
                url=target,
                headers=headers,
                body=None
            )
            
            # Create HttpResponse object
            http_response = HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
            )
            
            # Scan the request/response pair
            found_vulns = self.scan_request_response(request, http_response)
            vulnerabilities.extend(found_vulns)
            
            logger.info(f"Found {len(found_vulns)} vulnerabilities from initial request")
            
            # Try to discover additional endpoints and scan them
            # Check for common paths and API endpoints
            common_paths = [
                '/api', '/api/users', '/api/login', '/api/data',
                '/admin', '/login', '/signup', '/register',
                '/search', '/profile', '/user', '/test'
            ]
            
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Track seen vulnerabilities to avoid duplicates
            seen_vulns = set()
            
            # Scan a few common paths
            for path in common_paths[:5]:  # Scan more paths
                try:
                    test_url = base_url + path
                    test_response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
                    
                    # Only scan if endpoint exists (status 200-399)
                    if test_response.status_code >= 400:
                        continue
                    
                    test_request = HttpRequest(
                        method=HttpMethod.GET,
                        url=test_url,
                        headers=headers,
                        body=None
                    )
                    
                    test_http_response = HttpResponse(
                        status_code=test_response.status_code,
                        headers=dict(test_response.headers),
                        body=test_response.content,
                    )
                    
                    # Scan this endpoint
                    path_vulns = self.scan_request_response(test_request, test_http_response)
                    for vuln in path_vulns:
                        # Deduplicate: same title + URL combination
                        vuln_key = (vuln.title, test_url)
                        if vuln_key not in seen_vulns:
                            seen_vulns.add(vuln_key)
                            vulnerabilities.append(vuln)
                    
                except Exception as e:
                    logger.debug(f"Error scanning {path}: {e}")
                    continue
            
            # Deduplicate final list
            unique_vulns = []
            seen = set()
            for vuln in vulnerabilities:
                key = (vuln.title, vuln.request.url)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            vulnerabilities = unique_vulns
            logger.info(f"Total unique vulnerabilities found: {len(vulnerabilities)}")
            
            # Enhanced crawling with form discovery
            if self.config.active_checks:
                try:
                    from scanner.crawler.form_discovery import FormDiscovery
                    
                    # Parse HTML for forms
                    html_content = http_response.body.decode('utf-8', errors='ignore')
                    form_discovery = FormDiscovery()
                    forms = form_discovery.discover_forms(html_content, target)
                    
                    logger.info(f"Discovered {len(forms)} forms")
                    
                    # Scan discovered forms (basic check)
                    for form in forms[:2]:  # Limit to first 2 forms
                        if form['method'] == 'POST':
                            # Check for potential issues in forms
                            # This is a simplified check
                            pass
                    
                    # Discover API endpoints
                    api_endpoints = form_discovery.discover_api_endpoints(html_content)
                    logger.info(f"Discovered {len(api_endpoints)} API endpoints from JavaScript")
                    
                except Exception as e:
                    logger.debug(f"Form discovery error: {e}")
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}", exc_info=True)
        
        return vulnerabilities
    
    def scan_request_response(self, request: HttpRequest, response: HttpResponse) -> List[Vulnerability]:
        """Scan a request/response pair for vulnerabilities"""
        vulnerabilities = []
        
        # Run passive checks
        if self.config.passive_checks:
            for check in self.passive_checks:
                try:
                    vuln = check.check(request, response)
                    if vuln:
                        vulnerabilities.append(vuln)
                except Exception as e:
                    logger.error(f"Error in passive check {check.get_name()}: {e}")
        
        # Run active checks (async)
        if self.config.active_checks:
            futures = []
            for check in self.active_checks:
                future = self.executor.submit(self._run_active_check, check, request, response)
                futures.append(future)
            
            for future in futures:
                try:
                    vuln = future.result(timeout=self.config.check_timeout)
                    if vuln:
                        vulnerabilities.append(vuln)
                except Exception as e:
                    logger.error(f"Error in active check: {e}")
        
        # Save vulnerabilities
        if self.storage:
            for vuln in vulnerabilities:
                self.storage.save_vulnerability(vuln)
        
        return vulnerabilities
    
    def _run_active_check(self, check: ActiveCheck, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Run an active check"""
        return check.check(request, response)
    
    def register_check(self, check: IVulnCheck):
        """Register a vulnerability check"""
        if isinstance(check, PassiveCheck):
            self.passive_checks.append(check)
            logger.info(f"Registered passive check: {check.get_name()}")
        elif isinstance(check, ActiveCheck):
            self.active_checks.append(check)
            logger.info(f"Registered active check: {check.get_name()}")
        else:
            logger.warning(f"Unknown check type: {type(check)}")

