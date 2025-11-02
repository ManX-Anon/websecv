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
        
        # Passive checks
        if self.config.passive_checks:
            self.register_check(CORSCheck())
            self.register_check(SSLCheck())
            self.register_check(SecurityHeadersCheck())
        
        # Active checks
        if self.config.active_checks:
            self.register_check(XSSCheck())
            self.register_check(SQLInjectionCheck())
    
    def scan(self, target: str) -> List[Vulnerability]:
        """Scan target for vulnerabilities"""
        logger.info(f"Starting scan of {target}")
        
        # For now, scan requires HTTP requests
        # In production, this would integrate with crawler/proxy
        vulnerabilities = []
        
        # Placeholder - actual implementation would fetch and check requests
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

