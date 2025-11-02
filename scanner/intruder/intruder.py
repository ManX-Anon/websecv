"""
Intruder/Fuzzer engine
"""

import logging
import time
import threading
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.interfaces import HttpRequest, HttpResponse, HttpMethod
from scanner.core.config import IntruderConfig
from .payloads import PayloadGenerator
from .strategies import AttackStrategy, SniperStrategy

logger = logging.getLogger(__name__)


class Intruder:
    """Intruder/Fuzzer for parameterized attacks"""
    
    def __init__(self, config: Optional[IntruderConfig] = None):
        self.config = config or IntruderConfig()
        self.payload_generator = PayloadGenerator()
        self.results: List[Dict] = []
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_threads)
    
    def fuzz(
        self,
        base_request: HttpRequest,
        positions: Dict[str, List[str]],  # Parameter name -> list of payloads
        strategy: Optional[AttackStrategy] = None,
        callback: Optional[Callable] = None
    ) -> List[Dict]:
        """
        Fuzz a request with multiple payloads
        
        Args:
            base_request: Base HTTP request to fuzz
            positions: Dictionary mapping parameter names to payload lists
            strategy: Attack strategy (default: Sniper)
            callback: Optional callback for each request/response pair
        """
        strategy = strategy or SniperStrategy()
        
        logger.info(f"Starting fuzz attack with {len(positions)} positions")
        
        # Generate payload combinations based on strategy
        payload_combinations = strategy.generate_combinations(positions)
        
        # Execute requests
        futures = []
        for i, payloads in enumerate(payload_combinations):
            future = self.executor.submit(
                self._send_request,
                base_request,
                payloads,
                i,
                callback
            )
            futures.append(future)
            
            # Rate limiting
            time.sleep(self.config.rate_limit)
        
        # Collect results
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    self.results.append(result)
            except Exception as e:
                logger.error(f"Error in fuzz request: {e}")
        
        logger.info(f"Fuzz attack completed. {len(self.results)} requests sent")
        return self.results
    
    def _send_request(
        self,
        base_request: HttpRequest,
        payloads: Dict[str, str],
        request_id: int,
        callback: Optional[Callable] = None
    ) -> Optional[Dict]:
        """Send a single fuzzed request"""
        try:
            # Create modified request with payloads
            modified_request = self._inject_payloads(base_request, payloads)
            
            # Send request
            import requests
            method = modified_request.method.value.lower()
            headers = modified_request.headers.copy()
            data = modified_request.body
            
            response = requests.request(
                method=method,
                url=modified_request.url,
                headers=headers,
                data=data,
                allow_redirects=self.config.follow_redirects,
                timeout=self.config.timeout
            )
            
            http_response = HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
                timestamp=time.time()
            )
            
            result = {
                'request_id': request_id,
                'request': modified_request,
                'response': http_response,
                'payloads': payloads,
                'status_code': response.status_code,
                'response_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
            }
            
            if callback:
                callback(modified_request, http_response, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Error sending fuzz request: {e}")
            return None
    
    def _inject_payloads(self, request: HttpRequest, payloads: Dict[str, str]) -> HttpRequest:
        """Inject payloads into request"""
        import urllib.parse
        
        # Clone request
        modified_request = HttpRequest(
            method=request.method,
            url=request.url,
            headers=request.headers.copy(),
            body=request.body,
        )
        
        # Inject into URL query string
        if '?' in request.url:
            url_parts = request.url.split('?', 1)
            base_url = url_parts[0]
            query_string = url_parts[1]
            
            params = urllib.parse.parse_qs(query_string)
            for param, value in payloads.items():
                if param in params:
                    params[param] = [value]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            modified_request.url = f"{base_url}?{new_query}"
        
        # Inject into POST body
        if request.body and request.method in [HttpMethod.POST, HttpMethod.PUT]:
            body_str = request.body.decode('utf-8', errors='ignore')
            if 'application/x-www-form-urlencoded' in request.headers.get('Content-Type', ''):
                params = urllib.parse.parse_qs(body_str)
                for param, value in payloads.items():
                    if param in params:
                        params[param] = [value]
                
                new_body = urllib.parse.urlencode(params, doseq=True)
                modified_request.body = new_body.encode()
                modified_request.headers['Content-Length'] = str(len(modified_request.body))
        
        return modified_request
    
    def get_results(self) -> List[Dict]:
        """Get fuzzing results"""
        return self.results.copy()
    
    def clear_results(self):
        """Clear results"""
        self.results.clear()

