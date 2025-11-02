"""
Repeater tool for manual request editing and replay
"""

import logging
from typing import List, Optional, Dict, Any
import requests
import time

from scanner.core.interfaces import HttpRequest, HttpResponse, HttpMethod
from scanner.core.storage import Storage

logger = logging.getLogger(__name__)


class Repeater:
    """Repeater tool for manually editing and replaying HTTP requests"""
    
    def __init__(self, storage: Optional[Storage] = None):
        self.storage = storage
        self.history: List[tuple[HttpRequest, HttpResponse]] = []
    
    def send_request(self, request: HttpRequest, follow_redirects: bool = True) -> HttpResponse:
        """Send HTTP request and return response"""
        logger.info(f"Sending {request.method.value} request to {request.url}")
        
        try:
            # Convert to requests format
            method = request.method.value.lower()
            headers = request.headers.copy()
            data = request.body
            
            # Remove headers that requests handles automatically
            headers.pop('Host', None)
            headers.pop('Content-Length', None)
            
            # Send request
            response = requests.request(
                method=method,
                url=request.url,
                headers=headers,
                data=data,
                allow_redirects=follow_redirects,
                timeout=30
            )
            
            # Convert to HttpResponse
            http_response = HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
                timestamp=time.time()
            )
            
            # Store request with timestamp
            request.timestamp = time.time()
            
            # Save to history
            self.history.append((request, http_response))
            
            if self.storage:
                self.storage.save_request_response(request, http_response)
            
            return http_response
        
        except Exception as e:
            logger.error(f"Error sending request: {e}")
            raise
    
    def edit_request(self, request: HttpRequest, **kwargs) -> HttpRequest:
        """Edit a request (create modified copy)"""
        new_request = HttpRequest(
            method=kwargs.get('method', request.method),
            url=kwargs.get('url', request.url),
            headers=kwargs.get('headers', request.headers.copy()),
            body=kwargs.get('body', request.body),
        )
        
        # Update modified headers
        if 'set_headers' in kwargs:
            new_request.headers.update(kwargs['set_headers'])
        
        # Remove headers
        if 'remove_headers' in kwargs:
            for header in kwargs['remove_headers']:
                new_request.headers.pop(header, None)
        
        return new_request
    
    def compare_responses(self, response1: HttpResponse, response2: HttpResponse) -> Dict[str, Any]:
        """Compare two responses and highlight differences"""
        differences = {
            'status_code': response1.status_code != response2.status_code,
            'status_code_diff': (response1.status_code, response2.status_code),
            'headers_diff': self._diff_headers(response1.headers, response2.headers),
            'body_length_diff': len(response1.body) != len(response2.body),
            'body_length': (len(response1.body), len(response2.body)),
            'body_similarity': self._calculate_similarity(
                response1.body, response2.body
            ),
        }
        
        return differences
    
    def _diff_headers(self, headers1: Dict[str, str], headers2: Dict[str, str]) -> Dict[str, tuple]:
        """Find differences in headers"""
        diff = {}
        all_keys = set(headers1.keys()) | set(headers2.keys())
        
        for key in all_keys:
            val1 = headers1.get(key)
            val2 = headers2.get(key)
            if val1 != val2:
                diff[key] = (val1, val2)
        
        return diff
    
    def _calculate_similarity(self, body1: bytes, body2: bytes) -> float:
        """Calculate similarity between two response bodies"""
        if not body1 and not body2:
            return 1.0
        if not body1 or not body2:
            return 0.0
        
        # Simple byte comparison
        min_len = min(len(body1), len(body2))
        max_len = max(len(body1), len(body2))
        
        matches = sum(1 for i in range(min_len) if body1[i] == body2[i])
        return matches / max_len if max_len > 0 else 0.0
    
    def get_history(self) -> List[tuple[HttpRequest, HttpResponse]]:
        """Get request/response history"""
        return self.history.copy()

