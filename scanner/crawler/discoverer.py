"""
Endpoint discovery utilities
"""

import re
from typing import List, Set
from urllib.parse import urlparse
import ast


class EndpointDiscoverer:
    """Discover endpoints from various sources"""
    
    @staticmethod
    def discover_from_javascript(js_code: str) -> List[str]:
        """Discover API endpoints from JavaScript code"""
        endpoints = set()
        
        # Common patterns for API calls
        patterns = [
            r'["\']([^"\']*\/api\/[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                if isinstance(match, tuple):
                    endpoints.update(m for m in match if m)
                else:
                    endpoints.add(match)
        
        return list(endpoints)
    
    @staticmethod
    def discover_from_html(html: str) -> List[str]:
        """Discover endpoints from HTML"""
        endpoints = set()
        
        # Form actions
        endpoints.update(re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html))
        
        # Data attributes
        endpoints.update(re.findall(r'data-api=["\']([^"\']+)["\']', html))
        endpoints.update(re.findall(r'data-url=["\']([^"\']+)["\']', html))
        
        # JavaScript in HTML
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
        for js in js_blocks:
            endpoints.update(EndpointDiscoverer.discover_from_javascript(js))
        
        return list(endpoints)
    
    @staticmethod
    def discover_from_api_docs(api_spec: str) -> List[str]:
        """Discover endpoints from OpenAPI/Swagger specs"""
        endpoints = []
        
        # OpenAPI paths
        if isinstance(api_spec, dict):
            paths = api_spec.get('paths', {})
            endpoints.extend(paths.keys())
        elif isinstance(api_spec, str):
            # Try to parse as JSON/YAML
            try:
                import json
                spec = json.loads(api_spec)
                paths = spec.get('paths', {})
                endpoints.extend(paths.keys())
            except:
                pass
        
        return endpoints
    
    @staticmethod
    def discover_parameters_from_js(js_code: str) -> List[str]:
        """Discover parameter names from JavaScript"""
        params = set()
        
        # Function parameters
        param_pattern = r'function\s+\w+\s*\(([^)]+)\)'
        matches = re.findall(param_pattern, js_code)
        for match in matches:
            params.update(p.strip() for p in match.split(',') if p.strip())
        
        # Object properties
        obj_pattern = r'\.(\w+)\s*[:=]'
        params.update(re.findall(obj_pattern, js_code))
        
        # Common parameter patterns
        common_params = ['id', 'userId', 'token', 'apiKey', 'sessionId']
        params.update(common_params)
        
        return list(params)

