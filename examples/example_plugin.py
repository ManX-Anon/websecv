"""
Example plugin for the Extender API
"""

from scanner.extender.plugin import Plugin, PluginContext
from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, Severity


class ExamplePlugin(Plugin):
    """Example plugin that checks for API keys in responses"""
    
    def get_name(self) -> str:
        return "API Key Checker"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def initialize(self, context: PluginContext):
        super().initialize(context)
        # Register for request/response events
        # This would be handled by the ExtenderAPI in production
    
    def handle_event(self, event: str, data: dict):
        """Handle events"""
        if event == 'response_received':
            request = data.get('request')
            response = data.get('response')
            
            if request and response:
                vuln = self._check_for_api_keys(request, response)
                if vuln:
                    return vuln
        
        return None
    
    def _check_for_api_keys(self, request: HttpRequest, response: HttpResponse) -> Vulnerability:
        """Check if API keys are exposed in response"""
        import re
        
        body_str = response.body.decode('utf-8', errors='ignore')
        
        # Common API key patterns
        patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body_str, re.IGNORECASE)
            if match:
                return Vulnerability(
                    title="API Key Exposed in Response",
                    description="API key or access token found in response body. This may allow unauthorized access.",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    request=request,
                    response=response,
                    evidence=f"Found potential API key: {match.group(1)[:20]}...",
                    remediation="Do not expose API keys or tokens in responses. Use server-side storage and secure transmission.",
                    cwe_id=798,
                    cvss_score=7.5
                )
        
        return None

