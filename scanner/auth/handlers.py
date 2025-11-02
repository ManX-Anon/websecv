"""
Authentication handlers
"""

from typing import Optional, Dict, Any
from .manager import AuthManager


class LoginHandler:
    """Handle login forms"""
    
    @staticmethod
    def detect_login_form(html: str) -> Optional[Dict[str, Any]]:
        """Detect login form in HTML"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'lxml')
        
        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            input_types = [inp.get('type', '').lower() for inp in inputs]
            
            # Look for username/password fields
            if 'password' in input_types:
                username_field = None
                password_field = None
                
                for inp in inputs:
                    inp_type = inp.get('type', '').lower()
                    inp_name = inp.get('name', '').lower()
                    
                    if inp_type == 'password':
                        password_field = inp.get('name', 'password')
                    elif any(keyword in inp_name for keyword in ['user', 'email', 'login', 'account']):
                        username_field = inp.get('name', 'username')
                
                if username_field and password_field:
                    return {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'username_field': username_field,
                        'password_field': password_field,
                    }
        
        return None


class SessionHandler:
    """Handle session management"""
    
    @staticmethod
    def extract_session_tokens(response) -> Dict[str, str]:
        """Extract session tokens from response"""
        tokens = {}
        
        # Extract cookies
        if hasattr(response, 'cookies'):
            for cookie in response.cookies:
                if any(keyword in cookie.name.lower() for keyword in ['session', 'token', 'auth', 'jwt']):
                    tokens[cookie.name] = cookie.value
        
        # Extract from headers
        set_cookie = response.headers.get('Set-Cookie', '')
        if set_cookie:
            # Parse cookies from Set-Cookie header
            pass
        
        return tokens


class APIKeyHandler:
    """Handle API key authentication"""
    
    @staticmethod
    def detect_api_key_usage(html: str, response_headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Detect API key usage patterns"""
        # Check headers
        api_key_headers = ['X-API-Key', 'Authorization', 'API-Key', 'X-Auth-Token']
        
        for header in api_key_headers:
            if header in response_headers:
                return {
                    'header': header,
                    'location': 'header',
                }
        
        # Check JavaScript for API key patterns
        import re
        patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return {
                    'key': match.group(1),
                    'location': 'javascript',
                }
        
        return None

