"""
Authentication manager for scans
"""

from typing import Optional, Dict, Any
import requests
from scanner.core.interfaces import HttpRequest, HttpMethod


class AuthManager:
    """Manage authentication for scans"""
    
    def __init__(self):
        self.session = requests.Session()
        self.cookies = {}
        self.headers = {}
        self.auth_type = None
        self.auth_data = {}
    
    def set_basic_auth(self, username: str, password: str):
        """Set basic authentication"""
        from requests.auth import HTTPBasicAuth
        self.session.auth = HTTPBasicAuth(username, password)
        self.auth_type = 'basic'
        self.auth_data = {'username': username}
    
    def set_api_key(self, key: str, header_name: str = 'X-API-Key', location: str = 'header'):
        """Set API key authentication"""
        if location == 'header':
            self.headers[header_name] = key
            self.session.headers.update(self.headers)
        elif location == 'query':
            # Will be added to requests
            pass
        self.auth_type = 'api_key'
        self.auth_data = {'header': header_name, 'key': key}
    
    def login(self, login_url: str, username: str, password: str, 
              username_field: str = 'username', password_field: str = 'password') -> bool:
        """Perform login"""
        try:
            response = self.session.post(
                login_url,
                data={
                    username_field: username,
                    password_field: password,
                },
                allow_redirects=False
            )
            
            # Check for successful login (redirect or session cookie)
            if response.status_code in [200, 302, 303]:
                # Save cookies
                self.cookies.update(self.session.cookies.get_dict())
                self.auth_type = 'session'
                self.auth_data = {'login_url': login_url}
                return True
            
            return False
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def make_authenticated_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make authenticated request"""
        # Update headers
        if self.headers:
            kwargs.setdefault('headers', {}).update(self.headers)
        
        # Update cookies
        if self.cookies:
            kwargs.setdefault('cookies', {}).update(self.cookies)
        
        # Make request
        if method.upper() == 'GET':
            return self.session.get(url, **kwargs)
        elif method.upper() == 'POST':
            return self.session.post(url, **kwargs)
        elif method.upper() == 'PUT':
            return self.session.put(url, **kwargs)
        elif method.upper() == 'DELETE':
            return self.session.delete(url, **kwargs)
        else:
            return self.session.request(method, url, **kwargs)
    
    def get_session_cookies(self) -> Dict[str, str]:
        """Get session cookies"""
        return dict(self.session.cookies)
    
    def clear_auth(self):
        """Clear authentication"""
        self.session = requests.Session()
        self.cookies = {}
        self.headers = {}
        self.auth_type = None
        self.auth_data = {}

