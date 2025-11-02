"""
Form discovery and analysis
"""

import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup


class FormDiscovery:
    """Discover and analyze HTML forms"""
    
    @staticmethod
    def discover_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
        """Discover forms in HTML"""
        soup = BeautifulSoup(html, 'lxml')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'textarea': [],
                'select': [],
            }
            
            # Discover input fields
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required'),
                    'placeholder': input_tag.get('placeholder', ''),
                }
                form_data['inputs'].append(input_data)
            
            # Discover textareas
            for textarea in form.find_all('textarea'):
                textarea_data = {
                    'name': textarea.get('name', ''),
                    'value': textarea.string or '',
                }
                form_data['textarea'].append(textarea_data)
            
            # Discover select fields
            for select in form.find_all('select'):
                options = [opt.get('value', opt.string) for opt in select.find_all('option')]
                select_data = {
                    'name': select.get('name', ''),
                    'options': options,
                }
                form_data['select'].append(select_data)
            
            # Build full URL
            if form_data['action']:
                from urllib.parse import urljoin
                form_data['url'] = urljoin(base_url, form_data['action'])
            else:
                form_data['url'] = base_url
            
            forms.append(form_data)
        
        return forms
    
    @staticmethod
    def discover_hidden_inputs(html: str) -> List[Dict[str, str]]:
        """Discover hidden input fields"""
        soup = BeautifulSoup(html, 'lxml')
        hidden_inputs = []
        
        for input_tag in soup.find_all('input', type='hidden'):
            hidden_inputs.append({
                'name': input_tag.get('name', ''),
                'value': input_tag.get('value', ''),
            })
        
        return hidden_inputs
    
    @staticmethod
    def discover_api_endpoints(html: str) -> List[str]:
        """Discover API endpoints from JavaScript"""
        endpoints = []
        
        # Extract JavaScript
        js_patterns = [
            r'["\']([^"\']*\/api\/[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))  # Remove duplicates
    
    @staticmethod
    def discover_sensitive_files(html: str, base_url: str) -> List[str]:
        """Discover references to sensitive files"""
        soup = BeautifulSoup(html, 'lxml')
        sensitive_files = []
        
        # Common sensitive file patterns
        sensitive_patterns = [
            r'\.env',
            r'\.git',
            r'\.svn',
            r'backup',
            r'dump',
            r'config\.php',
            r'config\.json',
            r'\.key',
            r'\.pem',
        ]
        
        # Check in links
        for link in soup.find_all('a', href=True):
            href = link['href']
            for pattern in sensitive_patterns:
                if re.search(pattern, href, re.IGNORECASE):
                    from urllib.parse import urljoin
                    sensitive_files.append(urljoin(base_url, href))
        
        # Check in script src
        for script in soup.find_all('script', src=True):
            src = script['src']
            for pattern in sensitive_patterns:
                if re.search(pattern, src, re.IGNORECASE):
                    from urllib.parse import urljoin
                    sensitive_files.append(urljoin(base_url, src))
        
        return list(set(sensitive_files))

