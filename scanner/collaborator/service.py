"""
Out-of-band Application Security Testing (OAST) service
"""

import logging
import uuid
import time
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class CollaboratorService:
    """OAST service for detecting out-of-band interactions"""
    
    def __init__(self, domain: str = "collaborator.local"):
        self.domain = domain
        self.interactions: Dict[str, List[Dict]] = {}
        self.payloads: Dict[str, Dict] = {}
    
    def generate_payload(self, payload_type: str = "dns") -> str:
        """Generate a unique payload for out-of-band testing"""
        unique_id = str(uuid.uuid4())[:8]
        payload_id = f"{payload_type}-{unique_id}"
        
        if payload_type == "dns":
            payload = f"{unique_id}.{self.domain}"
        elif payload_type == "http":
            payload = f"http://{unique_id}.{self.domain}/test"
        else:
            payload = f"{unique_id}.{self.domain}"
        
        # Store payload metadata
        self.payloads[payload_id] = {
            'payload': payload,
            'type': payload_type,
            'created_at': datetime.now(),
            'interactions': [],
        }
        
        logger.info(f"Generated {payload_type} payload: {payload}")
        return payload
    
    def register_interaction(
        self,
        payload_id: str,
        interaction_type: str,
        source_ip: str,
        details: Optional[Dict] = None
    ):
        """Register an interaction (DNS lookup, HTTP request, etc.)"""
        if payload_id not in self.payloads:
            logger.warning(f"Unknown payload ID: {payload_id}")
            return
        
        interaction = {
            'type': interaction_type,
            'source_ip': source_ip,
            'timestamp': datetime.now(),
            'details': details or {},
        }
        
        self.payloads[payload_id]['interactions'].append(interaction)
        
        if payload_id not in self.interactions:
            self.interactions[payload_id] = []
        self.interactions[payload_id].append(interaction)
        
        logger.info(f"Registered {interaction_type} interaction for payload {payload_id}")
    
    def check_interactions(self, payload_id: str) -> List[Dict]:
        """Check for interactions for a specific payload"""
        if payload_id not in self.payloads:
            return []
        
        return self.payloads[payload_id]['interactions'].copy()
    
    def has_interactions(self, payload_id: str) -> bool:
        """Check if payload has any interactions"""
        return len(self.check_interactions(payload_id)) > 0
    
    def get_all_interactions(self) -> Dict[str, List[Dict]]:
        """Get all interactions"""
        return self.interactions.copy()
    
    def clear_payload(self, payload_id: str):
        """Clear a payload and its interactions"""
        if payload_id in self.payloads:
            del self.payloads[payload_id]
        if payload_id in self.interactions:
            del self.interactions[payload_id]

