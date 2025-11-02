"""
Collaborator server for OAST testing
"""

import logging
from flask import Flask, request, jsonify
from typing import Optional

from .service import CollaboratorService

logger = logging.getLogger(__name__)


class CollaboratorServer:
    """HTTP/DNS server for Collaborator service"""
    
    def __init__(self, service: CollaboratorService, host: str = "0.0.0.0", port: int = 8081):
        self.service = service
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/health', methods=['GET'])
        def health():
            return jsonify({'status': 'ok'}), 200
        
        @self.app.route('/interactions/<payload_id>', methods=['GET'])
        def get_interactions(payload_id: str):
            interactions = self.service.check_interactions(payload_id)
            return jsonify({'interactions': interactions}), 200
        
        @self.app.route('/register/<interaction_type>', methods=['POST'])
        def register_interaction(interaction_type: str):
            data = request.json
            payload_id = data.get('payload_id')
            source_ip = request.remote_addr
            
            if not payload_id:
                return jsonify({'error': 'payload_id required'}), 400
            
            self.service.register_interaction(
                payload_id,
                interaction_type,
                source_ip,
                data.get('details')
            )
            
            return jsonify({'status': 'registered'}), 200
    
    def start(self):
        """Start the server"""
        logger.info(f"Starting Collaborator server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False)
    
    def stop(self):
        """Stop the server"""
        # Flask doesn't have a clean stop method
        # In production, use a proper WSGI server
        logger.info("Stopping Collaborator server")

