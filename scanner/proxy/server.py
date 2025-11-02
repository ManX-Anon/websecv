"""
HTTP/HTTPS Proxy Server
"""

import socket
import threading
import ssl
import logging
from typing import List, Optional
from urllib.parse import urlparse

from scanner.core.interfaces import IProxy, HttpRequest, HttpResponse
from scanner.core.config import ProxyConfig
from scanner.core.storage import Storage
from .handler import ProxyHandler
from .tls import TLSCertificateManager

logger = logging.getLogger(__name__)


class ProxyServer(IProxy):
    """HTTP/HTTPS Proxy Server implementation"""
    
    def __init__(self, config: Optional[ProxyConfig] = None, storage: Optional[Storage] = None):
        self.config = config or ProxyConfig()
        self.storage = storage
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.history: List[tuple[HttpRequest, HttpResponse]] = []
        self.intercept_enabled = False
        self.tls_manager = TLSCertificateManager()
        
        # Initialize TLS certificates if needed
        if self.config.tls_intercept:
            self.tls_manager.ensure_certificate()
    
    def start(self, host: str = None, port: int = None):
        """Start the proxy server"""
        host = host or self.config.host
        port = port or self.config.port
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(100)
        self.running = True
        
        logger.info(f"Proxy server started on {host}:{port}")
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                logger.debug(f"New connection from {address}")
                
                # Handle each connection in a separate thread
                handler = ProxyHandler(
                    client_socket,
                    address,
                    self.config,
                    self.storage,
                    self.tls_manager,
                    self.on_request_response
                )
                thread = threading.Thread(target=handler.handle, daemon=True)
                thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Proxy server stopped")
    
    def on_request_response(self, request: HttpRequest, response: HttpResponse):
        """Callback for request/response pairs"""
        self.history.append((request, response))
        
        if self.storage:
            self.storage.save_request_response(request, response)
    
    def get_history(self) -> List[tuple[HttpRequest, HttpResponse]]:
        """Get request/response history"""
        return self.history.copy()
    
    def set_intercept(self, enabled: bool):
        """Enable/disable request interception"""
        self.intercept_enabled = enabled
        logger.info(f"Request interception {'enabled' if enabled else 'disabled'}")

