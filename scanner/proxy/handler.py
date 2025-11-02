"""
Proxy connection handler
"""

import socket
import ssl
import logging
from typing import Optional
from urllib.parse import urlparse

from scanner.core.interfaces import HttpRequest, HttpResponse, HttpMethod
from scanner.core.config import ProxyConfig
from scanner.core.storage import Storage
from .tls import TLSCertificateManager

logger = logging.getLogger(__name__)


class ProxyHandler:
    """Handles individual proxy connections"""
    
    def __init__(
        self,
        client_socket: socket.socket,
        address: tuple,
        config: ProxyConfig,
        storage: Optional[Storage],
        tls_manager: TLSCertificateManager,
        callback: callable
    ):
        self.client_socket = client_socket
        self.address = address
        self.config = config
        self.storage = storage
        self.tls_manager = tls_manager
        self.callback = callback
    
    def handle(self):
        """Handle the proxy connection"""
        try:
            # Receive the initial request
            data = self.client_socket.recv(4096)
            if not data:
                return
            
            # Check if this is a CONNECT request (HTTPS tunnel)
            request_str = data.decode('utf-8', errors='ignore')
            
            if request_str.startswith('CONNECT'):
                self._handle_connect(data)
            else:
                self._handle_http(data)
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            self.client_socket.close()
    
    def _handle_connect(self, data: bytes):
        """Handle HTTPS CONNECT tunnel"""
        # Parse CONNECT request
        lines = data.decode('utf-8', errors='ignore').split('\r\n')
        connect_line = lines[0]
        target_host, target_port = connect_line.split()[1].split(':')
        target_port = int(target_port)
        
        # Establish connection to target
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            target_socket.connect((target_host, target_port))
            
            # Send 200 Connection established to client
            self.client_socket.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
            
            if self.config.tls_intercept:
                # TLS interception - create MITM connection
                self._handle_tls_intercept(target_socket, target_host)
            else:
                # Pass-through tunnel
                self._tunnel(self.client_socket, target_socket)
        
        except Exception as e:
            logger.error(f"Error establishing tunnel: {e}")
            self.client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        finally:
            target_socket.close()
    
    def _handle_tls_intercept(self, target_socket: socket.socket, target_host: str):
        """Handle TLS interception"""
        try:
            # Create certificate for target host
            cert_path, key_path = self.tls_manager.get_certificate_for_host(target_host)
            
            # Wrap client socket with our certificate
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            
            client_ssl = context.wrap_socket(self.client_socket, server_side=True)
            
            # Wrap target socket with real SSL
            target_ssl = ssl.create_default_context().wrap_socket(
                target_socket, server_hostname=target_host
            )
            
            # Now handle decrypted HTTP
            try:
                # Receive decrypted request from client
                request_data = client_ssl.recv(4096)
                if request_data:
                    # Forward to target
                    target_ssl.sendall(request_data)
                    
                    # Receive response
                    response_data = target_ssl.recv(4096)
                    if response_data:
                        # Parse and log
                        self._parse_and_log(request_data, response_data)
                        # Forward to client
                        client_ssl.sendall(response_data)
                
                # Tunnel remaining data
                self._tunnel(client_ssl, target_ssl)
            finally:
                client_ssl.close()
                target_ssl.close()
        
        except Exception as e:
            logger.error(f"TLS interception error: {e}")
    
    def _handle_http(self, data: bytes):
        """Handle plain HTTP request"""
        try:
            # Parse request
            request = self._parse_request(data)
            
            # Check if we should intercept
            if self.config.intercept_all or not self._should_exclude(request.url):
                # Intercept logic here
                pass
            
            # Forward to target
            parsed_url = urlparse(request.url)
            target_host = parsed_url.hostname or 'localhost'
            target_port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((target_host, target_port))
            
            # Send request
            target_socket.sendall(data)
            
            # Receive response
            response_data = b''
            while True:
                chunk = target_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(chunk) < 4096:
                    break
            
            # Parse and log
            response = self._parse_response(response_data)
            if self.callback:
                self.callback(request, response)
            
            # Forward to client
            self.client_socket.sendall(response_data)
            
            target_socket.close()
        
        except Exception as e:
            logger.error(f"Error handling HTTP: {e}")
            self.client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
    
    def _parse_request(self, data: bytes) -> HttpRequest:
        """Parse HTTP request"""
        return HttpRequest.from_raw(data)
    
    def _parse_response(self, data: bytes) -> HttpResponse:
        """Parse HTTP response"""
        return HttpResponse.from_raw(data)
    
    def _should_exclude(self, url: str) -> bool:
        """Check if URL should be excluded"""
        parsed = urlparse(url)
        host = parsed.hostname or ''
        return any(domain in host for domain in self.config.exclude_domains)
    
    def _tunnel(self, client_sock: socket.socket, target_sock: socket.socket):
        """Tunnel data between two sockets"""
        import select
        
        try:
            while True:
                r, w, e = select.select([client_sock, target_sock], [], [], 1)
                if not r:
                    break
                
                if client_sock in r:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    target_sock.sendall(data)
                
                if target_sock in r:
                    data = target_sock.recv(4096)
                    if not data:
                        break
                    client_sock.sendall(data)
        except:
            pass

