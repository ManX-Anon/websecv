"""
TLS Certificate Management for MITM interception
"""

import os
from pathlib import Path
from OpenSSL import crypto, SSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import ipaddress
import logging

logger = logging.getLogger(__name__)


class TLSCertificateManager:
    """Manages TLS certificates for MITM interception"""
    
    def __init__(self, cert_dir: str = "certificates"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.ca_key_path = self.cert_dir / "ca.key"
    
    def ensure_certificate(self):
        """Ensure CA certificate exists, create if not"""
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._generate_ca_certificate()
    
    def _generate_ca_certificate(self):
        """Generate CA certificate and key"""
        # Generate private key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create certificate
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(1)
        cert.get_subject().CN = "Scanner CA"
        cert.get_subject().O = "Scanner Proxy"
        cert.set_issuer(cert.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 years
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        ])
        cert.sign(key, "sha256")
        
        # Save certificate
        with open(self.ca_cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Save key
        with open(self.ca_key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        logger.info(f"Generated CA certificate: {self.ca_cert_path}")
    
    def get_certificate_for_host(self, hostname: str) -> tuple[str, str]:
        """Get or generate certificate for a specific hostname"""
        cert_path = self.cert_dir / f"{hostname.replace('*', '_')}.crt"
        key_path = self.cert_dir / f"{hostname.replace('*', '_')}.key"
        
        if cert_path.exists() and key_path.exists():
            return str(cert_path), str(key_path)
        
        # Generate new certificate for hostname
        self._generate_host_certificate(hostname, cert_path, key_path)
        return str(cert_path), str(key_path)
    
    def _generate_host_certificate(self, hostname: str, cert_path: Path, key_path: Path):
        """Generate certificate for a specific hostname"""
        # Load CA certificate and key
        with open(self.ca_cert_path, 'rb') as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        
        with open(self.ca_key_path, 'rb') as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
        
        # Generate private key for host
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create certificate
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(2)
        cert.get_subject().CN = hostname
        cert.set_issuer(ca_cert.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
        cert.set_pubkey(key)
        
        # Add SAN (Subject Alternative Name) extension
        san_list = [f"DNS:{hostname}"]
        try:
            ipaddress.IPv4Address(hostname)
            san_list.append(f"IP:{hostname}")
        except:
            pass
        
        cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode()),
        ])
        cert.sign(ca_key, "sha256")
        
        # Save certificate
        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Save key
        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        logger.debug(f"Generated certificate for {hostname}")

