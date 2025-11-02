"""
Database models for scanner
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

Base = declarative_base()
db = SQLAlchemy()


class Scan(db.Model):
    """Scan record"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_url = Column(String(500), nullable=False)
    scan_type = Column(String(50), default='full')  # full, passive, active
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), nullable=True)
    
    # Relationships
    vulnerabilities = relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan')
    history = relationship('ScanHistory', back_populates='scan', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_by': self.created_by,
            'vulnerability_count': len(self.vulnerabilities) if self.vulnerabilities else 0,
        }


class Vulnerability(db.Model):
    """Vulnerability finding"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    request_id = Column(Integer, ForeignKey('requests.id'), nullable=True)
    
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    confidence = Column(Float, default=0.0)
    cwe_id = Column(Integer, nullable=True)
    cvss_score = Column(Float, nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    
    # Relationships
    scan = relationship('Scan', back_populates='vulnerabilities')
    request = relationship('Request', back_populates='vulnerabilities')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'request_id': self.request_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'verified': self.verified,
            'false_positive': self.false_positive,
        }


class Request(db.Model):
    """HTTP Request record"""
    __tablename__ = 'requests'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=True)
    
    method = Column(String(10), nullable=False)
    url = Column(String(2000), nullable=False)
    headers = Column(JSON, nullable=True)
    body = Column(Text, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    response = relationship('Response', back_populates='request', uselist=False, cascade='all, delete-orphan')
    vulnerabilities = relationship('Vulnerability', back_populates='request')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }


class Response(db.Model):
    """HTTP Response record"""
    __tablename__ = 'responses'
    
    id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey('requests.id'), nullable=False, unique=True)
    
    status_code = Column(Integer, nullable=False)
    headers = Column(JSON, nullable=True)
    body = Column(Text, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    request = relationship('Request', back_populates='response')
    
    def to_dict(self):
        return {
            'id': self.id,
            'request_id': self.request_id,
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body[:1000] if self.body else None,  # Truncate for JSON
            'body_length': len(self.body) if self.body else 0,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }


class Endpoint(db.Model):
    """Discovered endpoint"""
    __tablename__ = 'endpoints'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=True)
    
    url = Column(String(2000), nullable=False, unique=True)
    method = Column(String(10), nullable=False)
    parameters = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'url': self.url,
            'method': self.method,
            'parameters': self.parameters,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ScanHistory(db.Model):
    """Scan execution history"""
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    action = Column(String(100), nullable=False)  # started, completed, error, etc.
    message = Column(Text, nullable=True)
    metadata = Column(JSON, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship('Scan', back_populates='history')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'action': self.action,
            'message': self.message,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }

