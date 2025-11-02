"""
Storage abstractions for scanner data
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import sqlite3
import json
from scanner.core.interfaces import HttpRequest, HttpResponse, Vulnerability, HttpMethod, Severity


class Storage(ABC):
    """Storage interface"""
    
    @abstractmethod
    def save_request_response(self, request: HttpRequest, response: HttpResponse):
        """Save request/response pair"""
        pass
    
    @abstractmethod
    def get_history(self, limit: Optional[int] = None) -> List[tuple[HttpRequest, HttpResponse]]:
        """Get request/response history"""
        pass
    
    @abstractmethod
    def save_vulnerability(self, vuln: Vulnerability):
        """Save vulnerability finding"""
        pass
    
    @abstractmethod
    def get_vulnerabilities(self, severity: Optional[str] = None) -> List[Vulnerability]:
        """Get vulnerability findings"""
        pass


class DatabaseStorage(Storage):
    """SQLite-based storage implementation"""
    
    def __init__(self, db_path: str = "scanner.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Request/Response history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT,
                url TEXT,
                headers TEXT,
                body BLOB,
                timestamp REAL,
                response_status INTEGER,
                response_headers TEXT,
                response_body BLOB,
                response_timestamp REAL
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                description TEXT,
                severity TEXT,
                confidence REAL,
                request_id INTEGER,
                evidence TEXT,
                remediation TEXT,
                cwe_id INTEGER,
                cvss_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
        """)
        
        # Endpoints discovered by crawler
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                method TEXT,
                parameters TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_request_response(self, request: HttpRequest, response: HttpResponse):
        """Save request/response pair"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO requests (method, url, headers, body, timestamp,
                                 response_status, response_headers, response_body, response_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.method.value,
            request.url,
            json.dumps(request.headers),
            request.body,
            request.timestamp or datetime.now().timestamp(),
            response.status_code,
            json.dumps(response.headers),
            response.body,
            response.timestamp or datetime.now().timestamp(),
        ))
        
        conn.commit()
        conn.close()
    
    def get_history(self, limit: Optional[int] = None) -> List[tuple[HttpRequest, HttpResponse]]:
        """Get request/response history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM requests ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            request = HttpRequest(
                method=HttpMethod(row[1]),
                url=row[2],
                headers=json.loads(row[3]),
                body=row[4],
                timestamp=row[5],
            )
            response = HttpResponse(
                status_code=row[6],
                headers=json.loads(row[7]),
                body=row[8],
                timestamp=row[9],
            )
            results.append((request, response))
        
        return results
    
    def save_vulnerability(self, vuln: Vulnerability):
        """Save vulnerability finding"""
        # First save the request/response if not exists
        self.save_request_response(vuln.request, vuln.response)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get the request ID
        cursor.execute("SELECT id FROM requests WHERE url = ? AND timestamp = ?",
                      (vuln.request.url, vuln.request.timestamp))
        request_id = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO vulnerabilities (title, description, severity, confidence,
                                        request_id, evidence, remediation, cwe_id, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln.title,
            vuln.description,
            vuln.severity.value,
            vuln.confidence,
            request_id,
            vuln.evidence,
            vuln.remediation,
            vuln.cwe_id,
            vuln.cvss_score,
        ))
        
        conn.commit()
        conn.close()
    
    def get_vulnerabilities(self, severity: Optional[str] = None) -> List[Vulnerability]:
        """Get vulnerability findings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if severity:
            cursor.execute("""
                SELECT v.*, r.method, r.url, r.headers, r.body, r.timestamp,
                       r.response_status, r.response_headers, r.response_body, r.response_timestamp
                FROM vulnerabilities v
                JOIN requests r ON v.request_id = r.id
                WHERE v.severity = ?
                ORDER BY v.created_at DESC
            """, (severity,))
        else:
            cursor.execute("""
                SELECT v.*, r.method, r.url, r.headers, r.body, r.timestamp,
                       r.response_status, r.response_headers, r.response_body, r.response_timestamp
                FROM vulnerabilities v
                JOIN requests r ON v.request_id = r.id
                ORDER BY v.created_at DESC
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            request = HttpRequest(
                method=HttpMethod(row[11]),
                url=row[12],
                headers=json.loads(row[13]),
                body=row[14],
                timestamp=row[15],
            )
            response = HttpResponse(
                status_code=row[16],
                headers=json.loads(row[17]),
                body=row[18],
                timestamp=row[19],
            )
            
            vuln = Vulnerability(
                title=row[1],
                description=row[2],
                severity=Severity(row[3]),
                confidence=row[4],
                request=request,
                response=response,
                evidence=row[6],
                remediation=row[7],
                cwe_id=row[8],
                cvss_score=row[9],
            )
            results.append(vuln)
        
        return results

