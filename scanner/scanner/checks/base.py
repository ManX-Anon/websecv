"""
Base classes for vulnerability checks
"""

from abc import ABC, abstractmethod
from typing import Optional

from scanner.core.interfaces import IVulnCheck, HttpRequest, HttpResponse, Vulnerability


class PassiveCheck(IVulnCheck, ABC):
    """Base class for passive vulnerability checks"""
    
    @abstractmethod
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check request/response for vulnerability (no additional requests made)"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get check name"""
        pass


class ActiveCheck(IVulnCheck, ABC):
    """Base class for active vulnerability checks"""
    
    @abstractmethod
    def check(self, request: HttpRequest, response: HttpResponse) -> Optional[Vulnerability]:
        """Check request/response for vulnerability (may make additional requests)"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get check name"""
        pass

