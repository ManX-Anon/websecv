"""
Plugin base class and context
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

from scanner.core.interfaces import IProxy, ICrawler, IScanner, IPlugin

logger = logging.getLogger(__name__)


@dataclass
class PluginContext:
    """Context provided to plugins"""
    proxy: Optional[IProxy] = None
    crawler: Optional[ICrawler] = None
    scanner: Optional[IScanner] = None
    
    def get_proxy(self) -> Optional[IProxy]:
        """Get proxy instance"""
        return self.proxy
    
    def get_crawler(self) -> Optional[ICrawler]:
        """Get crawler instance"""
        return self.crawler
    
    def get_scanner(self) -> Optional[IScanner]:
        """Get scanner instance"""
        return self.scanner


class Plugin(IPlugin, ABC):
    """Base class for plugins"""
    
    def __init__(self):
        self.context: Optional[PluginContext] = None
        self.initialized = False
    
    @abstractmethod
    def get_name(self) -> str:
        """Get plugin name"""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Get plugin version"""
        pass
    
    def initialize(self, context: PluginContext):
        """Initialize plugin with context"""
        self.context = context
        self.initialized = True
        logger.info(f"Initialized plugin: {self.get_name()}")
    
    def cleanup(self):
        """Cleanup plugin resources"""
        self.initialized = False
        logger.info(f"Cleaned up plugin: {self.get_name()}")
    
    def handle_event(self, event: str, data: Dict[str, Any]) -> Optional[Any]:
        """Handle an event"""
        if not self.initialized:
            return None
        
        # Override in subclasses to handle events
        return None
    
    def get_context(self) -> Optional[PluginContext]:
        """Get plugin context"""
        return self.context

