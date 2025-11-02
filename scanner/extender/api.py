"""
Extender API for plugin development
"""

import logging
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod

from scanner.core.interfaces import IProxy, ICrawler, IScanner, HttpRequest, HttpResponse, Vulnerability
from .plugin import Plugin, PluginContext

logger = logging.getLogger(__name__)


class ExtenderAPI:
    """Extender API for plugin development"""
    
    def __init__(
        self,
        proxy: Optional[IProxy] = None,
        crawler: Optional[ICrawler] = None,
        scanner: Optional[IScanner] = None
    ):
        self.proxy = proxy
        self.crawler = crawler
        self.scanner = scanner
        self.plugins: List[Plugin] = []
    
    def register_plugin(self, plugin: Plugin):
        """Register a plugin"""
        context = PluginContext(
            proxy=self.proxy,
            crawler=self.crawler,
            scanner=self.scanner
        )
        plugin.initialize(context)
        self.plugins.append(plugin)
        logger.info(f"Registered plugin: {plugin.get_name()}")
    
    def unregister_plugin(self, plugin: Plugin):
        """Unregister a plugin"""
        if plugin in self.plugins:
            plugin.cleanup()
            self.plugins.remove(plugin)
            logger.info(f"Unregistered plugin: {plugin.get_name()}")
    
    def get_plugins(self) -> List[Plugin]:
        """Get all registered plugins"""
        return self.plugins.copy()
    
    def call_plugins(self, event: str, data: Dict[str, Any]) -> List[Any]:
        """Call plugins with an event"""
        results = []
        for plugin in self.plugins:
            try:
                result = plugin.handle_event(event, data)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error in plugin {plugin.get_name()}: {e}")
        return results

