"""
Scan profiles for different scanning strategies
"""

from typing import List, Dict, Any
from scanner.core.config import ScannerConfig, CrawlerConfig


class ScanProfile:
    """Base scan profile"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def get_scanner_config(self) -> ScannerConfig:
        """Get scanner configuration for this profile"""
        return ScannerConfig()
    
    def get_crawler_config(self) -> CrawlerConfig:
        """Get crawler configuration for this profile"""
        return CrawlerConfig()


class QuickProfile(ScanProfile):
    """Quick scan profile - fast, minimal checks"""
    
    def __init__(self):
        super().__init__('quick', 'Quick scan with essential checks only')
    
    def get_scanner_config(self) -> ScannerConfig:
        config = ScannerConfig()
        config.active_checks = False  # Only passive checks
        config.passive_checks = True
        config.max_concurrent_checks = 5
        return config
    
    def get_crawler_config(self) -> CrawlerConfig:
        config = CrawlerConfig()
        config.max_depth = 3
        config.max_pages = 50
        config.use_headless_browser = False
        return config


class FullProfile(ScanProfile):
    """Full scan profile - comprehensive, thorough checks"""
    
    def __init__(self):
        super().__init__('full', 'Comprehensive scan with all checks')
    
    def get_scanner_config(self) -> ScannerConfig:
        config = ScannerConfig()
        config.active_checks = True
        config.passive_checks = True
        config.max_concurrent_checks = 10
        return config
    
    def get_crawler_config(self) -> CrawlerConfig:
        config = CrawlerConfig()
        config.max_depth = 10
        config.max_pages = 1000
        config.use_headless_browser = True
        config.wait_for_spa = True
        return config


class CustomProfile(ScanProfile):
    """Custom scan profile"""
    
    def __init__(self, name: str, description: str, config_dict: Dict[str, Any]):
        super().__init__(name, description)
        self.config_dict = config_dict
    
    def get_scanner_config(self) -> ScannerConfig:
        config = ScannerConfig()
        
        if 'active_checks' in self.config_dict:
            config.active_checks = self.config_dict['active_checks']
        if 'passive_checks' in self.config_dict:
            config.passive_checks = self.config_dict['passive_checks']
        if 'max_concurrent_checks' in self.config_dict:
            config.max_concurrent_checks = self.config_dict['max_concurrent_checks']
        
        return config
    
    def get_crawler_config(self) -> CrawlerConfig:
        config = CrawlerConfig()
        
        if 'max_depth' in self.config_dict:
            config.max_depth = self.config_dict['max_depth']
        if 'max_pages' in self.config_dict:
            config.max_pages = self.config_dict['max_pages']
        if 'use_headless_browser' in self.config_dict:
            config.use_headless_browser = self.config_dict['use_headless_browser']
        
        return config

