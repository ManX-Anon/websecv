"""
Core architecture components and interfaces
"""

from .interfaces import IProxy, ICrawler, IScanner, IPlugin
from .config import Config, load_config
from .storage import Storage, DatabaseStorage

__all__ = [
    'IProxy',
    'ICrawler', 
    'IScanner',
    'IPlugin',
    'Config',
    'load_config',
    'Storage',
    'DatabaseStorage',
]

