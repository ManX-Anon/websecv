"""
Plugin loader for dynamic plugin loading
"""

import logging
import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import List, Dict, Any, Optional

from .plugin import Plugin

logger = logging.getLogger(__name__)


class PluginLoader:
    """Load plugins from files or directories"""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.loaded_plugins: Dict[str, Plugin] = {}
    
    def load_plugin(self, plugin_path: Path) -> Plugin:
        """Load a plugin from a file"""
        try:
            # Import module
            spec = importlib.util.spec_from_file_location(plugin_path.stem, plugin_path)
            if spec is None or spec.loader is None:
                raise ValueError(f"Could not load plugin: {plugin_path}")
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find Plugin subclass
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and
                    issubclass(obj, Plugin) and
                    obj != Plugin):
                    plugin = obj()
                    plugin_name = plugin.get_name()
                    self.loaded_plugins[plugin_name] = plugin
                    logger.info(f"Loaded plugin: {plugin_name} from {plugin_path}")
                    return plugin
            
            raise ValueError(f"No Plugin subclass found in {plugin_path}")
        
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_path}: {e}")
            raise
    
    def load_plugins_from_directory(self, directory: Optional[Path] = None) -> List[Plugin]:
        """Load all plugins from a directory"""
        directory = directory or self.plugin_dir
        
        if not directory.exists():
            logger.warning(f"Plugin directory does not exist: {directory}")
            return []
        
        plugins = []
        for plugin_file in directory.glob("*.py"):
            if plugin_file.name == "__init__.py":
                continue
            
            try:
                plugin = self.load_plugin(plugin_file)
                plugins.append(plugin)
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")
        
        return plugins
    
    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a loaded plugin by name"""
        return self.loaded_plugins.get(name)
    
    def get_all_plugins(self) -> List[Plugin]:
        """Get all loaded plugins"""
        return list(self.loaded_plugins.values())

