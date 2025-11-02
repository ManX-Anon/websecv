"""
Configuration management
"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: str = "127.0.0.1"
    port: int = 8080
    tls_intercept: bool = True
    ca_cert_path: Optional[str] = None
    ca_key_path: Optional[str] = None
    intercept_all: bool = False
    exclude_domains: list = field(default_factory=list)


@dataclass
class CrawlerConfig:
    """Crawler configuration"""
    respect_robots_txt: bool = True
    max_depth: int = 10
    max_pages: int = 1000
    follow_external_links: bool = False
    user_agent: str = "Scanner/1.0"
    delay_between_requests: float = 0.5
    timeout: int = 30
    use_headless_browser: bool = True
    wait_for_spa: bool = True
    spa_wait_time: int = 3


@dataclass
class ScannerConfig:
    """Scanner configuration"""
    active_checks: bool = True
    passive_checks: bool = True
    check_timeout: int = 30
    max_concurrent_checks: int = 10
    custom_wordlists: list = field(default_factory=list)
    excluded_paths: list = field(default_factory=list)


@dataclass
class IntruderConfig:
    """Intruder configuration"""
    max_threads: int = 10
    rate_limit: float = 0.1  # seconds between requests
    timeout: int = 30
    follow_redirects: bool = True


@dataclass
class Config:
    """Main configuration"""
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    intruder: IntruderConfig = field(default_factory=IntruderConfig)
    storage_path: str = "scans"
    log_level: str = "INFO"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "proxy": self.proxy.__dict__,
            "crawler": self.crawler.__dict__,
            "scanner": self.scanner.__dict__,
            "intruder": self.intruder.__dict__,
            "storage_path": self.storage_path,
            "log_level": self.log_level,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create from dictionary"""
        config = cls()
        if "proxy" in data:
            config.proxy = ProxyConfig(**data["proxy"])
        if "crawler" in data:
            config.crawler = CrawlerConfig(**data["crawler"])
        if "scanner" in data:
            config.scanner = ScannerConfig(**data["scanner"])
        if "intruder" in data:
            config.intruder = IntruderConfig(**data["intruder"])
        if "storage_path" in data:
            config.storage_path = data["storage_path"]
        if "log_level" in data:
            config.log_level = data["log_level"]
        return config
    
    def save(self, path: Path):
        """Save configuration to file"""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            if path.suffix == '.yaml' or path.suffix == '.yml':
                yaml.dump(self.to_dict(), f, default_flow_style=False)
            else:
                json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> 'Config':
        """Load configuration from file"""
        with open(path, 'r') as f:
            if path.suffix == '.yaml' or path.suffix == '.yml':
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        return cls.from_dict(data)


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or return default"""
    if config_path:
        path = Path(config_path)
        if path.exists():
            return Config.load(path)
    
    # Try default locations
    default_paths = [
        Path("config.yaml"),
        Path("config.yml"),
        Path("config.json"),
        Path.home() / ".scanner" / "config.yaml",
    ]
    
    for path in default_paths:
        if path.exists():
            return Config.load(path)
    
    # Return default configuration
    return Config()

