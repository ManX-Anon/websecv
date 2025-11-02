"""
Wordlist management for fuzzing
"""

from typing import List
from pathlib import Path
import os


class WordlistManager:
    """Manage wordlists for fuzzing"""
    
    COMMON_WORDS = [
        'admin', 'administrator', 'test', 'password', '123456',
        'root', 'user', 'guest', 'api', 'api_key', 'token',
        'id', 'user_id', 'session', 'session_id', 'login',
        'username', 'email', 'file', 'document', 'path',
        'config', 'settings', 'account', 'profile',
    ]
    
    DIRECTORIES = [
        '/admin', '/api', '/api/v1', '/api/v2', '/login', '/logout',
        '/register', '/signup', '/profile', '/settings', '/config',
        '/backup', '/tmp', '/temp', '/uploads', '/downloads',
        '/test', '/dev', '/staging', '/prod', '/production',
    ]
    
    FILES = [
        '/.env', '/.git/config', '/config.php', '/config.json',
        '/.htaccess', '/web.config', '/robots.txt', '/sitemap.xml',
        '/package.json', '/composer.json', '/README.md',
    ]
    
    def __init__(self, wordlist_dir: str = "wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
        self.wordlist_dir.mkdir(exist_ok=True)
    
    def get_common_words(self) -> List[str]:
        """Get common wordlist"""
        return self.COMMON_WORDS.copy()
    
    def get_directories(self) -> List[str]:
        """Get directory wordlist"""
        return self.DIRECTORIES.copy()
    
    def get_files(self) -> List[str]:
        """Get file wordlist"""
        return self.FILES.copy()
    
    def load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file"""
        file_path = self.wordlist_dir / filename
        
        if not file_path.exists():
            # Try built-in wordlists
            builtin = {
                'common.txt': self.COMMON_WORDS,
                'directories.txt': self.DIRECTORIES,
                'files.txt': self.FILES,
            }
            if filename in builtin:
                return builtin[filename].copy()
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"Error loading wordlist {filename}: {e}")
            return []
    
    def generate_from_target(self, base_url: str, html: str) -> List[str]:
        """Generate wordlist from target"""
        wordlist = set()
        
        # Extract from HTML
        import re
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract from links
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Extract path segments
            segments = href.split('/')
            for segment in segments:
                if segment and not segment.startswith('http'):
                    wordlist.add(segment)
        
        # Extract from JavaScript identifiers
        script_text = '\n'.join([script.string or '' for script in soup.find_all('script')])
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', script_text)
        wordlist.update(identifiers[:100])  # Limit to first 100
        
        return sorted(list(wordlist))

