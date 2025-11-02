"""
Profile manager
"""

from typing import List, Optional, Dict, Any
from pathlib import Path
import json
from .profiles import ScanProfile, QuickProfile, FullProfile, CustomProfile


class ProfileManager:
    """Manage scan profiles"""
    
    def __init__(self, profiles_dir: str = "profiles"):
        self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(exist_ok=True)
        self.profiles: Dict[str, ScanProfile] = {}
        self._load_default_profiles()
    
    def _load_default_profiles(self):
        """Load default profiles"""
        self.profiles['quick'] = QuickProfile()
        self.profiles['full'] = FullProfile()
    
    def get_profile(self, name: str) -> Optional[ScanProfile]:
        """Get profile by name"""
        return self.profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """List available profiles"""
        return list(self.profiles.keys())
    
    def create_profile(self, name: str, description: str, config: Dict[str, Any]) -> CustomProfile:
        """Create custom profile"""
        profile = CustomProfile(name, description, config)
        self.profiles[name] = profile
        self.save_profile(profile)
        return profile
    
    def save_profile(self, profile: ScanProfile):
        """Save profile to file"""
        if isinstance(profile, CustomProfile):
            profile_data = {
                'name': profile.name,
                'description': profile.description,
                'config': profile.config_dict,
            }
            
            file_path = self.profiles_dir / f"{profile.name}.json"
            with open(file_path, 'w') as f:
                json.dump(profile_data, f, indent=2)
    
    def load_profile(self, file_path: Path) -> Optional[CustomProfile]:
        """Load profile from file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            profile = CustomProfile(
                data['name'],
                data['description'],
                data.get('config', {})
            )
            self.profiles[profile.name] = profile
            return profile
        except Exception as e:
            print(f"Error loading profile {file_path}: {e}")
            return None

