"""
Schedule scans for automated execution
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from scanner.database.models import Scan
from scanner.scanner.engine import ScanEngine
from scanner.core.config import Config
import logging

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Schedule and manage automated scans"""
    
    def __init__(self):
        self.scheduled_scans: List[Dict[str, Any]] = []
    
    def schedule_scan(
        self,
        target_url: str,
        schedule_type: str = 'daily',  # daily, weekly, monthly, custom
        time: Optional[str] = None,
        profile: str = 'full'
    ) -> Dict[str, Any]:
        """Schedule a scan"""
        schedule = {
            'id': len(self.scheduled_scans) + 1,
            'target_url': target_url,
            'schedule_type': schedule_type,
            'time': time or '00:00',
            'profile': profile,
            'enabled': True,
            'next_run': self._calculate_next_run(schedule_type, time),
            'created_at': datetime.now(),
        }
        
        self.scheduled_scans.append(schedule)
        logger.info(f"Scheduled scan for {target_url}: {schedule_type} at {time}")
        return schedule
    
    def _calculate_next_run(self, schedule_type: str, time: str = None) -> datetime:
        """Calculate next run time"""
        now = datetime.now()
        
        if schedule_type == 'daily':
            next_run = now.replace(hour=int(time.split(':')[0]) if time else 0,
                                  minute=int(time.split(':')[1]) if time and ':' in time else 0,
                                  second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        elif schedule_type == 'weekly':
            next_run = now + timedelta(days=7)
        elif schedule_type == 'monthly':
            next_run = now + timedelta(days=30)
        else:
            next_run = now + timedelta(days=1)
        
        return next_run
    
    def get_due_scans(self) -> List[Dict[str, Any]]:
        """Get scans that are due to run"""
        now = datetime.now()
        due = []
        
        for schedule in self.scheduled_scans:
            if schedule['enabled'] and schedule['next_run'] <= now:
                due.append(schedule)
        
        return due
    
    def disable_schedule(self, schedule_id: int):
        """Disable a scheduled scan"""
        for schedule in self.scheduled_scans:
            if schedule['id'] == schedule_id:
                schedule['enabled'] = False
                logger.info(f"Disabled schedule {schedule_id}")
                return True
        return False

