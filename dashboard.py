"""
Real-Time Dashboard for AI Honeypot
Web-based dashboard with live attack feed, statistics, and visualization.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
import asyncio
from collections import defaultdict, Counter


# =========================
# DASHBOARD DATA AGGREGATOR
# =========================
class DashboardDataAggregator:
    """Aggregates data for dashboard display."""
    
    def __init__(self):
        self.recent_attacks: List[Dict[str, Any]] = []
        self.attack_stats = defaultdict(int)
        self.attacker_stats = defaultdict(int)
        self.endpoint_stats = defaultdict(int)
        self.skill_level_stats = defaultdict(int)
        self.country_stats = defaultdict(int)
        
        # WebSocket connections
        self.active_connections: List[WebSocket] = []
    
    def add_attack(self, attack_data: Dict[str, Any]) -> None:
        """Add new attack to dashboard."""
        # Add to recent attacks (keep last 100)
        self.recent_attacks.insert(0, attack_data)
        if len(self.recent_attacks) > 100:
            self.recent_attacks.pop()
        
        # Update statistics
        attack_type = attack_data.get("attack_type", "UNKNOWN")
        self.attack_stats[attack_type] += 1
        
        attacker_id = attack_data.get("attacker_id", "unknown")
        self.attacker_stats[attacker_id] += 1
        
        endpoint = attack_data.get("endpoint", "unknown")
        self.endpoint_stats[endpoint] += 1
        
        skill_level = attack_data.get("skill_level", "unknown")
        self.skill_level_stats[skill_level] += 1
        
        country = attack_data.get("country", "unknown")
        self.country_stats[country] += 1
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get all dashboard data."""
        return {
            "recent_attacks": self.recent_attacks[:20],  # Last 20 attacks
            "total_attacks": sum(self.attack_stats.values()),
            "unique_attackers": len(self.attacker_stats),
            "attack_type_distribution": dict(self.attack_stats),
            "endpoint_distribution": dict(self.endpoint_stats),
            "skill_level_distribution": dict(self.skill_level_stats),
            "country_distribution": dict(self.country_stats),
            "top_attackers": self._get_top_attackers(),
            "attack_timeline": self._get_attack_timeline(),
        }
    
    def _get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attackers by attack count."""
        return [
            {"attacker_id": attacker_id, "count": count}
            for attacker_id, count in sorted(
                self.attacker_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
        ]
    
    def _get_attack_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack timeline for last N hours."""
        # Group attacks by hour
        timeline = defaultdict(int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for attack in self.recent_attacks:
            timestamp_str = attack.get("timestamp")
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                    if timestamp > cutoff:
                        hour_key = timestamp.strftime("%Y-%m-%d %H:00")
                        timeline[hour_key] += 1
                except:
                    pass
        
        return [
            {"time": time, "count": count}
            for time, count in sorted(timeline.items())
        ]
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all connected WebSocket clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.active_connections.remove(connection)


# =========================
# GLOBAL INSTANCE
# =========================
_dashboard = DashboardDataAggregator()



def add_attack_to_dashboard(attack_data: Dict[str, Any]) -> None:
    """Add attack to dashboard (convenience function)."""
    _dashboard.add_attack(attack_data)


def get_dashboard_stats() -> Dict[str, Any]:
    """Get dashboard statistics (convenience function)."""
    return _dashboard.get_dashboard_data()


async def broadcast_attack(attack_data: Dict[str, Any]) -> None:
    """Broadcast attack to dashboard (convenience function)."""
    await _dashboard.broadcast({
        "type": "attack",
        "attack": attack_data
    })


async def broadcast_stats() -> None:
    """Broadcast stats to dashboard (convenience function)."""
    stats = _dashboard.get_dashboard_data()
    stats["active_now"] = len(_dashboard.active_connections)
    await _dashboard.broadcast({
        "type": "stats",
        "stats": stats
    })


def get_active_connections() -> List[WebSocket]:
    """Get active WebSocket connections."""
    return _dashboard.active_connections
