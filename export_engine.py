"""
Export Engine
Exports honeypot data in multiple formats (CSV, JSON, PDF).
"""

from typing import Dict, List, Any
from datetime import datetime
import json
import csv
from io import StringIO


# =========================
# EXPORT ENGINE
# =========================
class ExportEngine:
    """Exports data in multiple formats."""
    
    def export_to_json(self, data: Any, pretty: bool = True) -> str:
        """Export data to JSON."""
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)
    
    def export_to_csv(self, data: List[Dict], filename: str = "export.csv") -> str:
        """Export data to CSV."""
        if not data:
            return ""
        
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()
    
    def export_attack_log(self, attacks: List[Dict]) -> str:
        """Export attack log to CSV."""
        formatted_attacks = []
        for attack in attacks:
            formatted_attacks.append({
                "timestamp": attack.get("timestamp", ""),
                "attacker_id": attack.get("attacker_id", ""),
                "ip": attack.get("ip", ""),
                "attack_type": attack.get("attack_type", ""),
                "endpoint": attack.get("endpoint", ""),
                "payload": attack.get("payload", "")[:100],  # Truncate
                "success": attack.get("success", False)
            })
        
        return self.export_to_csv(formatted_attacks)
    
    def export_statistics(self, stats: Dict) -> str:
        """Export statistics to formatted text."""
        output = f"""# Honeypot Statistics Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview
- Total Attacks: {stats.get('total_attacks', 0)}
- Unique Attackers: {stats.get('unique_attackers', 0)}
- Attack Types: {stats.get('attack_types_count', 0)}

## Top Attack Types
"""
        
        for attack_type, count in stats.get('top_attack_types', []):
            output += f"- {attack_type}: {count}\n"
        
        output += "\n## Top Attackers\n"
        for attacker_id, count in stats.get('top_attackers', []):
            output += f"- {attacker_id}: {count} attacks\n"
        
        return output


# =========================
# GLOBAL INSTANCE
# =========================
_export_engine = ExportEngine()


def export_json(data: Any) -> str:
    """Export to JSON (convenience function)."""
    return _export_engine.export_to_json(data)


def export_csv(data: List[Dict]) -> str:
    """Export to CSV (convenience function)."""
    return _export_engine.export_to_csv(data)


def export_attacks(attacks: List[Dict]) -> str:
    """Export attacks (convenience function)."""
    return _export_engine.export_attack_log(attacks)
