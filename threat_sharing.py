"""
Threat Intelligence Sharing Engine
Exports threat data in STIX, IOC, and other standard formats.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json


# =========================
# IOC GENERATOR
# =========================
class IOCGenerator:
    """Generates Indicators of Compromise."""
    
    def generate_iocs(
        self,
        attacker_id: str,
        ip_addresses: List[str],
        attack_types: List[str],
        payloads: List[str]
    ) -> Dict:
        """Generate IOCs for an attacker."""
        iocs = {
            "attacker_id": attacker_id,
            "generated_at": datetime.now().isoformat(),
            "ioc_version": "1.0",
            "indicators": []
        }
        
        # IP indicators
        for ip in ip_addresses:
            iocs["indicators"].append({
                "type": "ipv4-addr",
                "value": ip,
                "confidence": "high",
                "description": f"Malicious IP associated with {attacker_id}"
            })
        
        # Payload indicators (hashes)
        for payload in payloads:
            iocs["indicators"].append({
                "type": "pattern",
                "value": payload[:100],  # Truncate
                "confidence": "medium",
                "description": "Attack payload pattern"
            })
        
        return iocs
    
    def export_to_csv(self, iocs: Dict) -> str:
        """Export IOCs to CSV format."""
        csv = "type,value,confidence,description\n"
        for indicator in iocs["indicators"]:
            csv += f"{indicator['type']},{indicator['value']},{indicator['confidence']},{indicator['description']}\n"
        return csv


# =========================
# STIX GENERATOR
# =========================
class STIXGenerator:
    """Generates STIX 2.1 threat intelligence."""
    
    def generate_stix_bundle(
        self,
        attacker_id: str,
        attack_data: Dict
    ) -> Dict:
        """Generate STIX 2.1 bundle."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{attacker_id}",
            "objects": []
        }
        
        # Threat Actor
        threat_actor = {
            "type": "threat-actor",
            "id": f"threat-actor--{attacker_id}",
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "name": f"Attacker-{attacker_id[:8]}",
            "description": "Threat actor detected by AI honeypot",
            "threat_actor_types": ["hacker"],
            "sophistication": attack_data.get("skill_level", "intermediate")
        }
        bundle["objects"].append(threat_actor)
        
        # Attack Pattern
        for attack_type in attack_data.get("attack_types", []):
            attack_pattern = {
                "type": "attack-pattern",
                "id": f"attack-pattern--{hash(attack_type)}",
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "name": attack_type,
                "description": f"{attack_type} attack observed"
            }
            bundle["objects"].append(attack_pattern)
        
        return bundle


# =========================
# THREAT REPORT GENERATOR
# =========================
class ThreatReportGenerator:
    """Generates threat intelligence reports."""
    
    def generate_markdown_report(
        self,
        attacker_id: str,
        attack_summary: Dict
    ) -> str:
        """Generate markdown threat report."""
        report = f"""# Threat Intelligence Report

## Attacker Profile
- **Attacker ID**: {attacker_id}
- **First Seen**: {attack_summary.get('first_seen', 'Unknown')}
- **Last Seen**: {attack_summary.get('last_seen', 'Unknown')}
- **Skill Level**: {attack_summary.get('skill_level', 'Unknown')}

## Attack Summary
- **Total Attacks**: {attack_summary.get('total_attacks', 0)}
- **Attack Types**: {', '.join(attack_summary.get('attack_types', []))}
- **Success Rate**: {attack_summary.get('success_rate', '0%')}

## Indicators of Compromise
"""
        
        for ioc in attack_summary.get('iocs', []):
            report += f"- {ioc['type']}: `{ioc['value']}`\n"
        
        report += "\n## Recommended Actions\n"
        for action in attack_summary.get('recommendations', []):
            report += f"- {action}\n"
        
        return report


# =========================
# GLOBAL INSTANCES
# =========================
_ioc_generator = IOCGenerator()
_stix_generator = STIXGenerator()
_report_generator = ThreatReportGenerator()


def generate_iocs(attacker_id: str, ip_addresses: List[str], attack_types: List[str], payloads: List[str]) -> Dict:
    """Generate IOCs (convenience function)."""
    return _ioc_generator.generate_iocs(attacker_id, ip_addresses, attack_types, payloads)


def generate_stix_bundle(attacker_id: str, attack_data: Dict) -> Dict:
    """Generate STIX bundle (convenience function)."""
    return _stix_generator.generate_stix_bundle(attacker_id, attack_data)


def generate_threat_report(attacker_id: str, attack_summary: Dict) -> str:
    """Generate threat report (convenience function)."""
    return _report_generator.generate_markdown_report(attacker_id, attack_summary)
