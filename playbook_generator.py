"""
Incident Response Playbook Generator
Auto-generates incident response playbooks and SIEM rules.
"""

from typing import Dict, List
from datetime import datetime


# =========================
# PLAYBOOK GENERATOR
# =========================
class PlaybookGenerator:
    """Generates incident response playbooks."""
    
    def generate_playbook(
        self,
        attack_type: str,
        attack_details: Dict
    ) -> str:
        """Generate incident response playbook."""
        playbook = f"""# Incident Response Playbook: {attack_type}

## Incident Overview
- **Attack Type**: {attack_type}
- **Severity**: {attack_details.get('severity', 'Medium')}
- **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Detection Indicators
"""
        
        for indicator in attack_details.get('indicators', []):
            playbook += f"- {indicator}\n"
        
        playbook += """
## Response Steps

### 1. Containment
"""
        for step in self._get_containment_steps(attack_type):
            playbook += f"- [ ] {step}\n"
        
        playbook += """
### 2. Investigation
"""
        for step in self._get_investigation_steps(attack_type):
            playbook += f"- [ ] {step}\n"
        
        playbook += """
### 3. Remediation
"""
        for step in self._get_remediation_steps(attack_type):
            playbook += f"- [ ] {step}\n"
        
        playbook += """
### 4. Recovery
- [ ] Verify systems are clean
- [ ] Restore from backups if necessary
- [ ] Monitor for re-infection

## Executive Summary Template
**Incident**: {attack_type}  
**Impact**: [Describe impact]  
**Actions Taken**: [List actions]  
**Current Status**: [In Progress/Resolved]  
**Next Steps**: [List next steps]
"""
        
        return playbook
    
    def _get_containment_steps(self, attack_type: str) -> List[str]:
        """Get containment steps for attack type."""
        if "sql" in attack_type.lower():
            return [
                "Block attacker IP address",
                "Disable vulnerable endpoint temporarily",
                "Review database access logs",
                "Change database credentials"
            ]
        elif "xss" in attack_type.lower():
            return [
                "Block attacker IP address",
                "Sanitize affected inputs",
                "Review stored XSS payloads",
                "Clear affected sessions"
            ]
        else:
            return [
                "Block attacker IP address",
                "Isolate affected systems",
                "Preserve evidence",
                "Document timeline"
            ]
    
    def _get_investigation_steps(self, attack_type: str) -> List[str]:
        """Get investigation steps."""
        return [
            "Review all logs for attacker activity",
            "Identify compromised accounts",
            "Determine data accessed/exfiltrated",
            "Check for persistence mechanisms",
            "Analyze attack tools and techniques"
        ]
    
    def _get_remediation_steps(self, attack_type: str) -> List[str]:
        """Get remediation steps."""
        if "sql" in attack_type.lower():
            return [
                "Implement parameterized queries",
                "Enable WAF SQL injection rules",
                "Apply input validation",
                "Update vulnerable components"
            ]
        elif "xss" in attack_type.lower():
            return [
                "Implement output encoding",
                "Enable Content Security Policy",
                "Sanitize all user inputs",
                "Update vulnerable components"
            ]
        else:
            return [
                "Patch vulnerabilities",
                "Update security controls",
                "Implement monitoring",
                "Review security policies"
            ]


# =========================
# SIEM RULE GENERATOR
# =========================
class SIEMRuleGenerator:
    """Generates SIEM detection rules."""
    
    def generate_sigma_rule(
        self,
        attack_type: str,
        patterns: List[str]
    ) -> str:
        """Generate Sigma rule."""
        rule = f"""title: {attack_type} Detection
id: {hash(attack_type)}
status: experimental
description: Detects {attack_type} attacks
author: AI Honeypot
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: webserver
detection:
    selection:
        request:
"""
        
        for pattern in patterns:
            rule += f"            - '*{pattern}*'\n"
        
        rule += """    condition: selection
falsepositives:
    - Unknown
level: high
"""
        
        return rule


# =========================
# GLOBAL INSTANCES
# =========================
_playbook_generator = PlaybookGenerator()
_siem_generator = SIEMRuleGenerator()


def generate_incident_playbook(attack_type: str, attack_details: Dict) -> str:
    """Generate playbook (convenience function)."""
    return _playbook_generator.generate_playbook(attack_type, attack_details)


def generate_sigma_rule(attack_type: str, patterns: List[str]) -> str:
    """Generate Sigma rule (convenience function)."""
    return _siem_generator.generate_sigma_rule(attack_type, patterns)
