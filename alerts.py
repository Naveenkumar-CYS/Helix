"""
Automated Alert System
Sends notifications via email, Slack, Discord, and other channels.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import requests
import json


# =========================
# ALERT SEVERITY
# =========================
class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =========================
# ALERT CONFIGURATION
# =========================
@dataclass
class AlertConfig:
    """Configuration for alert system."""
    # Email settings
    email_enabled: bool = False
    email_smtp_server: Optional[str] = None
    email_smtp_port: int = 587
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    email_recipients: List[str] = None
    
    # Slack settings
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    
    # Discord settings
    discord_enabled: bool = False
    discord_webhook_url: Optional[str] = None
    
    # Alert thresholds
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
    rate_limit_seconds: int = 300  # Don't spam alerts


# =========================
# SLACK ALERTER
# =========================
class SlackAlerter:
    """Send alerts to Slack."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send alert to Slack.
        
        Returns:
            True if successful
        """
        # Color based on severity
        colors = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.LOW: "#2196F3",
            AlertSeverity.MEDIUM: "#FFC107",
            AlertSeverity.HIGH: "#FF9800",
            AlertSeverity.CRITICAL: "#F44336",
        }
        
        # Build attachment
        attachment = {
            "color": colors.get(severity, "#808080"),
            "title": f"🚨 {title}",
            "text": message,
            "footer": "AI Honeypot Alert System",
            "ts": int(datetime.now().timestamp())
        }
        
        # Add fields for details
        if details:
            fields = []
            for key, value in details.items():
                fields.append({
                    "title": key.replace('_', ' ').title(),
                    "value": str(value),
                    "short": True
                })
            attachment["fields"] = fields
        
        payload = {
            "attachments": [attachment]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False


# =========================
# DISCORD ALERTER
# =========================
class DiscordAlerter:
    """Send alerts to Discord."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send alert to Discord.
        
        Returns:
            True if successful
        """
        # Color based on severity
        colors = {
            AlertSeverity.INFO: 3066993,    # Green
            AlertSeverity.LOW: 2196243,     # Blue
            AlertSeverity.MEDIUM: 16776960, # Yellow
            AlertSeverity.HIGH: 16753920,   # Orange
            AlertSeverity.CRITICAL: 15158332, # Red
        }
        
        # Build embed
        embed = {
            "title": f"🚨 {title}",
            "description": message,
            "color": colors.get(severity, 8421504),
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": "AI Honeypot Alert System"
            }
        }
        
        # Add fields for details
        if details:
            fields = []
            for key, value in details.items():
                fields.append({
                    "name": key.replace('_', ' ').title(),
                    "value": str(value),
                    "inline": True
                })
            embed["fields"] = fields
        
        payload = {
            "embeds": [embed]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            return response.status_code == 204
        except requests.exceptions.RequestException:
            return False


# =========================
# ALERT MANAGER
# =========================
class AlertManager:
    """Manages alerts across multiple channels."""
    
    def __init__(self, config: Optional[AlertConfig] = None):
        self.config = config or AlertConfig()
        
        # Initialize alerters
        self.slack = None
        if self.config.slack_enabled and self.config.slack_webhook_url:
            self.slack = SlackAlerter(self.config.slack_webhook_url)
        
        self.discord = None
        if self.config.discord_enabled and self.config.discord_webhook_url:
            self.discord = DiscordAlerter(self.config.discord_webhook_url)
        
        # Rate limiting
        self.last_alert_time: Dict[str, datetime] = {}
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        details: Optional[Dict[str, Any]] = None,
        alert_key: Optional[str] = None
    ) -> bool:
        """
        Send alert to all configured channels.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            details: Additional details
            alert_key: Unique key for rate limiting
            
        Returns:
            True if at least one alert sent successfully
        """
        # Check severity threshold
        severity_order = [
            AlertSeverity.INFO,
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL
        ]
        
        if severity_order.index(severity) < severity_order.index(self.config.min_severity):
            return False
        
        # Check rate limiting
        if alert_key:
            if alert_key in self.last_alert_time:
                time_since_last = (datetime.now() - self.last_alert_time[alert_key]).total_seconds()
                if time_since_last < self.config.rate_limit_seconds:
                    return False
            
            self.last_alert_time[alert_key] = datetime.now()
        
        success = False
        
        # Send to Slack
        if self.slack:
            if self.slack.send_alert(title, message, severity, details):
                success = True
        
        # Send to Discord
        if self.discord:
            if self.discord.send_alert(title, message, severity, details):
                success = True
        
        return success
    
    def alert_attack_detected(
        self,
        attack_type: str,
        attacker_id: str,
        ip: str,
        payload: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM
    ) -> bool:
        """Alert for attack detection."""
        return self.send_alert(
            title=f"{attack_type} Detected",
            message=f"Attack detected from {ip}",
            severity=severity,
            details={
                "Attack Type": attack_type,
                "Attacker ID": attacker_id[:16],
                "IP Address": ip,
                "Payload": payload[:100] + "..." if len(payload) > 100 else payload
            },
            alert_key=f"attack_{attacker_id}"
        )
    
    def alert_brute_force(
        self,
        attacker_id: str,
        ip: str,
        attempt_count: int
    ) -> bool:
        """Alert for brute force attack."""
        return self.send_alert(
            title="Brute Force Attack Detected",
            message=f"Brute force attack from {ip}",
            severity=AlertSeverity.HIGH,
            details={
                "Attacker ID": attacker_id[:16],
                "IP Address": ip,
                "Attempts": attempt_count,
                "Status": "Active"
            },
            alert_key=f"brute_force_{attacker_id}"
        )
    
    def alert_coordinated_attack(
        self,
        attacker_id: str,
        ip: str,
        vector_count: int,
        campaign_type: str
    ) -> bool:
        """Alert for coordinated multi-vector attack."""
        return self.send_alert(
            title="Coordinated Attack Campaign",
            message=f"Multi-vector attack campaign from {ip}",
            severity=AlertSeverity.CRITICAL,
            details={
                "Attacker ID": attacker_id[:16],
                "IP Address": ip,
                "Attack Vectors": vector_count,
                "Campaign Type": campaign_type
            },
            alert_key=f"coordinated_{attacker_id}"
        )
    
    def alert_anomaly_detected(
        self,
        attacker_id: str,
        ip: str,
        attack_type: str,
        anomaly_score: float
    ) -> bool:
        """Alert for anomalous attack pattern."""
        return self.send_alert(
            title="Anomalous Attack Detected",
            message=f"Unusual {attack_type} pattern from {ip}",
            severity=AlertSeverity.HIGH,
            details={
                "Attacker ID": attacker_id[:16],
                "IP Address": ip,
                "Attack Type": attack_type,
                "Anomaly Score": f"{anomaly_score:.2f}"
            },
            alert_key=f"anomaly_{attacker_id}_{attack_type}"
        )
    
    def alert_high_threat_ip(
        self,
        ip: str,
        threat_score: int,
        sources: List[str]
    ) -> bool:
        """Alert for high-threat IP."""
        return self.send_alert(
            title="High-Threat IP Detected",
            message=f"Known malicious IP {ip} detected",
            severity=AlertSeverity.CRITICAL,
            details={
                "IP Address": ip,
                "Threat Score": f"{threat_score}/100",
                "Sources": ", ".join(sources)
            },
            alert_key=f"threat_ip_{ip}"
        )


# =========================
# GLOBAL INSTANCE
# =========================
_alert_manager = AlertManager()


def configure_alerts(
    slack_webhook: Optional[str] = None,
    discord_webhook: Optional[str] = None,
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
) -> None:
    """Configure alert system."""
    global _alert_manager
    config = AlertConfig(
        slack_enabled=slack_webhook is not None,
        slack_webhook_url=slack_webhook,
        discord_enabled=discord_webhook is not None,
        discord_webhook_url=discord_webhook,
        min_severity=min_severity
    )
    _alert_manager = AlertManager(config)


def send_attack_alert(
    attack_type: str,
    attacker_id: str,
    ip: str,
    payload: str,
    severity: AlertSeverity = AlertSeverity.MEDIUM
) -> bool:
    """Send attack alert (convenience function)."""
    return _alert_manager.alert_attack_detected(attack_type, attacker_id, ip, payload, severity)


def send_brute_force_alert(attacker_id: str, ip: str, attempt_count: int) -> bool:
    """Send brute force alert (convenience function)."""
    return _alert_manager.alert_brute_force(attacker_id, ip, attempt_count)


def send_coordinated_attack_alert(
    attacker_id: str,
    ip: str,
    vector_count: int,
    campaign_type: str
) -> bool:
    """Send coordinated attack alert (convenience function)."""
    return _alert_manager.alert_coordinated_attack(attacker_id, ip, vector_count, campaign_type)


def send_anomaly_alert(
    attacker_id: str,
    ip: str,
    attack_type: str,
    anomaly_score: float
) -> bool:
    """Send anomaly alert (convenience function)."""
    return _alert_manager.alert_anomaly_detected(attacker_id, ip, attack_type, anomaly_score)


def send_threat_ip_alert(ip: str, threat_score: int, sources: List[str]) -> bool:
    """Send high-threat IP alert (convenience function)."""
    return _alert_manager.alert_high_threat_ip(ip, threat_score, sources)
