"""
Multi-Vector Attack Correlation Engine
Tracks and correlates attacks across multiple endpoints and vectors.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


# =========================
# ENUMS
# =========================
class AttackVector(Enum):
    """Attack vector types."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SESSION_HIJACKING = "session_hijacking"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BRUTE_FORCE = "brute_force"


class CampaignType(Enum):
    """Attack campaign classification."""
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"


# =========================
# DATA MODELS
# =========================
@dataclass
class AttackAction:
    """Single attack action in a campaign."""
    timestamp: datetime
    endpoint: str
    vector: AttackVector
    payload: str
    success: bool = False
    data_leaked: Optional[str] = None


@dataclass
class AttackCampaign:
    """Coordinated attack campaign across multiple vectors."""
    campaign_id: str
    attacker_id: str
    campaign_type: CampaignType
    actions: List[AttackAction] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    endpoints_targeted: Set[str] = field(default_factory=set)
    vectors_used: Set[AttackVector] = field(default_factory=set)
    credentials_extracted: List[str] = field(default_factory=list)
    sessions_hijacked: List[str] = field(default_factory=list)
    
    def add_action(self, action: AttackAction) -> None:
        """Add action to campaign."""
        self.actions.append(action)
        self.last_activity = action.timestamp
        self.endpoints_targeted.add(action.endpoint)
        self.vectors_used.add(action.vector)
    
    def get_timeline(self) -> str:
        """Get formatted timeline of campaign."""
        timeline = []
        for action in self.actions:
            status = "✓" if action.success else "✗"
            timeline.append(
                f"[{action.timestamp.strftime('%H:%M:%S')}] {status} "
                f"{action.vector.value} on {action.endpoint}"
            )
        return "\n".join(timeline)


@dataclass
class CredentialUsage:
    """Tracks where extracted credentials are used."""
    credential: str
    extracted_from: str
    extracted_at: datetime
    usage_attempts: List[Dict[str, any]] = field(default_factory=list)
    
    def add_usage(self, endpoint: str, success: bool) -> None:
        """Record credential usage attempt."""
        self.usage_attempts.append({
            "timestamp": datetime.now(),
            "endpoint": endpoint,
            "success": success
        })


# =========================
# CORRELATION ENGINE
# =========================
class CorrelationEngine:
    """Correlates attacks across endpoints and vectors."""
    
    def __init__(self):
        self.campaigns: Dict[str, AttackCampaign] = {}
        self.credential_tracking: Dict[str, CredentialUsage] = {}
        self.session_tracking: Dict[str, Dict[str, any]] = {}
    
    def detect_campaign_type(self, actions: List[AttackAction]) -> CampaignType:
        """
        Detect campaign type based on attack patterns.
        
        Args:
            actions: List of attack actions
            
        Returns:
            Detected campaign type
        """
        if len(actions) < 2:
            return CampaignType.RECONNAISSANCE
        
        # Check for data exfiltration pattern
        if any(action.data_leaked for action in actions):
            return CampaignType.DATA_EXFILTRATION
        
        # Check for privilege escalation (admin endpoint after SQLi)
        endpoints = [action.endpoint for action in actions]
        if "/admin" in endpoints and any(
            action.vector == AttackVector.SQL_INJECTION for action in actions
        ):
            return CampaignType.PRIVILEGE_ESCALATION
        
        # Check for exploitation (successful attacks)
        if any(action.success for action in actions):
            return CampaignType.EXPLOITATION
        
        # Default to reconnaissance
        return CampaignType.RECONNAISSANCE
    
    def track_attack(
        self,
        attacker_id: str,
        endpoint: str,
        vector: AttackVector,
        payload: str,
        success: bool = False,
        data_leaked: Optional[str] = None
    ) -> AttackCampaign:
        """
        Track an attack and correlate with existing campaigns.
        
        Args:
            attacker_id: Unique attacker identifier
            endpoint: Target endpoint
            vector: Attack vector used
            payload: Attack payload
            success: Whether attack succeeded
            data_leaked: Any data that was leaked
            
        Returns:
            Updated or new attack campaign
        """
        # Create attack action
        action = AttackAction(
            timestamp=datetime.now(),
            endpoint=endpoint,
            vector=vector,
            payload=payload,
            success=success,
            data_leaked=data_leaked
        )
        
        # Get or create campaign for attacker
        if attacker_id not in self.campaigns:
            campaign_id = f"campaign_{attacker_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.campaigns[attacker_id] = AttackCampaign(
                campaign_id=campaign_id,
                attacker_id=attacker_id,
                campaign_type=CampaignType.RECONNAISSANCE
            )
        
        campaign = self.campaigns[attacker_id]
        campaign.add_action(action)
        
        # Re-classify campaign type based on all actions
        campaign.campaign_type = self.detect_campaign_type(campaign.actions)
        
        return campaign
    
    def track_credential_extraction(
        self,
        attacker_id: str,
        credential: str,
        source_endpoint: str
    ) -> None:
        """
        Track credential extraction for reuse monitoring.
        
        Args:
            attacker_id: Unique attacker identifier
            credential: Extracted credential
            source_endpoint: Where it was extracted from
        """
        key = f"{attacker_id}:{credential}"
        
        if key not in self.credential_tracking:
            self.credential_tracking[key] = CredentialUsage(
                credential=credential,
                extracted_from=source_endpoint,
                extracted_at=datetime.now()
            )
        
        # Add to campaign
        if attacker_id in self.campaigns:
            self.campaigns[attacker_id].credentials_extracted.append(credential)
    
    def check_credential_reuse(
        self,
        attacker_id: str,
        credential: str,
        endpoint: str,
        success: bool
    ) -> bool:
        """
        Check if credential is being reused and track it.
        
        Args:
            attacker_id: Unique attacker identifier
            credential: Credential being used
            endpoint: Where it's being used
            success: Whether usage succeeded
            
        Returns:
            True if this is a reuse of extracted credential
        """
        key = f"{attacker_id}:{credential}"
        
        if key in self.credential_tracking:
            usage = self.credential_tracking[key]
            usage.add_usage(endpoint, success)
            return True
        
        return False
    
    def track_session_hijacking(
        self,
        attacker_id: str,
        session_id: str,
        source_endpoint: str
    ) -> None:
        """
        Track session hijacking attempt.
        
        Args:
            attacker_id: Unique attacker identifier
            session_id: Hijacked session ID
            source_endpoint: Where session was obtained
        """
        self.session_tracking[session_id] = {
            "attacker_id": attacker_id,
            "hijacked_at": datetime.now(),
            "source": source_endpoint,
            "usage_count": 0
        }
        
        # Add to campaign
        if attacker_id in self.campaigns:
            self.campaigns[attacker_id].sessions_hijacked.append(session_id)
    
    def check_session_usage(self, session_id: str) -> Optional[Dict[str, any]]:
        """
        Check if session is being used (hijacked).
        
        Returns:
            Session tracking info if hijacked, None otherwise
        """
        if session_id in self.session_tracking:
            self.session_tracking[session_id]["usage_count"] += 1
            return self.session_tracking[session_id]
        
        return None
    
    def detect_coordinated_attack(self, attacker_id: str) -> bool:
        """
        Detect if attacker is conducting coordinated multi-vector attack.
        
        Args:
            attacker_id: Unique attacker identifier
            
        Returns:
            True if coordinated attack detected
        """
        if attacker_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[attacker_id]
        
        # Coordinated if:
        # - Multiple vectors used
        # - Multiple endpoints targeted
        # - Actions within short time window
        
        if len(campaign.vectors_used) < 2:
            return False
        
        if len(campaign.endpoints_targeted) < 2:
            return False
        
        # Check if actions are within 10 minutes of each other
        if len(campaign.actions) >= 2:
            time_span = (campaign.last_activity - campaign.start_time).total_seconds()
            if time_span < 600:  # 10 minutes
                return True
        
        return False
    
    def get_campaign(self, attacker_id: str) -> Optional[AttackCampaign]:
        """Get attack campaign for attacker."""
        return self.campaigns.get(attacker_id)
    
    def get_campaign_summary(self, attacker_id: str) -> str:
        """Get formatted campaign summary."""
        campaign = self.campaigns.get(attacker_id)
        
        if not campaign:
            return "No campaign data"
        
        summary = f"""Campaign: {campaign.campaign_id}
Type: {campaign.campaign_type.value}
Duration: {(campaign.last_activity - campaign.start_time).total_seconds():.0f}s
Actions: {len(campaign.actions)}
Endpoints: {', '.join(campaign.endpoints_targeted)}
Vectors: {', '.join(v.value for v in campaign.vectors_used)}
Credentials: {len(campaign.credentials_extracted)}
Sessions: {len(campaign.sessions_hijacked)}

Timeline:
{campaign.get_timeline()}
"""
        
        return summary


# =========================
# DISTRIBUTED ATTACK DETECTOR
# =========================
class DistributedAttackDetector:
    """Detects distributed attacks from multiple IPs."""
    
    def __init__(self):
        self.ip_payloads: Dict[str, List[str]] = {}
        self.payload_ips: Dict[str, Set[str]] = {}
    
    def track_ip_payload(self, ip: str, payload: str) -> None:
        """Track payload from IP."""
        if ip not in self.ip_payloads:
            self.ip_payloads[ip] = []
        self.ip_payloads[ip].append(payload)
        
        if payload not in self.payload_ips:
            self.payload_ips[payload] = set()
        self.payload_ips[payload].add(ip)
    
    def detect_distributed_attack(self, payload: str, threshold: int = 3) -> bool:
        """
        Detect if payload is being used from multiple IPs.
        
        Args:
            payload: Attack payload
            threshold: Minimum IPs for distributed attack
            
        Returns:
            True if distributed attack detected
        """
        if payload in self.payload_ips:
            return len(self.payload_ips[payload]) >= threshold
        
        return False
    
    def get_attack_ips(self, payload: str) -> Set[str]:
        """Get all IPs using a payload."""
        return self.payload_ips.get(payload, set())


# =========================
# GLOBAL INSTANCE
# =========================
_correlation_engine = CorrelationEngine()
_distributed_detector = DistributedAttackDetector()


def track_attack_action(
    attacker_id: str,
    endpoint: str,
    vector: str,
    payload: str,
    success: bool = False,
    data_leaked: Optional[str] = None
) -> AttackCampaign:
    """Track attack action (convenience function)."""
    # Convert vector string to enum
    vector_map = {
        "SQL Injection": AttackVector.SQL_INJECTION,
        "XSS": AttackVector.XSS,
        "PATH_TRAVERSAL": AttackVector.PATH_TRAVERSAL,
        "CMD_INJECTION": AttackVector.COMMAND_INJECTION,
    }
    
    vector_enum = vector_map.get(vector, AttackVector.SQL_INJECTION)
    
    return _correlation_engine.track_attack(
        attacker_id, endpoint, vector_enum, payload, success, data_leaked
    )


def track_credential_extraction(
    attacker_id: str,
    credential: str,
    source: str
) -> None:
    """Track credential extraction (convenience function)."""
    _correlation_engine.track_credential_extraction(attacker_id, credential, source)


def check_credential_reuse(
    attacker_id: str,
    credential: str,
    endpoint: str,
    success: bool
) -> bool:
    """Check credential reuse (convenience function)."""
    return _correlation_engine.check_credential_reuse(attacker_id, credential, endpoint, success)


def get_attack_campaign(attacker_id: str) -> Optional[AttackCampaign]:
    """Get attack campaign (convenience function)."""
    return _correlation_engine.get_campaign(attacker_id)


def is_coordinated_attack(attacker_id: str) -> bool:
    """Check if coordinated attack (convenience function)."""
    return _correlation_engine.detect_coordinated_attack(attacker_id)
