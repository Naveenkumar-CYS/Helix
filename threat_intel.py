"""
Threat Intelligence Integration
IP reputation, geolocation, and attacker profiling.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re


# =========================
# ENUMS
# =========================
class ThreatLevel(Enum):
    """Threat level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IPReputation(Enum):
    """IP reputation classification."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    VPN = "vpn"
    TOR = "tor"
    PROXY = "proxy"
    DATACENTER = "datacenter"


# =========================
# DATA MODELS
# =========================
@dataclass
class GeoLocation:
    """Geographic location information."""
    country: str
    country_code: str
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class IPIntelligence:
    """Comprehensive IP intelligence."""
    ip_address: str
    reputation: IPReputation = IPReputation.CLEAN
    threat_level: ThreatLevel = ThreatLevel.LOW
    geolocation: Optional[GeoLocation] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    abuse_score: int = 0  # 0-100
    last_seen_malicious: Optional[datetime] = None
    known_attacks: List[str] = field(default_factory=list)
    
    def calculate_threat_level(self) -> ThreatLevel:
        """Calculate overall threat level."""
        if self.abuse_score > 75 or self.reputation == IPReputation.MALICIOUS:
            return ThreatLevel.CRITICAL
        elif self.abuse_score > 50 or self.reputation == IPReputation.SUSPICIOUS:
            return ThreatLevel.HIGH
        elif self.is_vpn or self.is_proxy or self.is_tor:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW


@dataclass
class AttackerProfile:
    """Comprehensive attacker profile."""
    attacker_id: str
    ip_addresses: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Intelligence
    ip_intelligence: Optional[IPIntelligence] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    
    # Behavioral
    skill_level: Optional[str] = None
    detected_tools: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    
    # Activity
    total_requests: int = 0
    successful_attacks: int = 0
    data_exfiltrated: List[str] = field(default_factory=list)
    
    # Attribution
    likely_country: Optional[str] = None
    likely_timezone: Optional[str] = None
    active_hours: List[int] = field(default_factory=list)  # Hours of day (0-23)
    
    def update_activity_time(self) -> None:
        """Update active hours based on current time."""
        current_hour = datetime.now().hour
        if current_hour not in self.active_hours:
            self.active_hours.append(current_hour)


# =========================
# IP REPUTATION ANALYZER
# =========================
class IPReputationAnalyzer:
    """Analyzes IP reputation using heuristics and patterns."""
    
    def __init__(self):
        # Known malicious IP ranges (examples)
        self.malicious_ranges = [
            # Add known malicious ranges here
        ]
        
        # Known VPN/Proxy providers (simplified)
        self.vpn_patterns = [
            r"\.vpn\.",
            r"\.proxy\.",
            r"nordvpn",
            r"expressvpn",
            r"protonvpn",
        ]
        
        # Datacenter ASN ranges (simplified)
        self.datacenter_asns = [
            "AS14061",  # DigitalOcean
            "AS16509",  # Amazon AWS
            "AS15169",  # Google Cloud
            "AS8075",   # Microsoft Azure
        ]
    
    def analyze_ip(self, ip_address: str, user_agent: Optional[str] = None) -> IPIntelligence:
        """
        Analyze IP address for threat intelligence.
        
        Args:
            ip_address: IP address to analyze
            user_agent: Optional user agent string
            
        Returns:
            IP intelligence data
        """
        intel = IPIntelligence(ip_address=ip_address)
        
        # Check if private IP
        if self._is_private_ip(ip_address):
            intel.reputation = IPReputation.CLEAN
            intel.threat_level = ThreatLevel.LOW
            return intel
        
        # Detect VPN/Proxy (simplified heuristic)
        if self._detect_vpn_proxy(ip_address):
            intel.is_vpn = True
            intel.reputation = IPReputation.VPN
            intel.abuse_score = 30
        
        # Detect Tor (simplified)
        if self._detect_tor(ip_address):
            intel.is_tor = True
            intel.reputation = IPReputation.TOR
            intel.abuse_score = 50
        
        # Detect datacenter
        if self._detect_datacenter(ip_address):
            intel.is_datacenter = True
            intel.abuse_score = max(intel.abuse_score, 20)
        
        # Calculate threat level
        intel.threat_level = intel.calculate_threat_level()
        
        return intel
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
            r"^localhost$",
        ]
        
        return any(re.match(pattern, ip) for pattern in private_patterns)
    
    def _detect_vpn_proxy(self, ip: str) -> bool:
        """Detect VPN/Proxy (simplified heuristic)."""
        # In production, use external API like IPQualityScore or IPHub
        # For now, use simple heuristics
        return False  # Placeholder
    
    def _detect_tor(self, ip: str) -> bool:
        """Detect Tor exit node (simplified)."""
        # In production, check against Tor exit node list
        return False  # Placeholder
    
    def _detect_datacenter(self, ip: str) -> bool:
        """Detect datacenter IP (simplified)."""
        # In production, check ASN against known datacenter providers
        return False  # Placeholder


# =========================
# GEOLOCATION SERVICE
# =========================
class GeolocationService:
    """Provides geolocation for IP addresses."""
    
    def __init__(self):
        # In production, use MaxMind GeoIP2 or similar
        self.mock_data = self._initialize_mock_data()
    
    def _initialize_mock_data(self) -> Dict[str, GeoLocation]:
        """Initialize mock geolocation data."""
        return {
            # Private IPs
            "127.0.0.1": GeoLocation(
                country="Local",
                country_code="LO",
                city="Localhost",
                timezone="UTC"
            ),
            "192.168.1.1": GeoLocation(
                country="Local",
                country_code="LO",
                city="Private Network",
                timezone="UTC"
            ),
        }
    
    def geolocate(self, ip_address: str) -> Optional[GeoLocation]:
        """
        Get geolocation for IP address.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            GeoLocation data or None
        """
        # Check mock data
        if ip_address in self.mock_data:
            return self.mock_data[ip_address]
        
        # In production, query GeoIP database
        # For now, return generic data
        return GeoLocation(
            country="Unknown",
            country_code="XX",
            city="Unknown",
            timezone="UTC"
        )


# =========================
# ATTACKER PROFILER
# =========================
class AttackerProfiler:
    """Builds comprehensive attacker profiles."""
    
    def __init__(self):
        self.profiles: Dict[str, AttackerProfile] = {}
        self.ip_analyzer = IPReputationAnalyzer()
        self.geo_service = GeolocationService()
    
    def get_or_create_profile(self, attacker_id: str) -> AttackerProfile:
        """Get existing profile or create new one."""
        if attacker_id not in self.profiles:
            self.profiles[attacker_id] = AttackerProfile(attacker_id=attacker_id)
        return self.profiles[attacker_id]
    
    def update_profile(
        self,
        attacker_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        attack_vector: Optional[str] = None,
        success: bool = False
    ) -> AttackerProfile:
        """
        Update attacker profile with new information.
        
        Args:
            attacker_id: Unique attacker identifier
            ip_address: IP address
            user_agent: User agent string
            attack_vector: Attack vector used
            success: Whether attack succeeded
            
        Returns:
            Updated attacker profile
        """
        profile = self.get_or_create_profile(attacker_id)
        
        # Update IP information
        if ip_address and ip_address not in profile.ip_addresses:
            profile.ip_addresses.append(ip_address)
            
            # Analyze IP
            ip_intel = self.ip_analyzer.analyze_ip(ip_address, user_agent)
            profile.ip_intelligence = ip_intel
            profile.threat_level = ip_intel.threat_level
            
            # Geolocate
            geo = self.geo_service.geolocate(ip_address)
            if geo:
                profile.likely_country = geo.country
                profile.likely_timezone = geo.timezone
        
        # Update user agent
        if user_agent and user_agent not in profile.user_agents:
            profile.user_agents.append(user_agent)
        
        # Update attack vectors
        if attack_vector and attack_vector not in profile.attack_vectors:
            profile.attack_vectors.append(attack_vector)
        
        # Update activity
        profile.total_requests += 1
        if success:
            profile.successful_attacks += 1
        
        profile.last_seen = datetime.now()
        profile.update_activity_time()
        
        return profile
    
    def get_profile(self, attacker_id: str) -> Optional[AttackerProfile]:
        """Get attacker profile."""
        return self.profiles.get(attacker_id)
    
    def get_profile_summary(self, attacker_id: str) -> str:
        """Get formatted profile summary."""
        profile = self.profiles.get(attacker_id)
        
        if not profile:
            return "No profile data"
        
        summary = f"""Attacker Profile: {attacker_id}
Threat Level: {profile.threat_level.value.upper()}
Skill Level: {profile.skill_level or 'Unknown'}

Network:
- IPs: {', '.join(profile.ip_addresses[:3])}
- Country: {profile.likely_country or 'Unknown'}
- Timezone: {profile.likely_timezone or 'Unknown'}

Activity:
- First Seen: {profile.first_seen.strftime('%Y-%m-%d %H:%M:%S')}
- Last Seen: {profile.last_seen.strftime('%Y-%m-%d %H:%M:%S')}
- Total Requests: {profile.total_requests}
- Successful Attacks: {profile.successful_attacks}
- Active Hours: {sorted(profile.active_hours)}

Tools & Techniques:
- Detected Tools: {', '.join(profile.detected_tools) or 'None'}
- Attack Vectors: {', '.join(profile.attack_vectors) or 'None'}
"""
        
        return summary


# =========================
# THREAT INTELLIGENCE ENGINE
# =========================
class ThreatIntelligenceEngine:
    """Main threat intelligence engine."""
    
    def __init__(self):
        self.profiler = AttackerProfiler()
    
    def analyze_attacker(
        self,
        attacker_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        attack_vector: Optional[str] = None,
        success: bool = False
    ) -> AttackerProfile:
        """Analyze attacker and update profile."""
        return self.profiler.update_profile(
            attacker_id, ip_address, user_agent, attack_vector, success
        )
    
    def get_threat_assessment(self, attacker_id: str) -> Dict[str, Any]:
        """Get threat assessment for attacker."""
        profile = self.profiler.get_profile(attacker_id)
        
        if not profile:
            return {"threat_level": "unknown", "confidence": 0}
        
        return {
            "threat_level": profile.threat_level.value,
            "skill_level": profile.skill_level,
            "total_requests": profile.total_requests,
            "success_rate": (profile.successful_attacks / profile.total_requests * 100
                           if profile.total_requests > 0 else 0),
            "likely_country": profile.likely_country,
            "is_vpn": profile.ip_intelligence.is_vpn if profile.ip_intelligence else False,
            "is_tor": profile.ip_intelligence.is_tor if profile.ip_intelligence else False,
        }


# =========================
# GLOBAL INSTANCE
# =========================
_threat_intel = ThreatIntelligenceEngine()


def analyze_threat(
    attacker_id: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    attack_vector: Optional[str] = None,
    success: bool = False
) -> AttackerProfile:
    """Analyze threat (convenience function)."""
    return _threat_intel.analyze_attacker(
        attacker_id, ip_address, user_agent, attack_vector, success
    )


def get_threat_level(attacker_id: str) -> str:
    """Get threat level (convenience function)."""
    assessment = _threat_intel.get_threat_assessment(attacker_id)
    return assessment.get("threat_level", "unknown")
