"""
External Threat Intelligence Integration
Integrates with AbuseIPDB, VirusTotal, and other threat feeds.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import requests
import json
from enum import Enum


# =========================
# CONFIGURATION
# =========================
@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence APIs."""
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    cache_ttl: int = 3600  # 1 hour cache
    timeout: int = 5  # API timeout in seconds


# =========================
# THREAT FEED TYPES
# =========================
class ThreatSource(Enum):
    """Threat intelligence sources."""
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    LOCAL_CACHE = "local_cache"
    HONEYPOT = "honeypot"


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence data."""
    ip_address: str
    is_malicious: bool = False
    abuse_confidence: int = 0  # 0-100
    threat_score: int = 0  # 0-100
    country: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    last_reported: Optional[datetime] = None
    report_count: int = 0
    sources: List[ThreatSource] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    cached_at: datetime = field(default_factory=datetime.now)


# =========================
# THREAT INTELLIGENCE CACHE
# =========================
class ThreatIntelCache:
    """Caches threat intelligence lookups."""
    
    def __init__(self, ttl: int = 3600):
        self.cache: Dict[str, ThreatIntelligence] = {}
        self.ttl = ttl
    
    def get(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Get cached threat intel if not expired."""
        if ip_address not in self.cache:
            return None
        
        intel = self.cache[ip_address]
        age = (datetime.now() - intel.cached_at).total_seconds()
        
        if age > self.ttl:
            # Expired
            del self.cache[ip_address]
            return None
        
        return intel
    
    def set(self, ip_address: str, intel: ThreatIntelligence) -> None:
        """Cache threat intelligence."""
        intel.cached_at = datetime.now()
        self.cache[ip_address] = intel
    
    def clear_expired(self) -> None:
        """Clear expired cache entries."""
        now = datetime.now()
        expired = [
            ip for ip, intel in self.cache.items()
            if (now - intel.cached_at).total_seconds() > self.ttl
        ]
        for ip in expired:
            del self.cache[ip]


# =========================
# ABUSEIPDB INTEGRATION
# =========================
class AbuseIPDBClient:
    """Client for AbuseIPDB API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    def check_ip(self, ip_address: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Check IP reputation on AbuseIPDB.
        
        Returns:
            API response data or None if API key not configured
        """
        if not self.api_key:
            return None
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=timeout
            )
            
            if response.status_code == 200:
                return response.json()
            
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def report_ip(
        self,
        ip_address: str,
        categories: List[int],
        comment: str,
        timeout: int = 5
    ) -> bool:
        """
        Report malicious IP to AbuseIPDB.
        
        Args:
            ip_address: IP to report
            categories: List of category IDs (e.g., [18, 21] for brute force)
            comment: Description of malicious activity
            
        Returns:
            True if report successful
        """
        if not self.api_key:
            return False
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            
            data = {
                "ip": ip_address,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment
            }
            
            response = requests.post(
                f"{self.base_url}/report",
                headers=headers,
                data=data,
                timeout=timeout
            )
            
            return response.status_code == 200
            
        except requests.exceptions.RequestException:
            return False


# =========================
# VIRUSTOTAL INTEGRATION
# =========================
class VirusTotalClient:
    """Client for VirusTotal API."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def check_ip(self, ip_address: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Check IP reputation on VirusTotal.
        
        Returns:
            API response data or None if API key not configured
        """
        if not self.api_key:
            return None
        
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip_address}",
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code == 200:
                return response.json()
            
        except requests.exceptions.RequestException:
            pass
        
        return None


# =========================
# THREAT INTELLIGENCE AGGREGATOR
# =========================
class ThreatIntelAggregator:
    """Aggregates threat intelligence from multiple sources."""
    
    def __init__(self, config: Optional[ThreatIntelConfig] = None):
        self.config = config or ThreatIntelConfig()
        self.cache = ThreatIntelCache(self.config.cache_ttl)
        self.abuseipdb = AbuseIPDBClient(self.config.abuseipdb_api_key)
        self.virustotal = VirusTotalClient(self.config.virustotal_api_key)
        
        # Local threat database (IPs we've seen attacking)
        self.local_threats: Dict[str, Dict[str, Any]] = {}
    
    def lookup_ip(self, ip_address: str) -> ThreatIntelligence:
        """
        Lookup IP across all threat intelligence sources.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Aggregated threat intelligence
        """
        # Check cache first
        cached = self.cache.get(ip_address)
        if cached:
            return cached
        
        # Create new intelligence object
        intel = ThreatIntelligence(ip_address=ip_address)
        
        # Check local threats database
        if ip_address in self.local_threats:
            local_data = self.local_threats[ip_address]
            intel.sources.append(ThreatSource.HONEYPOT)
            intel.report_count += local_data.get("attack_count", 0)
            intel.threat_score = min(100, local_data.get("attack_count", 0) * 10)
            intel.raw_data["honeypot"] = local_data
        
        # Check AbuseIPDB
        abuseipdb_data = self.abuseipdb.check_ip(ip_address, self.config.timeout)
        if abuseipdb_data:
            intel.sources.append(ThreatSource.ABUSEIPDB)
            data = abuseipdb_data.get("data", {})
            
            intel.abuse_confidence = data.get("abuseConfidenceScore", 0)
            intel.country = data.get("countryCode")
            intel.isp = data.get("isp")
            intel.domain = data.get("domain")
            intel.report_count += data.get("totalReports", 0)
            intel.is_malicious = intel.abuse_confidence > 50
            intel.raw_data["abuseipdb"] = data
        
        # Check VirusTotal
        virustotal_data = self.virustotal.check_ip(ip_address, self.config.timeout)
        if virustotal_data:
            intel.sources.append(ThreatSource.VIRUSTOTAL)
            data = virustotal_data.get("data", {})
            attributes = data.get("attributes", {})
            
            # Get malicious votes
            last_analysis = attributes.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            total = sum(last_analysis.values())
            
            if total > 0:
                vt_score = int((malicious + suspicious * 0.5) / total * 100)
                intel.threat_score = max(intel.threat_score, vt_score)
                intel.is_malicious = intel.is_malicious or (malicious > 0)
            
            intel.raw_data["virustotal"] = attributes
        
        # Calculate overall threat score
        if intel.abuse_confidence > 0:
            intel.threat_score = max(intel.threat_score, intel.abuse_confidence)
        
        # Cache the result
        self.cache.set(ip_address, intel)
        
        return intel
    
    def add_local_threat(
        self,
        ip_address: str,
        attack_type: str,
        severity: int = 1
    ) -> None:
        """
        Add IP to local threat database.
        
        Args:
            ip_address: IP address
            attack_type: Type of attack observed
            severity: Severity level (1-10)
        """
        if ip_address not in self.local_threats:
            self.local_threats[ip_address] = {
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "attack_count": 0,
                "attack_types": [],
                "severity_sum": 0
            }
        
        threat = self.local_threats[ip_address]
        threat["last_seen"] = datetime.now()
        threat["attack_count"] += 1
        threat["severity_sum"] += severity
        
        if attack_type not in threat["attack_types"]:
            threat["attack_types"].append(attack_type)
        
        # Invalidate cache for this IP
        if ip_address in self.cache.cache:
            del self.cache.cache[ip_address]
    
    def report_to_abuseipdb(
        self,
        ip_address: str,
        attack_type: str,
        details: str
    ) -> bool:
        """
        Report malicious IP to AbuseIPDB.
        
        Args:
            ip_address: IP to report
            attack_type: Type of attack
            details: Attack details
            
        Returns:
            True if report successful
        """
        # Map attack types to AbuseIPDB categories
        category_map = {
            "SQL Injection": [18, 21],  # Brute force, Web attack
            "XSS": [21],  # Web attack
            "CMD_INJECTION": [21],  # Web attack
            "PATH_TRAVERSAL": [21],  # Web attack
            "brute_force": [18],  # Brute force
            "password_spray": [18],  # Brute force
        }
        
        categories = category_map.get(attack_type, [21])  # Default to web attack
        comment = f"Honeypot detected {attack_type}: {details}"
        
        return self.abuseipdb.report_ip(ip_address, categories, comment)
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of all threats."""
        return {
            "total_threats": len(self.local_threats),
            "cache_size": len(self.cache.cache),
            "top_threats": sorted(
                [
                    {
                        "ip": ip,
                        "attack_count": data["attack_count"],
                        "attack_types": data["attack_types"],
                        "severity": data["severity_sum"]
                    }
                    for ip, data in self.local_threats.items()
                ],
                key=lambda x: x["severity"],
                reverse=True
            )[:10]
        }


# =========================
# GLOBAL INSTANCE
# =========================
_threat_intel = ThreatIntelAggregator()


def lookup_threat_intel(ip_address: str) -> ThreatIntelligence:
    """Lookup IP threat intelligence (convenience function)."""
    return _threat_intel.lookup_ip(ip_address)


def add_threat(ip_address: str, attack_type: str, severity: int = 1) -> None:
    """Add IP to threat database (convenience function)."""
    _threat_intel.add_local_threat(ip_address, attack_type, severity)


def report_threat(ip_address: str, attack_type: str, details: str) -> bool:
    """Report threat to external feeds (convenience function)."""
    return _threat_intel.report_to_abuseipdb(ip_address, attack_type, details)


def configure_threat_intel(
    abuseipdb_key: Optional[str] = None,
    virustotal_key: Optional[str] = None
) -> None:
    """Configure threat intelligence API keys."""
    global _threat_intel
    config = ThreatIntelConfig(
        abuseipdb_api_key=abuseipdb_key,
        virustotal_api_key=virustotal_key
    )
    _threat_intel = ThreatIntelAggregator(config)
