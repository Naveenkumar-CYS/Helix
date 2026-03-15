"""
Behavioral Fingerprinting and Attacker Intelligence
Analyzes attacker behavior patterns, skill levels, and tool signatures.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
import time


# =========================
# ENUMS
# =========================
class SkillLevel(Enum):
    """Attacker skill level classification."""
    AUTOMATED = "automated"      # Automated scanning tools
    NOVICE = "novice"           # Basic manual testing
    INTERMEDIATE = "intermediate"  # Experienced manual testing
    ADVANCED = "advanced"       # Sophisticated, targeted attacks


class AttackTool(Enum):
    """Known attack tool signatures."""
    SQLMAP = "sqlmap"
    BURP_SUITE = "burp_suite"
    NIKTO = "nikto"
    METASPLOIT = "metasploit"
    NMAP = "nmap"
    CUSTOM = "custom"
    MANUAL = "manual"
    UNKNOWN = "unknown"


# =========================
# DATA MODELS
# =========================
@dataclass
class AttackEvent:
    """Single attack event for behavioral analysis."""
    timestamp: datetime
    payload: str
    endpoint: str
    attack_type: str
    user_agent: Optional[str] = None


@dataclass
class BehavioralProfile:
    """Comprehensive attacker behavioral profile."""
    attacker_id: str
    skill_level: SkillLevel = SkillLevel.NOVICE
    detected_tool: AttackTool = AttackTool.UNKNOWN
    attack_history: List[AttackEvent] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Behavioral metrics
    total_requests: int = 0
    unique_payloads: int = 0
    avg_request_interval: float = 0.0  # seconds
    payload_sophistication_score: float = 0.0
    
    # Tool signatures detected
    tool_signatures: List[str] = field(default_factory=list)
    
    def update_metrics(self) -> None:
        """Recalculate behavioral metrics from attack history."""
        self.total_requests = len(self.attack_history)
        
        if self.total_requests > 0:
            # Calculate unique payloads
            unique = set(event.payload for event in self.attack_history)
            self.unique_payloads = len(unique)
            
            # Calculate average request interval
            if self.total_requests > 1:
                intervals = []
                for i in range(1, len(self.attack_history)):
                    delta = (self.attack_history[i].timestamp - 
                            self.attack_history[i-1].timestamp).total_seconds()
                    intervals.append(delta)
                self.avg_request_interval = sum(intervals) / len(intervals)
            
            self.last_seen = self.attack_history[-1].timestamp


# =========================
# TOOL SIGNATURE DETECTION
# =========================
class ToolSignatureDetector:
    """Detects attack tools based on payload and user agent patterns."""
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
    
    def _initialize_signatures(self) -> Dict[AttackTool, Dict[str, List[str]]]:
        """Define tool signature patterns."""
        return {
            AttackTool.SQLMAP: {
                "payload": [
                    r"AND \d+=\d+",
                    r"UNION ALL SELECT NULL",
                    r"CONCAT\(0x[0-9a-f]+",
                    r"SLEEP\(\d+\)",
                    r"BENCHMARK\(",
                    r"@@version",
                    r"information_schema",
                ],
                "user_agent": [
                    "sqlmap",
                ]
            },
            AttackTool.BURP_SUITE: {
                "payload": [
                    r"§.*§",  # Burp intruder markers
                ],
                "user_agent": [
                    "burp",
                ]
            },
            AttackTool.NIKTO: {
                "payload": [],
                "user_agent": [
                    "nikto",
                ]
            },
            AttackTool.METASPLOIT: {
                "payload": [
                    r"metasploit",
                ],
                "user_agent": [
                    "metasploit",
                    "msfconsole",
                ]
            },
            AttackTool.NMAP: {
                "payload": [],
                "user_agent": [
                    "nmap",
                ]
            },
        }
    
    def detect(self, payload: str, user_agent: Optional[str] = None) -> Tuple[AttackTool, List[str]]:
        """
        Detect attack tool from payload and user agent.
        
        Returns:
            Tuple of (detected_tool, matching_signatures)
        """
        detected_signatures = []
        
        for tool, patterns in self.signatures.items():
            # Check payload patterns
            for pattern in patterns["payload"]:
                if re.search(pattern, payload, re.IGNORECASE):
                    detected_signatures.append(f"{tool.value}:payload:{pattern}")
            
            # Check user agent patterns
            if user_agent:
                for pattern in patterns["user_agent"]:
                    if pattern.lower() in user_agent.lower():
                        detected_signatures.append(f"{tool.value}:ua:{pattern}")
            
            # If we found signatures for this tool, return it
            if detected_signatures:
                return tool, detected_signatures
        
        # Check if it looks like manual testing
        if user_agent and any(browser in user_agent.lower() 
                             for browser in ["mozilla", "chrome", "safari", "firefox"]):
            return AttackTool.MANUAL, ["manual:browser_ua"]
        
        return AttackTool.UNKNOWN, []


# =========================
# PAYLOAD SOPHISTICATION SCORER
# =========================
class PayloadSophisticationScorer:
    """Scores payload sophistication on a scale of 0-100."""
    
    def score(self, payload: str) -> float:
        """
        Calculate sophistication score for a payload.
        
        Scoring criteria:
        - Basic patterns (OR 1=1): 10-30
        - Intermediate (UNION SELECT): 30-60
        - Advanced (blind SQLi, time-based): 60-90
        - Expert (WAF bypass, encoding): 90-100
        """
        score = 0.0
        payload_lower = payload.lower()
        
        # Basic SQL injection patterns
        if any(p in payload_lower for p in ["or 1=1", "' or '1'='1", "admin'--"]):
            score += 15
        
        # Intermediate patterns
        if "union" in payload_lower and "select" in payload_lower:
            score += 25
        
        # Advanced patterns
        if any(p in payload_lower for p in ["sleep(", "benchmark(", "waitfor delay"]):
            score += 30
        
        # Expert patterns - encoding/obfuscation
        if re.search(r'%[0-9a-f]{2}', payload, re.IGNORECASE):
            score += 15
        
        # Expert patterns - advanced functions
        if any(p in payload_lower for p in ["concat(", "char(", "hex(", "unhex("]):
            score += 20
        
        # Expert patterns - information schema
        if "information_schema" in payload_lower:
            score += 15
        
        # Expert patterns - stacked queries
        if ";" in payload and any(cmd in payload_lower for cmd in ["drop", "insert", "update", "delete"]):
            score += 20
        
        # WAF bypass techniques
        if any(p in payload for p in ["/**/", "/*!*/", "/*!", "||", "&&"]):
            score += 15
        
        return min(score, 100.0)


# =========================
# SKILL LEVEL CLASSIFIER
# =========================
class SkillLevelClassifier:
    """Classifies attacker skill level based on behavioral metrics."""
    
    def classify(self, profile: BehavioralProfile) -> SkillLevel:
        """
        Classify attacker skill level.
        
        Classification criteria:
        - AUTOMATED: Very fast requests (<1s avg), high volume, low sophistication
        - NOVICE: Slow requests, basic payloads, browser user agent
        - INTERMEDIATE: Moderate speed, some advanced payloads, manual testing
        - ADVANCED: Varied timing, high sophistication, custom tools
        """
        # Need at least 3 requests for meaningful classification
        if profile.total_requests < 3:
            return SkillLevel.NOVICE
        
        # AUTOMATED: Very fast, repetitive
        if (profile.avg_request_interval < 1.0 and 
            profile.total_requests > 10 and
            profile.payload_sophistication_score < 50):
            return SkillLevel.AUTOMATED
        
        # Check for known automated tools
        if profile.detected_tool in [AttackTool.SQLMAP, AttackTool.NIKTO, AttackTool.NMAP]:
            return SkillLevel.AUTOMATED
        
        # ADVANCED: High sophistication, varied techniques
        if profile.payload_sophistication_score > 70:
            return SkillLevel.ADVANCED
        
        # INTERMEDIATE: Moderate sophistication, manual testing
        if (profile.payload_sophistication_score > 40 and 
            profile.detected_tool == AttackTool.MANUAL):
            return SkillLevel.INTERMEDIATE
        
        # Default to NOVICE
        return SkillLevel.NOVICE


# =========================
# BEHAVIORAL ANALYZER
# =========================
class BehavioralAnalyzer:
    """Main behavioral analysis engine."""
    
    def __init__(self):
        self.profiles: Dict[str, BehavioralProfile] = {}
        self.tool_detector = ToolSignatureDetector()
        self.sophistication_scorer = PayloadSophisticationScorer()
        self.skill_classifier = SkillLevelClassifier()
    
    def analyze_request(
        self,
        attacker_id: str,
        payload: str,
        endpoint: str,
        attack_type: str,
        user_agent: Optional[str] = None
    ) -> BehavioralProfile:
        """
        Analyze a request and update attacker profile.
        
        Args:
            attacker_id: Unique attacker identifier
            payload: Attack payload
            endpoint: Target endpoint
            attack_type: Detected attack type
            user_agent: User agent string
            
        Returns:
            Updated behavioral profile
        """
        # Get or create profile
        if attacker_id not in self.profiles:
            self.profiles[attacker_id] = BehavioralProfile(attacker_id=attacker_id)
        
        profile = self.profiles[attacker_id]
        
        # Create attack event
        event = AttackEvent(
            timestamp=datetime.now(),
            payload=payload,
            endpoint=endpoint,
            attack_type=attack_type,
            user_agent=user_agent
        )
        
        # Add to history
        profile.attack_history.append(event)
        
        # Detect tool
        detected_tool, signatures = self.tool_detector.detect(payload, user_agent)
        if detected_tool != AttackTool.UNKNOWN:
            profile.detected_tool = detected_tool
            profile.tool_signatures.extend(signatures)
        
        # Score payload sophistication
        sophistication = self.sophistication_scorer.score(payload)
        
        # Update running average of sophistication
        if profile.total_requests == 0:
            profile.payload_sophistication_score = sophistication
        else:
            # Weighted average (give more weight to recent payloads)
            profile.payload_sophistication_score = (
                profile.payload_sophistication_score * 0.7 + sophistication * 0.3
            )
        
        # Update metrics
        profile.update_metrics()
        
        # Classify skill level
        profile.skill_level = self.skill_classifier.classify(profile)
        
        return profile
    
    def get_profile(self, attacker_id: str) -> Optional[BehavioralProfile]:
        """Get behavioral profile for an attacker."""
        return self.profiles.get(attacker_id)
    
    def get_all_profiles(self) -> Dict[str, BehavioralProfile]:
        """Get all behavioral profiles."""
        return self.profiles


# =========================
# GLOBAL INSTANCE
# =========================
_analyzer = BehavioralAnalyzer()


def analyze_behavior(
    attacker_id: str,
    payload: str,
    endpoint: str,
    attack_type: str,
    user_agent: Optional[str] = None
) -> BehavioralProfile:
    """
    Analyze attacker behavior (convenience function).
    
    Args:
        attacker_id: Unique attacker identifier
        payload: Attack payload
        endpoint: Target endpoint
        attack_type: Detected attack type
        user_agent: User agent string
        
    Returns:
        Updated behavioral profile
    """
    return _analyzer.analyze_request(attacker_id, payload, endpoint, attack_type, user_agent)


def get_behavioral_profile(attacker_id: str) -> Optional[BehavioralProfile]:
    """Get behavioral profile for an attacker."""
    return _analyzer.get_profile(attacker_id)
