"""
MITRE ATT&CK Framework Mapper
Maps detected attacks to MITRE ATT&CK techniques and tactics.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json


# =========================
# MITRE ATT&CK TACTICS
# =========================
class MITRETactic(Enum):
    """MITRE ATT&CK Tactics."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# =========================
# DATA MODELS
# =========================
@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique."""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    detection_patterns: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)


@dataclass
class AttackMapping:
    """Mapping of attack to MITRE technique."""
    attack_type: str
    payload: str
    technique: MITRETechnique
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    attacker_id: Optional[str] = None


@dataclass
class TTPProfile:
    """Tactics, Techniques, and Procedures profile for an attacker."""
    attacker_id: str
    tactics_used: Set[MITRETactic] = field(default_factory=set)
    techniques_used: List[MITRETechnique] = field(default_factory=list)
    attack_mappings: List[AttackMapping] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    def add_mapping(self, mapping: AttackMapping):
        """Add attack mapping to profile."""
        self.attack_mappings.append(mapping)
        self.techniques_used.append(mapping.technique)
        self.tactics_used.add(mapping.technique.tactic)
        self.last_seen = datetime.now()
    
    def get_tactic_coverage(self) -> float:
        """Calculate percentage of MITRE tactics covered."""
        total_tactics = len(MITRETactic)
        return len(self.tactics_used) / total_tactics


# =========================
# MITRE TECHNIQUE DATABASE
# =========================
class MITRETechniqueDatabase:
    """Database of MITRE ATT&CK techniques."""
    
    def __init__(self):
        self.techniques: Dict[str, MITRETechnique] = {}
        self._initialize_techniques()
    
    def _initialize_techniques(self):
        """Initialize common techniques relevant to web attacks."""
        techniques = [
            # Initial Access
            MITRETechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic=MITRETactic.INITIAL_ACCESS,
                description="Exploiting weaknesses in Internet-facing applications",
                detection_patterns=["sql injection", "xss", "command injection", "path traversal"]
            ),
            MITRETechnique(
                technique_id="T1133",
                name="External Remote Services",
                tactic=MITRETactic.INITIAL_ACCESS,
                description="Leveraging external remote services",
                detection_patterns=["admin", "remote", "ssh", "rdp"]
            ),
            
            # Execution
            MITRETechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactic=MITRETactic.EXECUTION,
                description="Executing commands via interpreters",
                detection_patterns=["command injection", "shell", "exec", "system"]
            ),
            MITRETechnique(
                technique_id="T1203",
                name="Exploitation for Client Execution",
                tactic=MITRETactic.EXECUTION,
                description="Exploiting software vulnerabilities for execution",
                detection_patterns=["xss", "script", "javascript"]
            ),
            
            # Persistence
            MITRETechnique(
                technique_id="T1505",
                name="Server Software Component",
                tactic=MITRETactic.PERSISTENCE,
                description="Abusing server software components",
                detection_patterns=["backdoor", "webshell", "upload"]
            ),
            
            # Privilege Escalation
            MITRETechnique(
                technique_id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=MITRETactic.PRIVILEGE_ESCALATION,
                description="Exploiting vulnerabilities to gain elevated privileges",
                detection_patterns=["admin", "privilege", "escalation", "sudo"]
            ),
            
            # Defense Evasion
            MITRETechnique(
                technique_id="T1027",
                name="Obfuscated Files or Information",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Making data difficult to discover or analyze",
                detection_patterns=["encode", "obfuscate", "base64", "hex"]
            ),
            MITRETechnique(
                technique_id="T1140",
                name="Deobfuscate/Decode Files or Information",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Decoding obfuscated data",
                detection_patterns=["decode", "unhex", "char"]
            ),
            
            # Credential Access
            MITRETechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                description="Guessing credentials through repeated attempts",
                detection_patterns=["brute force", "password spray", "credential stuffing"],
                sub_techniques=["T1110.001", "T1110.003", "T1110.004"]
            ),
            MITRETechnique(
                technique_id="T1552",
                name="Unsecured Credentials",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                description="Searching for unsecured credentials",
                detection_patterns=["credential", "password", "dump", "hash"]
            ),
            
            # Discovery
            MITRETechnique(
                technique_id="T1087",
                name="Account Discovery",
                tactic=MITRETactic.DISCOVERY,
                description="Discovering valid accounts",
                detection_patterns=["enumerate", "user", "account", "list"]
            ),
            MITRETechnique(
                technique_id="T1083",
                name="File and Directory Discovery",
                tactic=MITRETactic.DISCOVERY,
                description="Enumerating files and directories",
                detection_patterns=["ls", "dir", "find", "locate", "path traversal"]
            ),
            MITRETechnique(
                technique_id="T1046",
                name="Network Service Scanning",
                tactic=MITRETactic.DISCOVERY,
                description="Scanning for network services",
                detection_patterns=["scan", "probe", "enumerate", "nmap"]
            ),
            
            # Collection
            MITRETechnique(
                technique_id="T1005",
                name="Data from Local System",
                tactic=MITRETactic.COLLECTION,
                description="Collecting data from local system",
                detection_patterns=["read", "cat", "download", "file"]
            ),
            MITRETechnique(
                technique_id="T1213",
                name="Data from Information Repositories",
                tactic=MITRETactic.COLLECTION,
                description="Collecting data from repositories",
                detection_patterns=["database", "select", "dump", "export"]
            ),
            
            # Exfiltration
            MITRETechnique(
                technique_id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic=MITRETactic.EXFILTRATION,
                description="Exfiltrating data over command and control channel",
                detection_patterns=["exfiltrate", "upload", "send", "post"]
            ),
        ]
        
        for technique in techniques:
            self.techniques[technique.technique_id] = technique
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique by ID."""
        return self.techniques.get(technique_id)
    
    def search_by_pattern(self, pattern: str) -> List[MITRETechnique]:
        """Search techniques by detection pattern."""
        pattern_lower = pattern.lower()
        matches = []
        
        for technique in self.techniques.values():
            for detection_pattern in technique.detection_patterns:
                if detection_pattern in pattern_lower or pattern_lower in detection_pattern:
                    matches.append(technique)
                    break
        
        return matches


# =========================
# ATTACK TO MITRE MAPPER
# =========================
class AttackToMITREMapper:
    """Maps honeypot attacks to MITRE ATT&CK techniques."""
    
    def __init__(self):
        self.technique_db = MITRETechniqueDatabase()
        self.attacker_profiles: Dict[str, TTPProfile] = {}
    
    def map_attack(
        self,
        attack_type: str,
        payload: str,
        attacker_id: Optional[str] = None
    ) -> List[AttackMapping]:
        """
        Map an attack to MITRE techniques.
        
        Returns:
            List of possible technique mappings with confidence scores
        """
        mappings = []
        
        # Search for matching techniques
        search_text = f"{attack_type} {payload}".lower()
        matching_techniques = self.technique_db.search_by_pattern(search_text)
        
        # Create mappings with confidence scores
        for technique in matching_techniques:
            confidence = self._calculate_confidence(
                attack_type,
                payload,
                technique
            )
            
            if confidence > 0.3:  # Only include if confidence > 30%
                mapping = AttackMapping(
                    attack_type=attack_type,
                    payload=payload,
                    technique=technique,
                    confidence=confidence,
                    attacker_id=attacker_id
                )
                mappings.append(mapping)
        
        # Sort by confidence
        mappings.sort(key=lambda x: x.confidence, reverse=True)
        
        # Update attacker profile if provided
        if attacker_id and mappings:
            self._update_attacker_profile(attacker_id, mappings[0])
        
        return mappings
    
    def _calculate_confidence(
        self,
        attack_type: str,
        payload: str,
        technique: MITRETechnique
    ) -> float:
        """Calculate confidence score for technique mapping."""
        score = 0.0
        search_text = f"{attack_type} {payload}".lower()
        
        # Check each detection pattern
        for pattern in technique.detection_patterns:
            if pattern in search_text:
                # Exact match in attack type is high confidence
                if pattern in attack_type.lower():
                    score += 0.5
                else:
                    score += 0.3
        
        return min(score, 1.0)
    
    def _update_attacker_profile(self, attacker_id: str, mapping: AttackMapping):
        """Update attacker's TTP profile."""
        if attacker_id not in self.attacker_profiles:
            self.attacker_profiles[attacker_id] = TTPProfile(attacker_id=attacker_id)
        
        profile = self.attacker_profiles[attacker_id]
        profile.add_mapping(mapping)
    
    def get_attacker_ttp_profile(self, attacker_id: str) -> Optional[TTPProfile]:
        """Get TTP profile for attacker."""
        return self.attacker_profiles.get(attacker_id)
    
    def get_ttp_summary(self, attacker_id: str) -> Dict:
        """Get formatted TTP summary for attacker."""
        profile = self.get_attacker_ttp_profile(attacker_id)
        
        if not profile:
            return {"error": "No TTP data for attacker"}
        
        # Count techniques by tactic
        tactics_breakdown = {}
        for mapping in profile.attack_mappings:
            tactic_name = mapping.technique.tactic.name
            if tactic_name not in tactics_breakdown:
                tactics_breakdown[tactic_name] = []
            tactics_breakdown[tactic_name].append({
                "technique_id": mapping.technique.technique_id,
                "technique_name": mapping.technique.name,
                "confidence": f"{mapping.confidence:.1%}"
            })
        
        return {
            "attacker_id": attacker_id,
            "tactics_used": [t.name for t in profile.tactics_used],
            "tactic_coverage": f"{profile.get_tactic_coverage():.1%}",
            "total_techniques": len(profile.techniques_used),
            "tactics_breakdown": tactics_breakdown,
            "first_seen": profile.first_seen.isoformat(),
            "last_seen": profile.last_seen.isoformat()
        }
    
    def generate_attack_matrix(self, attacker_id: str) -> Dict:
        """Generate MITRE ATT&CK matrix visualization data."""
        profile = self.get_attacker_ttp_profile(attacker_id)
        
        if not profile:
            return {}
        
        # Create matrix structure
        matrix = {
            "attacker_id": attacker_id,
            "tactics": [],
            "techniques_by_tactic": {}
        }
        
        # Group techniques by tactic
        for tactic in MITRETactic:
            tactic_techniques = [
                {
                    "id": m.technique.technique_id,
                    "name": m.technique.name,
                    "count": sum(1 for x in profile.attack_mappings if x.technique.technique_id == m.technique.technique_id)
                }
                for m in profile.attack_mappings
                if m.technique.tactic == tactic
            ]
            
            if tactic_techniques:
                matrix["tactics"].append(tactic.name)
                matrix["techniques_by_tactic"][tactic.name] = tactic_techniques
        
        return matrix
    
    def get_all_attacker_ttps(self) -> List[Dict]:
        """Get TTP summaries for all attackers."""
        return [
            self.get_ttp_summary(attacker_id)
            for attacker_id in self.attacker_profiles.keys()
        ]


# =========================
# APT PATTERN MATCHER
# =========================
class APTPatternMatcher:
    """Matches attacker behavior to known APT groups."""
    
    def __init__(self):
        # Simplified APT signatures (in production, use real threat intel)
        self.apt_signatures = {
            "APT28": {
                "tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.CREDENTIAL_ACCESS],
                "techniques": ["T1190", "T1110"],
                "description": "Fancy Bear - Known for credential harvesting"
            },
            "APT29": {
                "tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.PERSISTENCE],
                "techniques": ["T1190", "T1505"],
                "description": "Cozy Bear - Web application exploitation"
            },
            "APT41": {
                "tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.EXFILTRATION],
                "techniques": ["T1190", "T1041"],
                "description": "Double Dragon - Data theft operations"
            }
        }
    
    def match_apt(self, ttp_profile: TTPProfile) -> List[Tuple[str, float]]:
        """
        Match TTP profile to known APT groups.
        
        Returns:
            List of (APT_name, similarity_score) tuples
        """
        matches = []
        
        for apt_name, signature in self.apt_signatures.items():
            score = 0.0
            
            # Check tactic overlap
            tactic_overlap = len(
                set(signature["tactics"]) & ttp_profile.tactics_used
            )
            if tactic_overlap > 0:
                score += (tactic_overlap / len(signature["tactics"])) * 0.5
            
            # Check technique overlap
            attacker_technique_ids = {t.technique_id for t in ttp_profile.techniques_used}
            technique_overlap = len(
                set(signature["techniques"]) & attacker_technique_ids
            )
            if technique_overlap > 0:
                score += (technique_overlap / len(signature["techniques"])) * 0.5
            
            if score > 0.3:  # Only include if >30% match
                matches.append((apt_name, score))
        
        # Sort by score
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches


# =========================
# GLOBAL INSTANCE
# =========================
_mitre_mapper = AttackToMITREMapper()
_apt_matcher = APTPatternMatcher()


def map_attack_to_mitre(
    attack_type: str,
    payload: str,
    attacker_id: Optional[str] = None
) -> List[AttackMapping]:
    """Map attack to MITRE techniques (convenience function)."""
    return _mitre_mapper.map_attack(attack_type, payload, attacker_id)


def get_attacker_ttps(attacker_id: str) -> Dict:
    """Get attacker TTP summary (convenience function)."""
    return _mitre_mapper.get_ttp_summary(attacker_id)


def get_mitre_matrix(attacker_id: str) -> Dict:
    """Get MITRE matrix for attacker (convenience function)."""
    return _mitre_mapper.generate_attack_matrix(attacker_id)


def match_to_apt_groups(attacker_id: str) -> List[Tuple[str, float]]:
    """Match attacker to APT groups (convenience function)."""
    profile = _mitre_mapper.get_attacker_ttp_profile(attacker_id)
    if profile:
        return _apt_matcher.match_apt(profile)
    return []
