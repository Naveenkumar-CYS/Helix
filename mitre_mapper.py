"""
MITRE ATT&CK Framework Mapper
Maps detected attacks to MITRE ATT&CK techniques and tactics.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re

# =========================
# MITRE ATT&CK TACTICS
# =========================
class MITRETactic(Enum):
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
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    detection_patterns: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)

@dataclass
class AttackMapping:
    attack_type: str
    payload: str
    technique: MITRETechnique
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    attacker_id: Optional[str] = None

@dataclass
class TTPProfile:
    attacker_id: str
    tactics_used: Set[MITRETactic] = field(default_factory=set)
    techniques_used: List[MITRETechnique] = field(default_factory=list)
    attack_mappings: List[AttackMapping] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def add_mapping(self, mapping: AttackMapping):
        self.attack_mappings.append(mapping)
        self.techniques_used.append(mapping.technique)
        self.tactics_used.add(mapping.technique.tactic)
        self.last_seen = datetime.now()

    def get_tactic_coverage(self) -> float:
        return len(self.tactics_used) / len(MITRETactic)

# =========================
# MITRE TECHNIQUE DATABASE
# =========================
class MITRETechniqueDatabase:
    def __init__(self):
        self.techniques: Dict[str, MITRETechnique] = {}
        self._initialize_techniques()

    def _initialize_techniques(self):
        techniques = [
            MITRETechnique("T1190", "Exploit Public-Facing Application", MITRETactic.INITIAL_ACCESS,
                           "Exploiting weaknesses in Internet-facing applications",
                           ["sql injection", "xss", "command injection", "path traversal"]),
            MITRETechnique("T1133", "External Remote Services", MITRETactic.INITIAL_ACCESS,
                           "Leveraging external remote services",
                           ["admin", "remote", "ssh", "rdp"]),
            MITRETechnique("T1059", "Command and Scripting Interpreter", MITRETactic.EXECUTION,
                           "Executing commands via interpreters",
                           ["command injection", "shell", "exec", "system"]),
            MITRETechnique("T1203", "Exploitation for Client Execution", MITRETactic.EXECUTION,
                           "Exploiting software vulnerabilities for execution",
                           ["xss", "script", "javascript"]),
            MITRETechnique("T1505", "Server Software Component", MITRETactic.PERSISTENCE,
                           "Abusing server software components",
                           ["backdoor", "webshell", "upload"]),
            MITRETechnique("T1068", "Exploitation for Privilege Escalation", MITRETactic.PRIVILEGE_ESCALATION,
                           "Exploiting vulnerabilities to gain elevated privileges",
                           ["admin", "privilege", "escalation", "sudo"]),
            MITRETechnique("T1027", "Obfuscated Files or Information", MITRETactic.DEFENSE_EVASION,
                           "Making data difficult to discover or analyze",
                           ["encode", "obfuscate", "base64", "hex"]),
            MITRETechnique("T1140", "Deobfuscate/Decode Files or Information", MITRETactic.DEFENSE_EVASION,
                           "Decoding obfuscated data",
                           ["decode", "unhex", "char"]),
            MITRETechnique("T1110", "Brute Force", MITRETactic.CREDENTIAL_ACCESS,
                           "Guessing credentials through repeated attempts",
                           ["brute force", "password spray", "credential stuffing"],
                           ["T1110.001", "T1110.003", "T1110.004"]),
            MITRETechnique("T1552", "Unsecured Credentials", MITRETactic.CREDENTIAL_ACCESS,
                           "Searching for unsecured credentials",
                           ["credential", "password", "dump", "hash"]),
            MITRETechnique("T1087", "Account Discovery", MITRETactic.DISCOVERY,
                           "Discovering valid accounts",
                           ["enumerate", "user", "account", "list"]),
            MITRETechnique("T1083", "File and Directory Discovery", MITRETactic.DISCOVERY,
                           "Enumerating files and directories",
                           ["ls", "dir", "find", "locate", "path traversal"]),
            MITRETechnique("T1046", "Network Service Scanning", MITRETactic.DISCOVERY,
                           "Scanning for network services",
                           ["scan", "probe", "enumerate", "nmap"]),
            MITRETechnique("T1005", "Data from Local System", MITRETactic.COLLECTION,
                           "Collecting data from local system",
                           ["read", "cat", "download", "file"]),
            MITRETechnique("T1213", "Data from Information Repositories", MITRETactic.COLLECTION,
                           "Collecting data from repositories",
                           ["database", "select", "dump", "export"]),
            MITRETechnique("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION,
                           "Exfiltrating data over command and control channel",
                           ["exfiltrate", "upload", "send", "post"]),
        ]
        for tech in techniques:
            self.techniques[tech.technique_id] = tech

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        return self.techniques.get(technique_id)

    def search_by_pattern(self, pattern: str) -> List[MITRETechnique]:
        pattern_lower = pattern.lower()
        matches = []
        seen_ids = set()
        for tech in self.techniques.values():
            for detect in tech.detection_patterns:
                if re.search(rf'\b{re.escape(detect)}\b', pattern_lower):
                    if tech.technique_id not in seen_ids:
                        matches.append(tech)
                        seen_ids.add(tech.technique_id)
                    break
        return matches

# =========================
# ATTACK TO MITRE MAPPER
# =========================
class AttackToMITREMapper:
    def __init__(self):
        self.technique_db = MITRETechniqueDatabase()
        self.attacker_profiles: Dict[str, TTPProfile] = {}

    def map_attack(self, attack_type: str, payload: str, attacker_id: Optional[str] = None) -> List[AttackMapping]:
        mappings = []
        added_techniques = set()
        search_text = f"{attack_type} {payload}".lower()
        matching_techniques = self.technique_db.search_by_pattern(search_text)

        for tech in matching_techniques:
            if tech.technique_id in added_techniques:
                continue
            confidence = self._calculate_confidence(attack_type, payload, tech)
            if confidence > 0.3:
                mapping = AttackMapping(attack_type, payload, tech, confidence, attacker_id=attacker_id)
                mappings.append(mapping)
                added_techniques.add(tech.technique_id)

        mappings.sort(key=lambda x: x.confidence, reverse=True)

        if attacker_id and mappings:
            self._update_attacker_profile(attacker_id, mappings[0])

        return mappings

    def _calculate_confidence(self, attack_type: str, payload: str, technique: MITRETechnique) -> float:
        score = 0.0
        search_text = f"{attack_type} {payload}".lower()
        for pattern in technique.detection_patterns:
            if re.search(rf'\b{re.escape(pattern)}\b', search_text):
                if pattern in attack_type.lower():
                    score += 0.5
                else:
                    score += 0.3
        return min(score, 1.0)

    def _update_attacker_profile(self, attacker_id: str, mapping: AttackMapping):
        if attacker_id not in self.attacker_profiles:
            self.attacker_profiles[attacker_id] = TTPProfile(attacker_id)
        self.attacker_profiles[attacker_id].add_mapping(mapping)

    def get_attacker_ttp_profile(self, attacker_id: str) -> Optional[TTPProfile]:
        return self.attacker_profiles.get(attacker_id)

    def get_ttp_summary(self, attacker_id: str) -> Dict:
        profile = self.get_attacker_ttp_profile(attacker_id)
        if not profile:
            return {"error": "No TTP data for attacker"}
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
        profile = self.get_attacker_ttp_profile(attacker_id)
        if not profile:
            return {}
        matrix = {"attacker_id": attacker_id, "tactics": [], "techniques_by_tactic": {}}
        for tactic in MITRETactic:
            tactic_techniques = [
                {
                    "id": m.technique.technique_id,
                    "name": m.technique.name,
                    "count": sum(1 for x in profile.attack_mappings if x.technique.technique_id == m.technique.technique_id)
                }
                for m in profile.attack_mappings if m.technique.tactic == tactic
            ]
            if tactic_techniques:
                matrix["tactics"].append(tactic.name)
                matrix["techniques_by_tactic"][tactic.name] = tactic_techniques
        return matrix

    def get_all_attacker_ttps(self) -> List[Dict]:
        return [self.get_ttp_summary(aid) for aid in self.attacker_profiles.keys()]

# =========================
# APT PATTERN MATCHER
# =========================
class APTPatternMatcher:
    def __init__(self):
        self.apt_signatures = {
            "APT28": {"tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.CREDENTIAL_ACCESS],
                      "techniques": ["T1190", "T1110"], "description": "Fancy Bear - Known for credential harvesting"},
            "APT29": {"tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.PERSISTENCE],
                      "techniques": ["T1190", "T1505"], "description": "Cozy Bear - Web application exploitation"},
            "APT41": {"tactics": [MITRETactic.INITIAL_ACCESS, MITRETactic.EXFILTRATION],
                      "techniques": ["T1190", "T1041"], "description": "Double Dragon - Data theft operations"}
        }

    def match_apt(self, ttp_profile: TTPProfile) -> List[Tuple[str, float]]:
        matches = []
        for apt_name, sig in self.apt_signatures.items():
            score = 0.0
            tactic_overlap = len(set(sig["tactics"]) & ttp_profile.tactics_used)
            if tactic_overlap > 0:
                score += (tactic_overlap / len(sig["tactics"])) * 0.5
            attacker_tech_ids = {t.technique_id for t in ttp_profile.techniques_used}
            technique_overlap = len(set(sig["techniques"]) & attacker_tech_ids)
            if technique_overlap > 0:
                score += (technique_overlap / len(sig["techniques"])) * 0.5
            if score > 0.3:
                matches.append((apt_name, score))
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

# =========================
# GLOBAL INSTANCE
# =========================
_mitre_mapper = AttackToMITREMapper()
_apt_matcher = APTPatternMatcher()

def map_attack_to_mitre(attack_type: str, payload: str, attacker_id: Optional[str] = None) -> List[AttackMapping]:
    return _mitre_mapper.map_attack(attack_type, payload, attacker_id)

def get_attacker_ttps(attacker_id: str) -> Dict:
    return _mitre_mapper.get_ttp_summary(attacker_id)

def get_mitre_matrix(attacker_id: str) -> Dict:
    return _mitre_mapper.generate_attack_matrix(attacker_id)

def match_to_apt_groups(attacker_id: str) -> List[Tuple[str, float]]:
    profile = _mitre_mapper.get_attacker_ttp_profile(attacker_id)
    if profile:
        return _apt_matcher.match_apt(profile)
    return []
