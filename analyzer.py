"""
Attack Pattern Analyzer
Detects common web attack patterns in incoming payloads.
"""

from typing import List
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Enumeration of detectable attack types."""
    NORMAL = "NORMAL"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "CMD_INJECTION"
    SSRF = "SSRF"
    AUTH_BYPASS = "Authentication Bypass"
    DESERIALIZATION = "Insecure Deserialization"


@dataclass
class AttackPattern:
    """Represents a detectable attack pattern."""
    attack_type: AttackType
    signatures: List[str]
    case_sensitive: bool = False
    
    def matches(self, payload: str) -> bool:
        """Check if payload matches any signature in this pattern."""
        search_payload = payload if self.case_sensitive else payload.lower()
        return any(sig in search_payload for sig in self.signatures)


class AttackAnalyzer:
    """
    Analyzes incoming payloads for common attack patterns.
    
    Patterns are checked in order, so place more specific patterns first
    to avoid false positives.
    """
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> List[AttackPattern]:
        """Define all attack patterns to detect."""
        return [
            # SQL Injection patterns
            AttackPattern(
                attack_type=AttackType.SQL_INJECTION,
                signatures=[
                    "union select",
                    " or 1=1",
                    "' or 1=1",
                    '" or 1=1',
                    "drop table",
                    "drop database",
                    "insert into",
                    "update set",
                    "delete from",
                    "' or '1'='1",
                    '" or "1"="1',
                    "admin'--",
                    "admin'#",
                ]
            ),
            
            # Cross-Site Scripting (XSS)
            AttackPattern(
                attack_type=AttackType.XSS,
                signatures=[
                    "<script>",
                    "</script>",
                    "javascript:",
                    "onerror=",
                    "onload=",
                    "onclick=",
                    "<img src=",
                    "<iframe",
                    "eval(",
                    "alert(",
                ]
            ),
            
            # Path Traversal
            AttackPattern(
                attack_type=AttackType.PATH_TRAVERSAL,
                signatures=[
                    "../",
                    "..\\",
                    "..%2f",
                    "..%5c",
                    "%2e%2e%2f",
                    "%2e%2e/",
                    "..%252f",
                ]
            ),
            
            # Command Injection
            AttackPattern(
                attack_type=AttackType.COMMAND_INJECTION,
                signatures=[
                    "cmd=",
                    ";ls",
                    ";cat",
                    ";rm",
                    ";wget",
                    ";curl",
                    "|ls",
                    "|cat",
                    "&ls",
                    "&cat",
                    "$(cat",
                    "$(ls",
                    "`cat",
                    "`ls",
                ]
            ),
            
            # Server-Side Request Forgery (SSRF)
            AttackPattern(
                attack_type=AttackType.SSRF,
                signatures=[
                    "http://localhost",
                    "http://127.0.0.1",
                    "http://169.254.169.254",  # AWS metadata endpoint
                    "http://metadata.google.internal",  # GCP metadata
                    "file://",
                    "gopher://",
                    "dict://",
                    "ftp://localhost",
                    "@localhost",
                    "@127.0.0.1",
                    "localhost:",
                    "0.0.0.0",
                ]
            ),
            
            # Authentication Bypass
            AttackPattern(
                attack_type=AttackType.AUTH_BYPASS,
                signatures=[
                    "admin:admin",
                    "root:root",
                    "test:test",
                    "guest:guest",
                    "default:default",
                    "password:password",
                    "user:user",
                    "administrator:administrator",
                ]
            ),
            
            # Insecure Deserialization
            AttackPattern(
                attack_type=AttackType.DESERIALIZATION,
                signatures=[
                    "__reduce__",
                    "pickle.loads",
                    "yaml.load",
                    "eval(",
                    "exec(",
                    "os.system",
                    "subprocess.",
                    "__import__",
                    "compile(",
                ]
            ),
        ]
    
    def analyze(self, payload: str) -> AttackType:
        """
        Analyze payload and return detected attack type.
        
        Args:
            payload: The request payload to analyze
            
        Returns:
            AttackType enum value representing the detected attack
        """
        if not payload:
            return AttackType.NORMAL
        
        # Check each pattern in order
        for pattern in self.patterns:
            if pattern.matches(payload):
                return pattern.attack_type
        
        return AttackType.NORMAL
    
    def get_attack_name(self, attack_type: AttackType) -> str:
        """Get the string representation of an attack type."""
        return attack_type.value
    
    def add_custom_pattern(self, pattern: AttackPattern) -> None:
        """
        Add a custom attack pattern to the analyzer.
        
        Useful for detecting honeypot-specific or emerging attack patterns.
        """
        self.patterns.append(pattern)


# =========================
# BACKWARD COMPATIBLE API
# =========================
_analyzer = AttackAnalyzer()

def analyze_request(payload: str) -> str:
    """
    Analyze a request payload for attack patterns.
    Maintains backward compatibility with original function signature.
    
    Args:
        payload: The request payload to analyze
        
    Returns:
        String representation of the attack type
    """
    attack_type = _analyzer.analyze(payload)
    return attack_type.value


# =========================
# EXAMPLE USAGE
# =========================
if __name__ == "__main__":
    # Test cases
    test_payloads = [
        ("' OR 1=1--", "SQL Injection"),
        ("<script>alert('xss')</script>", "XSS"),
        ("../../../etc/passwd", "PATH_TRAVERSAL"),
        (";cat /etc/passwd", "CMD_INJECTION"),
        ("http://localhost:8080/admin", "SSRF"),
        ("admin:admin", "Authentication Bypass"),
        ("pickle.loads(data)", "Insecure Deserialization"),
        ("normal query string", "NORMAL"),
    ]
    
    for payload, expected in test_payloads:
        result = analyze_request(payload)
        status = "PASS" if result == expected else "FAIL"
        print(f"{status} {payload[:30]:30} -> {result}")