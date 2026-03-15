"""
Attack Logging Module
Centralized logging for honeypot attack events with structured output.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
import json
import logging


# =========================
# CONFIGURATION
# =========================
@dataclass
class LogConfig:
    """Logging configuration."""
    log_file: Path = Path("attacks.log")
    json_log_file: Optional[Path] = Path("attacks.json")
    max_field_length: int = 300
    encoding: str = "utf-8"
    use_utc: bool = True


# =========================
# ATTACK EVENT DATA MODEL
# =========================
@dataclass
class AttackEvent:
    """Structured representation of an attack event."""
    attacker_id: str
    endpoint: str
    attack_type: str
    payload: str
    llm_response: str
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    user_agent: Optional[str] = None
    
    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
        
        # Ensure attacker_id is never empty
        if not self.attacker_id:
            self.attacker_id = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime to ISO format string
        if isinstance(data['timestamp'], datetime):
            data['timestamp'] = data['timestamp'].isoformat()
        return data


# =========================
# LOGGING UTILITIES
# =========================
class FieldSanitizer:
    """Sanitizes log field values for safe output."""
    
    def __init__(self, max_length: int = 300):
        self.max_length = max_length
    
    def sanitize(self, value: Any) -> str:
        """
        Clean and truncate field value for logging.
        
        Args:
            value: Any value to sanitize
            
        Returns:
            Cleaned string safe for log output
        """
        if value is None:
            return ""
        
        # Convert to string
        clean_value = str(value)
        
        # Replace problematic characters
        clean_value = (
            clean_value
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            .replace("|", "/")  # Pipe conflicts with delimiter
        )
        
        # Truncate if needed
        if len(clean_value) > self.max_length:
            clean_value = clean_value[:self.max_length] + "..."
        
        return clean_value


class AttackLogger:
    """
    Centralized attack event logger with multiple output formats.
    
    Supports both human-readable pipe-delimited logs and JSON logs
    for easier parsing and analysis.
    """
    
    def __init__(self, config: Optional[LogConfig] = None):
        self.config = config or LogConfig()
        self.sanitizer = FieldSanitizer(self.config.max_field_length)
        
        # Ensure log directory exists
        self.config.log_file.parent.mkdir(parents=True, exist_ok=True)
        if self.config.json_log_file:
            self.config.json_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Set up standard Python logger for errors
        self.logger = logging.getLogger(__name__)
    
    def log_attack(
        self,
        attacker_id: str,
        endpoint: str,
        attack_type: str,
        payload: str,
        llm_response: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """
        Log an attack event to file(s).
        
        Args:
            attacker_id: Unique attacker identifier
            endpoint: The endpoint that was attacked
            attack_type: Type of attack detected
            payload: The attack payload
            llm_response: Honeypot's response
            ip: Attacker's IP address (optional)
            user_agent: Attacker's user agent (optional)
        """
        event = AttackEvent(
            attacker_id=attacker_id,
            endpoint=endpoint,
            attack_type=attack_type,
            payload=payload,
            llm_response=llm_response,
            ip=ip,
            user_agent=user_agent
        )
        
        try:
            # Write to pipe-delimited log
            self._write_text_log(event)
            
            # Write to JSON log if enabled
            if self.config.json_log_file:
                self._write_json_log(event)
        
        except Exception as e:
            self.logger.error(f"Failed to write attack log: {e}")
    
    def _write_text_log(self, event: AttackEvent) -> None:
        """Write event to human-readable pipe-delimited log."""
        timestamp = event.timestamp.isoformat()
        
        log_line = (
            f"{timestamp} | "
            f"attacker_id={self.sanitizer.sanitize(event.attacker_id)} | "
            f"ip={self.sanitizer.sanitize(event.ip)} | "
            f"endpoint={self.sanitizer.sanitize(event.endpoint)} | "
            f"attack_type={self.sanitizer.sanitize(event.attack_type)} | "
            f"payload={self.sanitizer.sanitize(event.payload)} | "
            f"llm_response={self.sanitizer.sanitize(event.llm_response)}"
        )
        
        # Add user agent if available
        if event.user_agent:
            log_line += f" | user_agent={self.sanitizer.sanitize(event.user_agent)}"
        
        log_line += "\n"
        
        with open(self.config.log_file, "a", encoding=self.config.encoding) as f:
            f.write(log_line)
    
    def _write_json_log(self, event: AttackEvent) -> None:
        """Write event to JSON log for easier parsing."""
        with open(self.config.json_log_file, "a", encoding=self.config.encoding) as f:
            json.dump(event.to_dict(), f, ensure_ascii=False)
            f.write("\n")
    
    def get_attacker_history(self, attacker_id: str) -> list:
        """
        Retrieve all events for a specific attacker from JSON log.
        
        Args:
            attacker_id: The attacker to look up
            
        Returns:
            List of attack events for this attacker
        """
        if not self.config.json_log_file or not self.config.json_log_file.exists():
            return []
        
        history = []
        try:
            with open(self.config.json_log_file, "r", encoding=self.config.encoding) as f:
                for line in f:
                    event = json.loads(line)
                    if event.get("attacker_id") == attacker_id:
                        history.append(event)
        except Exception as e:
            self.logger.error(f"Failed to read attacker history: {e}")
        
        return history


# =========================
# BACKWARD COMPATIBLE API
# =========================
_default_logger = AttackLogger()

def log_attack(
    attacker_id: str,
    ip: Optional[str],
    endpoint: str,
    attack_type: str,
    payload: str,
    llm_response: str
) -> None:
    """
    Log an attack event (backward compatible function).
    
    Args:
        attacker_id: Unique attacker identifier
        ip: Attacker's IP address
        endpoint: The endpoint that was attacked
        attack_type: Type of attack detected
        payload: The attack payload
        llm_response: Honeypot's response
    """
    _default_logger.log_attack(
        attacker_id=attacker_id,
        ip=ip,
        endpoint=endpoint,
        attack_type=attack_type,
        payload=payload,
        llm_response=llm_response
    )


def get_attacker_history(attacker_id: str) -> list:
    """
    Get attack history for a specific attacker.
    
    Args:
        attacker_id: The attacker ID to look up
        
    Returns:
        List of attack events for this attacker
    """
    return _default_logger.get_attacker_history(attacker_id)


def get_all_attacks() -> list:
    """
    Get all attack events from the JSON log.
    
    Returns:
        List of all attack events
    """
    if not _default_logger.config.json_log_file or not _default_logger.config.json_log_file.exists():
        return []
    
    attacks = []
    try:
        with open(_default_logger.config.json_log_file, "r", encoding=_default_logger.config.encoding) as f:
            for line in f:
                attacks.append(json.loads(line))
    except Exception as e:
        _default_logger.logger.error(f"Failed to read all attacks: {e}")
    
    return attacks
