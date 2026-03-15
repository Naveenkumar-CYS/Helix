"""
Advanced Deception Engine
Provides realistic timing delays, believable errors, and polymorphic responses.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import random
import time
from datetime import datetime


# =========================
# ENUMS
# =========================
class DelayType(Enum):
    """Types of realistic delays."""
    DATABASE_QUERY = "database_query"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_REQUEST = "network_request"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"


class ErrorType(Enum):
    """Types of believable errors."""
    CONNECTION_TIMEOUT = "connection_timeout"
    CONNECTION_POOL_EXHAUSTED = "connection_pool_exhausted"
    PARTIAL_DATA = "partial_data"
    RATE_LIMIT = "rate_limit"
    INTERMITTENT_FAILURE = "intermittent_failure"
    DEPRECATED_WARNING = "deprecated_warning"


# =========================
# TIMING SIMULATOR
# =========================
@dataclass
class DelayConfig:
    """Configuration for realistic delays."""
    min_delay: float  # seconds
    max_delay: float  # seconds
    failure_rate: float = 0.0  # 0.0 to 1.0


class TimingSimulator:
    """Simulates realistic system timing delays."""
    
    def __init__(self):
        self.delay_configs = self._initialize_delays()
    
    def _initialize_delays(self) -> Dict[DelayType, DelayConfig]:
        """Define realistic delay ranges for different operations."""
        return {
            DelayType.DATABASE_QUERY: DelayConfig(0.05, 0.3, 0.02),
            DelayType.FILE_READ: DelayConfig(0.02, 0.15, 0.01),
            DelayType.FILE_WRITE: DelayConfig(0.1, 0.5, 0.03),
            DelayType.NETWORK_REQUEST: DelayConfig(0.1, 1.0, 0.05),
            DelayType.AUTHENTICATION: DelayConfig(0.2, 0.8, 0.01),
            DelayType.ENCRYPTION: DelayConfig(0.05, 0.2, 0.0),
        }
    
    def apply_delay(self, delay_type: DelayType) -> Optional[str]:
        """
        Apply realistic delay for operation type.
        
        Returns:
            Error message if operation "failed", None otherwise
        """
        config = self.delay_configs.get(delay_type, DelayConfig(0.1, 0.3))
        
        # Apply delay
        delay = random.uniform(config.min_delay, config.max_delay)
        time.sleep(delay)
        
        # Simulate occasional failures
        if random.random() < config.failure_rate:
            return self._generate_timeout_error(delay_type)
        
        return None
    
    def _generate_timeout_error(self, delay_type: DelayType) -> str:
        """Generate realistic timeout error message."""
        errors = {
            DelayType.DATABASE_QUERY: "Database query timeout after 30s",
            DelayType.FILE_READ: "File read operation timed out",
            DelayType.FILE_WRITE: "File write operation failed: disk busy",
            DelayType.NETWORK_REQUEST: "Connection timeout: remote host not responding",
            DelayType.AUTHENTICATION: "Authentication service unavailable",
            DelayType.ENCRYPTION: "Encryption operation failed",
        }
        return errors.get(delay_type, "Operation timed out")


# =========================
# ERROR GENERATOR
# =========================
class BelievableErrorGenerator:
    """Generates realistic system errors and warnings."""
    
    def __init__(self):
        self.error_templates = self._initialize_error_templates()
    
    def _initialize_error_templates(self) -> Dict[ErrorType, List[str]]:
        """Define realistic error message templates."""
        return {
            ErrorType.CONNECTION_TIMEOUT: [
                "Error: Connection timeout after {timeout}s",
                "Database connection lost: timeout exceeded",
                "MySQL server has gone away (timeout)",
            ],
            ErrorType.CONNECTION_POOL_EXHAUSTED: [
                "Error: Connection pool exhausted (max: {max_conn})",
                "Too many connections (current: {current}, max: {max_conn})",
                "Warning: Connection pool at 95% capacity",
            ],
            ErrorType.PARTIAL_DATA: [
                "Warning: Query returned partial results ({count}/{total} rows)",
                "Data truncated: result set too large",
                "Notice: Showing first {count} of {total} results",
            ],
            ErrorType.RATE_LIMIT: [
                "Rate limit exceeded: {requests} requests in {window}s",
                "Too many requests: please wait {wait}s",
                "Warning: Approaching rate limit ({current}/{max} requests)",
            ],
            ErrorType.INTERMITTENT_FAILURE: [
                "Temporary failure: retrying in {retry}s",
                "Service temporarily unavailable",
                "Warning: High server load detected",
            ],
            ErrorType.DEPRECATED_WARNING: [
                "Warning: mysql_query() is deprecated, use mysqli_query()",
                "Notice: This feature will be removed in version {version}",
                "Deprecated: {feature} is deprecated since version {version}",
            ],
        }
    
    def generate_error(
        self,
        error_type: ErrorType,
        **kwargs
    ) -> str:
        """
        Generate a believable error message.
        
        Args:
            error_type: Type of error to generate
            **kwargs: Template variables
            
        Returns:
            Formatted error message
        """
        templates = self.error_templates.get(error_type, ["Unknown error"])
        template = random.choice(templates)
        
        # Fill in default values if not provided
        defaults = {
            "timeout": random.randint(15, 60),
            "max_conn": random.choice([100, 150, 200]),
            "current": random.randint(95, 150),
            "count": random.randint(10, 100),
            "total": random.randint(500, 5000),
            "requests": random.randint(100, 500),
            "window": random.choice([60, 300, 3600]),
            "wait": random.randint(30, 300),
            "retry": random.randint(1, 10),
            "version": random.choice(["2.0", "3.0", "4.0"]),
            "feature": "legacy_auth",
        }
        
        # Merge with provided kwargs
        params = {**defaults, **kwargs}
        
        try:
            return template.format(**params)
        except KeyError:
            return template


# =========================
# POLYMORPHIC RESPONSE SYSTEM
# =========================
class PolymorphicResponseGenerator:
    """Generates varied responses to avoid fingerprinting."""
    
    def __init__(self):
        self.response_variants = self._initialize_variants()
    
    def _initialize_variants(self) -> Dict[str, List[str]]:
        """Define response variations for common outputs."""
        return {
            "success": [
                "200 OK",
                "Success",
                "OK",
                "Request processed successfully",
            ],
            "sql_error": [
                "MySQL error: You have an error in your SQL syntax",
                "Warning: mysql_fetch_array() expects parameter 1 to be resource",
                "Error in SQL query near '{payload}'",
                "Database error: syntax error at or near '{payload}'",
            ],
            "access_denied": [
                "Access denied",
                "403 Forbidden",
                "Unauthorized access",
                "Permission denied",
            ],
            "not_found": [
                "404 Not Found",
                "Page not found",
                "Resource not found",
                "The requested URL was not found",
            ],
        }
    
    def generate_variant(self, response_type: str, **kwargs) -> str:
        """
        Generate a polymorphic response variant.
        
        Args:
            response_type: Type of response
            **kwargs: Template variables
            
        Returns:
            Varied response string
        """
        variants = self.response_variants.get(response_type, ["OK"])
        template = random.choice(variants)
        
        try:
            return template.format(**kwargs)
        except KeyError:
            return template


# =========================
# FAKE SECURITY MEASURES
# =========================
class FakeSecurityMeasures:
    """Simulates security measures that can be bypassed."""
    
    def __init__(self):
        self.rate_limit_counter: Dict[str, List[datetime]] = {}
    
    def check_rate_limit(
        self,
        attacker_id: str,
        limit: int = 100,
        window: int = 60
    ) -> Optional[str]:
        """
        Fake rate limiting that can be bypassed.
        
        Args:
            attacker_id: Attacker identifier
            limit: Max requests per window
            window: Time window in seconds
            
        Returns:
            Warning message if "approaching" limit, None otherwise
        """
        now = datetime.now()
        
        # Initialize counter for new attacker
        if attacker_id not in self.rate_limit_counter:
            self.rate_limit_counter[attacker_id] = []
        
        # Clean old requests outside window
        cutoff = now.timestamp() - window
        self.rate_limit_counter[attacker_id] = [
            ts for ts in self.rate_limit_counter[attacker_id]
            if ts.timestamp() > cutoff
        ]
        
        # Add current request
        self.rate_limit_counter[attacker_id].append(now)
        
        # Count requests in window
        count = len(self.rate_limit_counter[attacker_id])
        
        # Return warning at 80% of limit (but don't actually block)
        if count > limit * 0.8:
            return f"Warning: Rate limit approaching ({count}/{limit} requests in {window}s)"
        
        return None
    
    def check_waf(self, payload: str) -> Optional[str]:
        """
        Fake WAF that detects but doesn't block.
        
        Returns:
            Warning message for "detected" attacks
        """
        # Detect obvious attack patterns
        dangerous_patterns = ["union", "select", "drop", "insert", "<script>", "javascript:"]
        
        if any(pattern in payload.lower() for pattern in dangerous_patterns):
            # 20% chance to show WAF warning (but still process request)
            if random.random() < 0.2:
                return "WAF Alert: Suspicious pattern detected (logged)"
        
        return None
    
    def generate_fake_captcha(self) -> str:
        """Generate fake CAPTCHA that accepts any input."""
        captcha_id = random.randint(100000, 999999)
        return f"CAPTCHA required: Please solve {captcha_id} (any answer accepted)"


# =========================
# DECEPTION ENGINE
# =========================
class DeceptionEngine:
    """Main deception engine coordinating all deception tactics."""
    
    def __init__(self):
        self.timing = TimingSimulator()
        self.errors = BelievableErrorGenerator()
        self.polymorphic = PolymorphicResponseGenerator()
        self.security = FakeSecurityMeasures()
    
    def apply_realistic_delay(self, operation_type: DelayType) -> Optional[str]:
        """Apply realistic delay and return error if operation "failed"."""
        return self.timing.apply_delay(operation_type)
    
    def generate_error(self, error_type: ErrorType, **kwargs) -> str:
        """Generate believable error message."""
        return self.errors.generate_error(error_type, **kwargs)
    
    def get_polymorphic_response(self, response_type: str, **kwargs) -> str:
        """Get varied response to avoid fingerprinting."""
        return self.polymorphic.generate_variant(response_type, **kwargs)
    
    def check_security_measures(
        self,
        attacker_id: str,
        payload: str
    ) -> List[str]:
        """
        Check fake security measures and return warnings.
        
        Returns:
            List of warning messages (but doesn't block)
        """
        warnings = []
        
        # Check rate limit
        rate_warning = self.security.check_rate_limit(attacker_id)
        if rate_warning:
            warnings.append(rate_warning)
        
        # Check WAF
        waf_warning = self.security.check_waf(payload)
        if waf_warning:
            warnings.append(waf_warning)
        
        return warnings
    
    def should_add_intermittent_failure(self, failure_rate: float = 0.05) -> bool:
        """Randomly decide if operation should fail."""
        return random.random() < failure_rate


# =========================
# GLOBAL INSTANCE
# =========================
_engine = DeceptionEngine()


def apply_deception_delay(operation_type: DelayType) -> Optional[str]:
    """Apply realistic delay (convenience function)."""
    return _engine.apply_realistic_delay(operation_type)


def generate_deception_error(error_type: ErrorType, **kwargs) -> str:
    """Generate believable error (convenience function)."""
    return _engine.generate_error(error_type, **kwargs)


def get_polymorphic_response(response_type: str, **kwargs) -> str:
    """Get polymorphic response (convenience function)."""
    return _engine.get_polymorphic_response(response_type, **kwargs)


def check_fake_security(attacker_id: str, payload: str) -> List[str]:
    """Check fake security measures (convenience function)."""
    return _engine.check_security_measures(attacker_id, payload)
