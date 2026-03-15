"""
Dynamic Content Generator
LLM-powered generation of personalized fake data and canary tokens.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import random
import hashlib
import uuid


# =========================
# CANARY TOKEN SYSTEM
# =========================
@dataclass
class CanaryToken:
    """Represents a unique canary token for tracking data exfiltration."""
    token_id: str
    token_value: str
    token_type: str  # "credential", "api_key", "session", "database"
    attacker_id: str
    created_at: datetime = field(default_factory=datetime.now)
    accessed: bool = False
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    
    def mark_accessed(self) -> None:
        """Mark token as accessed."""
        self.accessed = True
        self.access_count += 1
        self.last_accessed = datetime.now()


class CanaryTokenGenerator:
    """Generates and tracks unique canary tokens."""
    
    def __init__(self):
        self.tokens: Dict[str, CanaryToken] = {}
    
    def generate_token(
        self,
        attacker_id: str,
        token_type: str
    ) -> str:
        """
        Generate a unique canary token.
        
        Args:
            attacker_id: Unique attacker identifier
            token_type: Type of token (credential, api_key, etc.)
            
        Returns:
            Token value
        """
        # Create unique token ID
        token_id = hashlib.sha256(
            f"{attacker_id}:{token_type}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Generate token value based on type
        if token_type == "api_key":
            token_value = f"sk_live_{uuid.uuid4().hex[:24]}"
        elif token_type == "session":
            token_value = f"sess_{uuid.uuid4().hex[:16]}"
        elif token_type == "database":
            token_value = f"db_{attacker_id[:8]}_{uuid.uuid4().hex[:12]}"
        else:  # credential
            token_value = f"pwd_{uuid.uuid4().hex[:12]}"
        
        # Create and store token
        token = CanaryToken(
            token_id=token_id,
            token_value=token_value,
            token_type=token_type,
            attacker_id=attacker_id
        )
        
        self.tokens[token_value] = token
        
        return token_value
    
    def check_token(self, token_value: str) -> Optional[CanaryToken]:
        """
        Check if a value is a canary token and mark as accessed.
        
        Returns:
            CanaryToken if found, None otherwise
        """
        if token_value in self.tokens:
            token = self.tokens[token_value]
            token.mark_accessed()
            return token
        return None
    
    def get_attacker_tokens(self, attacker_id: str) -> List[CanaryToken]:
        """Get all tokens generated for an attacker."""
        return [
            token for token in self.tokens.values()
            if token.attacker_id == attacker_id
        ]


# =========================
# PERSONALIZED DATA GENERATOR
# =========================
class PersonalizedDataGenerator:
    """Generates personalized fake data for each attacker."""
    
    def __init__(self, canary_generator: CanaryTokenGenerator):
        self.canary_generator = canary_generator
        self.attacker_data: Dict[str, Dict[str, Any]] = {}
    
    def generate_user_credentials(
        self,
        attacker_id: str,
        username: str
    ) -> Dict[str, str]:
        """
        Generate personalized user credentials with canary token.
        
        Returns:
            Dict with username, email, password_hash (with canary)
        """
        # Generate canary password
        canary_password = self.canary_generator.generate_token(
            attacker_id, "credential"
        )
        
        # Create password hash (MD5 for realism)
        password_hash = hashlib.md5(canary_password.encode()).hexdigest()
        
        return {
            "username": username,
            "email": f"{username}@corp.com",
            "password_hash": password_hash,
            "password_plain": canary_password  # "Accidentally" leaked
        }
    
    def generate_api_key(self, attacker_id: str) -> str:
        """Generate personalized API key with canary token."""
        return self.canary_generator.generate_token(attacker_id, "api_key")
    
    def generate_database_name(self, attacker_id: str) -> str:
        """Generate personalized database name with canary token."""
        return self.canary_generator.generate_token(attacker_id, "database")
    
    def generate_session_id(self, attacker_id: str) -> str:
        """Generate personalized session ID with canary token."""
        return self.canary_generator.generate_token(attacker_id, "session")
    
    def generate_fake_users_table(
        self,
        attacker_id: str,
        num_users: int = 3
    ) -> str:
        """
        Generate personalized fake users table with canary tokens.
        
        Returns:
            HTML table with fake user data
        """
        usernames = ["admin", "dev", "test", "jsmith", "dbadmin"][:num_users]
        
        html = """<!DOCTYPE html>
<html>
<body>
<h3>Users</h3>
<table border="1">
<tr><th>id</th><th>username</th><th>email</th><th>password</th></tr>
"""
        
        for idx, username in enumerate(usernames, 1):
            creds = self.generate_user_credentials(attacker_id, username)
            html += f"""<tr><td>{idx}</td><td>{creds['username']}</td><td>{creds['email']}</td><td>{creds['password_hash']}</td></tr>
"""
        
        html += """</table>
</body>
</html>"""
        
        return html
    
    def generate_config_file(self, attacker_id: str) -> str:
        """Generate fake config file with canary tokens."""
        api_key = self.generate_api_key(attacker_id)
        db_name = self.generate_database_name(attacker_id)
        
        return f"""# Application Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME={db_name}
DB_USER=root
DB_PASS=admin123

API_KEY={api_key}
API_SECRET=sk_secret_{uuid.uuid4().hex[:16]}

DEBUG=true
LOG_LEVEL=debug
"""
    
    def generate_env_file(self, attacker_id: str) -> str:
        """Generate fake .env file with canary tokens."""
        api_key = self.generate_api_key(attacker_id)
        
        return f"""DATABASE_URL=mysql://root:password@localhost:3306/production
SECRET_KEY={uuid.uuid4().hex}
API_KEY={api_key}
AWS_ACCESS_KEY_ID=AKIA{uuid.uuid4().hex[:16].upper()}
AWS_SECRET_ACCESS_KEY={uuid.uuid4().hex}
STRIPE_SECRET_KEY=sk_live_{uuid.uuid4().hex[:24]}
"""


# =========================
# DYNAMIC SCHEMA GENERATOR
# =========================
class DynamicSchemaGenerator:
    """Generates realistic database schemas on-the-fly."""
    
    def generate_table_schema(self, table_name: str) -> str:
        """Generate realistic table schema."""
        schemas = {
            "users": """CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user', 'developer') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);""",
            "sessions": """CREATE TABLE sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);""",
            "orders": """CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);""",
            "payments": """CREATE TABLE payments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_method VARCHAR(50),
    card_last4 VARCHAR(4),
    status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id)
);""",
        }
        
        return schemas.get(table_name, f"-- Schema for {table_name} not found")
    
    def generate_database_list(self) -> List[str]:
        """Generate list of fake databases."""
        return [
            "production_db",
            "staging_db",
            "backup_db",
            "test_db",
            "analytics_db",
            "logs_db"
        ]
    
    def generate_table_list(self, database: str) -> List[str]:
        """Generate list of tables for a database."""
        tables_map = {
            "production_db": ["users", "sessions", "orders", "payments", "customers", "products", "audit_logs"],
            "staging_db": ["users", "test_data", "sandbox"],
            "backup_db": ["users_backup_jan2024", "orders_archive", "sessions_old"],
            "test_db": ["test_users", "test_orders"],
            "analytics_db": ["page_views", "user_events", "conversions"],
            "logs_db": ["access_logs", "error_logs", "security_logs"],
        }
        
        return tables_map.get(database, ["data"])


# =========================
# CONTENT GENERATOR
# =========================
class ContentGenerator:
    """Main content generation engine."""
    
    def __init__(self):
        self.canary_generator = CanaryTokenGenerator()
        self.data_generator = PersonalizedDataGenerator(self.canary_generator)
        self.schema_generator = DynamicSchemaGenerator()
    
    def generate_personalized_users_table(
        self,
        attacker_id: str,
        num_users: int = 3
    ) -> str:
        """Generate personalized users table with canary tokens."""
        return self.data_generator.generate_fake_users_table(attacker_id, num_users)
    
    def generate_personalized_config(self, attacker_id: str) -> str:
        """Generate personalized config file."""
        return self.data_generator.generate_config_file(attacker_id)
    
    def generate_personalized_env(self, attacker_id: str) -> str:
        """Generate personalized .env file."""
        return self.data_generator.generate_env_file(attacker_id)
    
    def generate_session_id(self, attacker_id: str) -> str:
        """Generate personalized session ID."""
        return self.data_generator.generate_session_id(attacker_id)
    
    def check_canary_token(self, token_value: str) -> Optional[CanaryToken]:
        """Check if value is a canary token."""
        return self.canary_generator.check_token(token_value)
    
    def get_table_schema(self, table_name: str) -> str:
        """Get database table schema."""
        return self.schema_generator.generate_table_schema(table_name)
    
    def get_database_list(self) -> List[str]:
        """Get list of databases."""
        return self.schema_generator.generate_database_list()
    
    def get_table_list(self, database: str) -> List[str]:
        """Get list of tables in database."""
        return self.schema_generator.generate_table_list(database)


# =========================
# GLOBAL INSTANCE
# =========================
_generator = ContentGenerator()


def generate_personalized_content(
    attacker_id: str,
    content_type: str,
    **kwargs
) -> str:
    """
    Generate personalized content (convenience function).
    
    Args:
        attacker_id: Unique attacker identifier
        content_type: Type of content (users_table, config, env, etc.)
        **kwargs: Additional parameters
        
    Returns:
        Generated content string
    """
    if content_type == "users_table":
        return _generator.generate_personalized_users_table(
            attacker_id,
            kwargs.get("num_users", 3)
        )
    elif content_type == "config":
        return _generator.generate_personalized_config(attacker_id)
    elif content_type == "env":
        return _generator.generate_personalized_env(attacker_id)
    elif content_type == "session_id":
        return _generator.generate_session_id(attacker_id)
    else:
        return "Content type not supported"


def check_for_canary_token(token_value: str) -> Optional[CanaryToken]:
    """Check if value is a canary token (convenience function)."""
    return _generator.check_canary_token(token_value)
