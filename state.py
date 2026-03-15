"""
Honeypot State Management
Maintains realistic fake data and system state to deceive attackers.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


# =========================
# ENUMS
# =========================
class UserRole(Enum):
    """User role types."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    TESTER = "tester"
    USER = "user"


class FileType(Enum):
    """Sensitive file types commonly targeted."""
    CONFIG = "config"
    ENVIRONMENT = "environment"
    BACKUP = "backup"
    DATABASE = "database"
    CREDENTIAL = "credential"
    LOG = "log"


# =========================
# DATA MODELS
# =========================
@dataclass
class FakeUser:
    """Represents a fake user account."""
    id: int
    username: str
    email: str
    role: UserRole = UserRole.USER
    password_hash: Optional[str] = None
    created_at: Optional[str] = None
    last_login: Optional[str] = None
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for responses."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "is_active": self.is_active
        }


@dataclass
class FakeFile:
    """Represents a fake sensitive file."""
    filename: str
    file_type: FileType
    size: str = "0 KB"
    modified: Optional[str] = None
    permissions: str = "rw-r--r--"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for responses."""
        return {
            "filename": self.filename,
            "type": self.file_type.value,
            "size": self.size,
            "modified": self.modified,
            "permissions": self.permissions
        }


@dataclass
class ServerInfo:
    """Server configuration information."""
    os: str
    os_version: str
    web_server: str
    language: str
    database: str
    hostname: str = "web-prod-01"
    uptime: str = "42 days"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for responses."""
        return {
            "os": self.os,
            "os_version": self.os_version,
            "web_server": self.web_server,
            "language": self.language,
            "database": self.database,
            "hostname": self.hostname,
            "uptime": self.uptime
        }


# =========================
# HONEYPOT STATE
# =========================
class HoneypotState:
    """
    Centralized honeypot state with realistic fake data.
    
    This class maintains all the fake data that attackers will discover
    as they explore the honeypot system.
    """
    
    def __init__(self):
        self.users = self._initialize_users()
        self.files = self._initialize_files()
        self.server = self._initialize_server()
        self.sessions = self._initialize_sessions()
        self.databases = self._initialize_databases()
    
    def _initialize_users(self) -> List[FakeUser]:
        """Create fake user accounts with realistic details."""
        return [
            FakeUser(
                id=1,
                username="admin",
                email="admin@corp.com",
                role=UserRole.ADMIN,
                password_hash="5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of "password"
                created_at="2023-01-15 10:30:00",
                last_login="2024-02-08 09:15:23"
            ),
            FakeUser(
                id=2,
                username="dev",
                email="dev@corp.com",
                role=UserRole.DEVELOPER,
                password_hash="e99a18c428cb38d5f260853678922e03",  # MD5 of "abc123"
                created_at="2023-03-20 14:22:11",
                last_login="2024-02-07 16:45:09"
            ),
            FakeUser(
                id=3,
                username="test",
                email="test@corp.com",
                role=UserRole.TESTER,
                password_hash="098f6bcd4621d373cade4e832627b4f6",  # MD5 of "test"
                created_at="2023-05-10 11:00:00",
                last_login="2024-01-30 10:20:15"
            ),
            FakeUser(
                id=4,
                username="jsmith",
                email="j.smith@corp.com",
                role=UserRole.USER,
                password_hash="5ebe2294ecd0e0f08eab7690d2a6ee69",  # MD5 of "secret"
                created_at="2023-08-05 09:30:00",
                last_login="2024-02-05 14:30:00",
                is_active=False  # Inactive account - looks suspicious
            )
        ]
    
    def _initialize_files(self) -> List[FakeFile]:
        """Create fake sensitive files that attackers typically target."""
        return [
            FakeFile(
                filename="config.php",
                file_type=FileType.CONFIG,
                size="4.2 KB",
                modified="2024-01-15 10:30:22",
                permissions="rw-r--r--"
            ),
            FakeFile(
                filename=".env",
                file_type=FileType.ENVIRONMENT,
                size="1.8 KB",
                modified="2024-01-20 14:22:15",
                permissions="rw-------"
            ),
            FakeFile(
                filename="backup_old.zip",
                file_type=FileType.BACKUP,
                size="15.3 MB",
                modified="2023-12-01 03:00:00",
                permissions="rw-r--r--"
            ),
            FakeFile(
                filename="database.sql",
                file_type=FileType.DATABASE,
                size="42.7 MB",
                modified="2024-02-01 02:15:00",
                permissions="rw-------"
            ),
            FakeFile(
                filename="credentials.txt",
                file_type=FileType.CREDENTIAL,
                size="892 B",
                modified="2023-11-10 16:45:30",
                permissions="rw-------"
            ),
            FakeFile(
                filename="error.log",
                file_type=FileType.LOG,
                size="8.4 MB",
                modified="2024-02-08 12:00:00",
                permissions="rw-r--r--"
            ),
            FakeFile(
                filename=".git/config",
                file_type=FileType.CONFIG,
                size="256 B",
                modified="2024-01-05 11:20:00",
                permissions="rw-r--r--"
            )
        ]
    
    def _initialize_server(self) -> ServerInfo:
        """Create fake server configuration."""
        return ServerInfo(
            os="Ubuntu",
            os_version="20.04.6 LTS",
            web_server="Apache/2.4.41",
            language="PHP 7.4.3",
            database="MySQL 8.0.32",
            hostname="web-prod-01",
            uptime="42 days, 15 hours"
        )
    
    def _initialize_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Create fake active sessions."""
        return {
            "adm_9f3c2a1b7e": {
                "user_id": 1,
                "username": "admin",
                "role": "admin",
                "ip": "192.168.1.100",
                "created": "2024-02-08 09:15:23",
                "expires": "2024-02-08 17:15:23"
            },
            "dev_3a8f2c9d1e": {
                "user_id": 2,
                "username": "dev",
                "role": "developer",
                "ip": "192.168.1.105",
                "created": "2024-02-07 16:45:09",
                "expires": "2024-02-08 00:45:09"
            }
        }
    
    def _initialize_databases(self) -> Dict[str, List[str]]:
        """Create fake database structure."""
        return {
            "production_db": [
                "users",
                "sessions",
                "products",
                "orders",
                "customers",
                "payments",
                "audit_logs"
            ],
            "staging_db": [
                "users",
                "test_data",
                "sandbox"
            ],
            "backup_db": [
                "users_backup_jan2024",
                "orders_archive"
            ]
        }
    
    # =========================
    # QUERY METHODS
    # =========================
    def get_user_by_id(self, user_id: int) -> Optional[FakeUser]:
        """Retrieve user by ID."""
        for user in self.users:
            if user.id == user_id:
                return user
        return None
    
    def get_user_by_username(self, username: str) -> Optional[FakeUser]:
        """Retrieve user by username."""
        for user in self.users:
            if user.username.lower() == username.lower():
                return user
        return None
    
    def get_admin_users(self) -> List[FakeUser]:
        """Get all admin users."""
        return [u for u in self.users if u.role == UserRole.ADMIN]
    
    def get_files_by_type(self, file_type: FileType) -> List[FakeFile]:
        """Get all files of a specific type."""
        return [f for f in self.files if f.file_type == file_type]
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session by ID."""
        return self.sessions.get(session_id)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export entire state as dictionary."""
        return {
            "users": [u.to_dict() for u in self.users],
            "files": [f.to_dict() for f in self.files],
            "server": self.server.to_dict(),
            "sessions": self.sessions,
            "databases": self.databases
        }


# =========================
# GLOBAL STATE INSTANCE
# =========================
fake_state = HoneypotState()


# =========================
# CONVENIENCE FUNCTIONS
# =========================
def get_state() -> HoneypotState:
    """Get the global honeypot state instance."""
    return fake_state


def get_all_users() -> List[Dict[str, Any]]:
    """Get all users as dictionaries (for backward compatibility)."""
    return [u.to_dict() for u in fake_state.users]


def get_all_files() -> List[str]:
    """Get all filenames (for backward compatibility)."""
    return [f.filename for f in fake_state.files]


def get_server_info() -> Dict[str, Any]:
    """Get server info as dictionary (for backward compatibility)."""
    return fake_state.server.to_dict()