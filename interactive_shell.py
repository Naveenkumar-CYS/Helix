"""
Interactive Honeypot Shell
Provides fake admin chat, file system browser, and database shell.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import random


# =========================
# FAKE FILE SYSTEM
# =========================
class FakeFileSystem:
    """Simulates a realistic file system for browsing."""
    
    def __init__(self):
        self.structure = self._initialize_structure()
        self.current_dir = "/"
    
    def _initialize_structure(self) -> Dict[str, any]:
        """Create fake directory structure."""
        return {
            "/": {
                "type": "dir",
                "children": {
                    "home": {
                        "type": "dir",
                        "children": {
                            "admin": {
                                "type": "dir",
                                "children": {
                                    ".bash_history": {"type": "file", "size": "2.1 KB"},
                                    ".ssh": {
                                        "type": "dir",
                                        "children": {
                                            "id_rsa": {"type": "file", "size": "1.8 KB"},
                                            "id_rsa.pub": {"type": "file", "size": "400 B"},
                                            "authorized_keys": {"type": "file", "size": "800 B"},
                                        }
                                    },
                                    "backup.sh": {"type": "file", "size": "1.2 KB"},
                                }
                            }
                        }
                    },
                    "var": {
                        "type": "dir",
                        "children": {
                            "www": {
                                "type": "dir",
                                "children": {
                                    "html": {
                                        "type": "dir",
                                        "children": {
                                            "config.php": {"type": "file", "size": "4.2 KB"},
                                            ".env": {"type": "file", "size": "1.8 KB"},
                                            "index.php": {"type": "file", "size": "8.5 KB"},
                                        }
                                    }
                                }
                            },
                            "log": {
                                "type": "dir",
                                "children": {
                                    "apache2": {
                                        "type": "dir",
                                        "children": {
                                            "access.log": {"type": "file", "size": "42 MB"},
                                            "error.log": {"type": "file", "size": "8.4 MB"},
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "etc": {
                        "type": "dir",
                        "children": {
                            "passwd": {"type": "file", "size": "2.8 KB"},
                            "shadow": {"type": "file", "size": "1.5 KB"},
                            "mysql": {
                                "type": "dir",
                                "children": {
                                    "my.cnf": {"type": "file", "size": "4.8 KB"},
                                }
                            }
                        }
                    },
                    "tmp": {
                        "type": "dir",
                        "children": {
                            "backup_old.zip": {"type": "file", "size": "15.3 MB"},
                            "database.sql": {"type": "file", "size": "42.7 MB"},
                        }
                    }
                }
            }
        }
    
    def list_directory(self, path: str = None) -> str:
        """List directory contents."""
        if path is None:
            path = self.current_dir
        
        # Navigate to path
        node = self._navigate_to_path(path)
        
        if not node:
            return f"ls: cannot access '{path}': No such file or directory"
        
        if node["type"] != "dir":
            return f"ls: {path}: Not a directory"
        
        # Build output
        output = []
        for name, child in node.get("children", {}).items():
            if child["type"] == "dir":
                output.append(f"drwxr-xr-x  {name}/")
            else:
                size = child.get("size", "0 B")
                output.append(f"-rw-r--r--  {name}  {size}")
        
        return "\n".join(output) if output else "total 0"
    
    def read_file(self, path: str) -> str:
        """Read file contents."""
        node = self._navigate_to_path(path)
        
        if not node:
            return f"cat: {path}: No such file or directory"
        
        if node["type"] != "file":
            return f"cat: {path}: Is a directory"
        
        # Return fake file contents based on filename
        filename = path.split("/")[-1]
        return self._generate_file_content(filename)
    
    def _navigate_to_path(self, path: str) -> Optional[Dict]:
        """Navigate to path in file system."""
        if not path or path == "/":
            return self.structure["/"]
        
        parts = path.strip("/").split("/")
        node = self.structure["/"]
        
        for part in parts:
            if "children" not in node or part not in node["children"]:
                return None
            node = node["children"][part]
        
        return node
    
    def _generate_file_content(self, filename: str) -> str:
        """Generate fake file content."""
        if filename == "config.php":
            return """<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'admin123');
define('DB_NAME', 'production_db');
?>"""
        elif filename == ".env":
            return """DATABASE_URL=mysql://root:password@localhost:3306/production
SECRET_KEY=a3f8d9e2b1c4a5f6d7e8b9c0a1b2c3d4
API_KEY=sk_live_abc123def456ghi789
"""
        elif filename == "passwd":
            return """root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
"""
        else:
            return f"[Content of {filename}]"


# =========================
# FAKE DATABASE SHELL
# =========================
class FakeDatabaseShell:
    """Simulates MySQL database shell."""
    
    def __init__(self):
        self.databases = ["production_db", "staging_db", "backup_db"]
        self.current_db = None
        self.tables = {
            "production_db": ["users", "sessions", "orders", "payments", "customers"],
            "staging_db": ["users", "test_data"],
            "backup_db": ["users_backup_jan2024", "orders_archive"],
        }
    
    def execute_query(self, query: str) -> str:
        """Execute fake SQL query."""
        query_lower = query.lower().strip()
        
        # SHOW DATABASES
        if "show databases" in query_lower:
            return self._show_databases()
        
        # SHOW TABLES
        if "show tables" in query_lower:
            return self._show_tables()
        
        # USE database
        if query_lower.startswith("use "):
            db_name = query.split()[1].strip(";")
            return self._use_database(db_name)
        
        # SELECT queries
        if query_lower.startswith("select"):
            return self._handle_select(query)
        
        # DESCRIBE table
        if query_lower.startswith("describe") or query_lower.startswith("desc"):
            table = query.split()[1].strip(";")
            return self._describe_table(table)
        
        # Default response
        return "Query OK, 0 rows affected"
    
    def _show_databases(self) -> str:
        """Show available databases."""
        output = "+--------------------+\n"
        output += "| Database           |\n"
        output += "+--------------------+\n"
        for db in self.databases:
            output += f"| {db:<18} |\n"
        output += "+--------------------+\n"
        return output
    
    def _show_tables(self) -> str:
        """Show tables in current database."""
        if not self.current_db:
            return "ERROR: No database selected"
        
        tables = self.tables.get(self.current_db, [])
        output = f"+-------------------------+\n"
        output += f"| Tables_in_{self.current_db:<12} |\n"
        output += f"+-------------------------+\n"
        for table in tables:
            output += f"| {table:<23} |\n"
        output += f"+-------------------------+\n"
        return output
    
    def _use_database(self, db_name: str) -> str:
        """Switch to database."""
        if db_name in self.databases:
            self.current_db = db_name
            return f"Database changed to {db_name}"
        else:
            return f"ERROR: Unknown database '{db_name}'"
    
    def _handle_select(self, query: str) -> str:
        """Handle SELECT queries."""
        # Fake user data response
        if "from users" in query.lower():
            return """+----+----------+-------------------+----------------------------------+
| id | username | email             | password_hash                    |
+----+----------+-------------------+----------------------------------+
|  1 | admin    | admin@corp.com    | 5f4dcc3b5aa765d61d8327deb882cf99 |
|  2 | dev      | dev@corp.com      | e99a18c428cb38d5f260853678922e03 |
|  3 | test     | test@corp.com     | 098f6bcd4621d373cade4e832627b4f6 |
+----+----------+-------------------+----------------------------------+
3 rows in set"""
        
        return "Empty set"
    
    def _describe_table(self, table: str) -> str:
        """Describe table structure."""
        if table == "users":
            return """+---------------+--------------+------+-----+---------+----------------+
| Field         | Type         | Null | Key | Default | Extra          |
+---------------+--------------+------+-----+---------+----------------+
| id            | int(11)      | NO   | PRI | NULL    | auto_increment |
| username      | varchar(50)  | NO   | UNI | NULL    |                |
| email         | varchar(100) | NO   |     | NULL    |                |
| password_hash | varchar(255) | NO   |     | NULL    |                |
| role          | varchar(20)  | YES  |     | user    |                |
| created_at    | timestamp    | YES  |     | NULL    |                |
+---------------+--------------+------+-----+---------+----------------+"""
        
        return f"Table '{table}' doesn't exist"


# =========================
# FAKE ADMIN CHAT
# =========================
class FakeAdminChat:
    """Simulates admin chat/command interface."""
    
    def __init__(self):
        self.responses = self._initialize_responses()
    
    def _initialize_responses(self) -> Dict[str, List[str]]:
        """Initialize chat responses."""
        return {
            "help": [
                "Available commands: users, logs, backup, status, timeline",
            ],
            "users": [
                "Active users: admin, dev, test",
                "Total users: 3 active, 1 inactive",
            ],
            "logs": [
                "Recent logs:\n- [10:23] User login: admin\n- [10:25] Database query executed\n- [10:30] Backup started",
            ],
            "backup": [
                "Last backup: 2024-02-08 03:00:00\nStatus: Completed\nSize: 42.7 MB",
            ],
            "status": [
                "System Status:\n- CPU: 45%\n- Memory: 62%\n- Disk: 78%\n- Uptime: 42 days",
            ],
            "default": [
                "Command not recognized. Type 'help' for available commands.",
            ],
        }
    
    def process_command(self, command: str) -> str:
        """Process admin command."""
        command_lower = command.lower().strip()
        
        # Find matching response
        for key, responses in self.responses.items():
            if key in command_lower:
                return random.choice(responses)
        
        return random.choice(self.responses["default"])


# =========================
# INTERACTIVE SHELL
# =========================
class InteractiveShell:
    """Main interactive shell coordinator."""
    
    def __init__(self):
        self.file_system = FakeFileSystem()
        self.database = FakeDatabaseShell()
        self.admin_chat = FakeAdminChat()
    
    def execute_shell_command(self, command: str) -> str:
        """Execute shell command."""
        cmd_lower = command.lower().strip()
        
        if cmd_lower.startswith("ls"):
            path = command.split()[1] if len(command.split()) > 1 else None
            return self.file_system.list_directory(path)
        
        elif cmd_lower.startswith("cat"):
            if len(command.split()) < 2:
                return "cat: missing file operand"
            path = command.split()[1]
            return self.file_system.read_file(path)
        
        elif cmd_lower.startswith("pwd"):
            return self.file_system.current_dir
        
        elif cmd_lower in ["whoami", "id"]:
            return "admin"
        
        elif cmd_lower.startswith("ps"):
            return self._fake_process_list()
        
        else:
            return f"bash: {command.split()[0]}: command not found"
    
    def execute_sql_query(self, query: str) -> str:
        """Execute SQL query."""
        return self.database.execute_query(query)
    
    def process_admin_command(self, command: str) -> str:
        """Process admin panel command."""
        return self.admin_chat.process_command(command)
    
    def _fake_process_list(self) -> str:
        """Generate fake process list."""
        return """  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  123 ?        00:00:01 apache2
  124 ?        00:00:00 apache2
  125 ?        00:00:00 apache2
  456 ?        00:00:05 mysqld
  789 pts/0    00:00:00 bash
  790 pts/0    00:00:00 ps"""


# =========================
# GLOBAL INSTANCE
# =========================
_shell = InteractiveShell()


def execute_shell_command(command: str) -> str:
    """Execute shell command (convenience function)."""
    return _shell.execute_shell_command(command)


def execute_sql_query(query: str) -> str:
    """Execute SQL query (convenience function)."""
    return _shell.execute_sql_query(query)


def process_admin_command(command: str) -> str:
    """Process admin command (convenience function)."""
    return _shell.process_admin_command(command)
