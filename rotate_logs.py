"""
Log Rotation Utility
Standalone script to rotate log files when they exceed size limits
"""

import os
from pathlib import Path

# Configuration
ATTACKS_FILE = "attacks.json"
MAX_LOG_SIZE_MB = 50
MAX_BACKUP_FILES = 10

def rotate_logs():
    """Rotate attacks.json if it exceeds maximum size."""
    log_file = Path(ATTACKS_FILE)
    
    if not log_file.exists():
        print(f"[INFO] {ATTACKS_FILE} does not exist yet")
        return
    
    file_size_mb = log_file.stat().st_size / (1024 * 1024)
    print(f"[INFO] Current log size: {file_size_mb:.2f}MB")
    
    if file_size_mb >= MAX_LOG_SIZE_MB:
        print(f"[ROTATION] Log file exceeds {MAX_LOG_SIZE_MB}MB, rotating...")
        
        # Rotate existing backups
        for i in range(MAX_BACKUP_FILES - 1, 0, -1):
            old_backup = Path(f"{ATTACKS_FILE}.{i}")
            new_backup = Path(f"{ATTACKS_FILE}.{i + 1}")
            
            if old_backup.exists():
                if i == MAX_BACKUP_FILES - 1:
                    old_backup.unlink()  # Delete oldest
                    print(f"[ROTATION] Deleted oldest backup: {old_backup.name}")
                else:
                    old_backup.rename(new_backup)
                    print(f"[ROTATION] Renamed {old_backup.name} → {new_backup.name}")
        
        # Rotate current file to .1
        backup_name = Path(f"{ATTACKS_FILE}.1")
        log_file.rename(backup_name)
        print(f"[ROTATION] Rotated {ATTACKS_FILE} → {backup_name.name}")
        print(f"[SUCCESS] Log rotation complete!")
    else:
        print(f"[INFO] No rotation needed (size: {file_size_mb:.2f}MB < {MAX_LOG_SIZE_MB}MB)")

if __name__ == "__main__":
    rotate_logs()
