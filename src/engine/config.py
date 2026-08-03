"""
VaultSentry - Base Configuration & Dynamic Path Resolver
Ensures path portability across developer machines and PyInstaller executables.
"""

import sys
from pathlib import Path

def get_base_dir() -> Path:
    """
    Calculates the root path of the VaultSentry workspace dynamically.
    Handles both raw dev environment and frozen PyInstaller execution.
    """
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)  # type: ignore
    
    # Path of config.py: src/engine/config.py -> .parent.parent.parent gets root
    return Path(__file__).resolve().parent.parent.parent

# Centralized Path Mapping
BASE_DIR: Path = get_base_dir()
SRC_DIR: Path = BASE_DIR / "src"
ENGINE_DIR: Path = SRC_DIR / "engine"
GUI_DIR: Path = SRC_DIR / "gui"

# Security Runtime & Sandbox Folders
QUARANTINE_DIR: Path = BASE_DIR / "quarantine_storage"
LOGS_DIR: Path = BASE_DIR / "logs"
RULES_DIR: Path = ENGINE_DIR / "rules"
YARA_RULES_DIR: Path = RULES_DIR / "yara"
CLAMAV_DIR: Path = RULES_DIR / "clamav"

def init_workspace_directories() -> None:
    """Ensures required local runtime paths exist."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
    CLAMAV_DIR.mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    init_workspace_directories()
    print(f"[+] VaultSentry Base Directory set to: {BASE_DIR}")
    print(f"[+] Quarantine Storage located at: {QUARANTINE_DIR}")