"""
VaultSentry - Base Configuration & Dynamic Path Resolver
Ensures path portability across developer machines and PyInstaller executables.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict


def get_base_dir() -> Path:
    """
    Calculates the root path of the VaultSentry workspace dynamically.
    Handles both raw dev environment and frozen PyInstaller execution.
    """
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)  # type: ignore

    # Path of config.py: src/VaultSentry.Engine/config.py -> .parent.parent.parent gets repository root
    return Path(__file__).resolve().parent.parent.parent


# Centralized Path Mapping matching actual folder layout on disk
BASE_DIR: Path = get_base_dir()
SRC_DIR: Path = BASE_DIR / "src"
ENGINE_DIR: Path = SRC_DIR / "VaultSentry.Engine"
CLIENT_DIR: Path = SRC_DIR / "VaultSentry.Client"


def _load_settings() -> Dict[str, Any]:
    settings_path = BASE_DIR / "config" / "settings.json"
    with settings_path.open("r", encoding="utf-8") as settings_file:
        settings = json.load(settings_file)

    if not isinstance(settings, dict) or not isinstance(settings.get("VaultSentry"), dict):
        raise ValueError(f"Invalid VaultSentry settings structure in {settings_path}")

    return settings["VaultSentry"]


SETTINGS: Dict[str, Any] = _load_settings()
ENGINE_SETTINGS = SETTINGS.get("Engine")
QUARANTINE_SETTINGS = SETTINGS.get("Quarantine")

if not isinstance(ENGINE_SETTINGS, dict):
    raise ValueError("VaultSentry Engine settings must be an object.")
if not isinstance(QUARANTINE_SETTINGS, dict):
    raise ValueError("VaultSentry Quarantine settings must be an object.")

ENGINE_RELATIVE_PATH = ENGINE_SETTINGS.get("RelativePath")
ENGINE_MODULE_NAME = ENGINE_SETTINGS.get("ModuleName")
ENGINE_TIMEOUT_SECONDS = ENGINE_SETTINGS.get("TimeoutSeconds")
QUARANTINE_STORAGE_PATH = QUARANTINE_SETTINGS.get("StoragePath")
QUARANTINE_AUTO_PURGE_DAYS = QUARANTINE_SETTINGS.get("AutoPurgeDays")

if not isinstance(ENGINE_RELATIVE_PATH, str) or not ENGINE_RELATIVE_PATH.strip():
    raise ValueError("VaultSentry Engine.RelativePath must be a non-empty string.")
if not isinstance(ENGINE_TIMEOUT_SECONDS, int) or ENGINE_TIMEOUT_SECONDS <= 0:
    raise ValueError("VaultSentry Engine.TimeoutSeconds must be a positive integer.")
if not isinstance(QUARANTINE_STORAGE_PATH, str) or not QUARANTINE_STORAGE_PATH.strip():
    raise ValueError("VaultSentry Quarantine.StoragePath must be a non-empty string.")
if not isinstance(QUARANTINE_AUTO_PURGE_DAYS, int) or QUARANTINE_AUTO_PURGE_DAYS <= 0:
    raise ValueError("VaultSentry Quarantine.AutoPurgeDays must be a positive integer.")


def _resolve_configured_path(configured_path: str) -> Path:
    path = Path(configured_path)
    return (path if path.is_absolute() else BASE_DIR / path).resolve()


# Security Runtime & Sandbox Folders
QUARANTINE_DIR: Path = _resolve_configured_path(QUARANTINE_STORAGE_PATH)
LOGS_DIR: Path = BASE_DIR / "logs"
RULES_DIR: Path = BASE_DIR / "config"
YARA_RULES_DIR: Path = RULES_DIR / "yara"
CLAMAV_DIR: Path = ENGINE_DIR / "rules" / "clamav"


def init_workspace_directories() -> None:
    """Ensures required local runtime paths exist."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
    CLAMAV_DIR.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    init_workspace_directories()
    print(f"[+] VaultSentry Base Directory set to: {BASE_DIR}")
    print(f"[+] Engine Directory set to: {ENGINE_DIR}")
    print(f"[+] Quarantine Storage located at: {QUARANTINE_DIR}")