"""
VaultSentry - Module 1: Virtual Quarantine Space (VQS)
Provides isolated file staging, permission stripping, and safe lifecycle management.
"""

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from config import QUARANTINE_DIR


class VirtualQuarantineSpace:
    """Enterprise Virtual Quarantine Space for isolated binary and document staging."""

    def __init__(self, base_storage_dir: Path = QUARANTINE_DIR) -> None:
        self.base_storage_dir = Path(base_storage_dir).resolve()
        self.base_storage_dir.mkdir(parents=True, exist_ok=True)

    def stage_file(self, source_path: Path) -> Dict[str, Any]:
        """
        Safely copies the target file into a dedicated UUID-isolated quarantine container
        and enforces read-only filesystem attributes.
        """
        resolved_source = Path(source_path).resolve()
        if not resolved_source.is_file():
            raise FileNotFoundError(f"Source file for quarantine staging does not exist: {resolved_source}")

        # 1. Generate unique container sandbox
        quarantine_id = str(uuid.uuid4())
        container_dir = self.base_storage_dir / quarantine_id
        container_dir.mkdir(parents=True, exist_ok=True)

        staged_path = container_dir / resolved_source.name

        # 2. Chunked stream copy to avoid file-lock contention
        with open(resolved_source, "rb") as f_src, open(staged_path, "wb") as f_dst:
            shutil.copyfileobj(f_src, f_dst, length=64 * 1024)

        # 3. Strip write and execute permissions (Read-Only 0o444)
        try:
            os.chmod(staged_path, 0o444)
        except OSError:
            pass

        return {
            "quarantine_id": quarantine_id,
            "original_name": resolved_source.name,
            "staged_path": str(staged_path),
            "staged_directory": str(container_dir),
            "isolation_timestamp": datetime.now(timezone.utc).isoformat()
        }

    def purge_container(self, quarantine_id: str) -> bool:
        """Permanently removes a quarantined container directory and its contents."""
        container_dir = self.base_storage_dir / quarantine_id
        if container_dir.exists() and container_dir.is_dir():
            # Restore write permissions to allow removal
            for item in container_dir.iterdir():
                try:
                    os.chmod(item, 0o666)
                except OSError:
                    pass
            shutil.rmtree(container_dir, ignore_errors=True)
            return True
        return False