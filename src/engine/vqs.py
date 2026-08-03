"""
VaultSentry - Module 1: Virtual Quarantine Space (VQS)
Provides secure file isolation, path sanitization, and read-only staging 
for untrusted downloads prior to static analysis execution.
"""

import os
import shutil
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from src.engine.config import QUARANTINE_DIR, LOGS_DIR

# Set up dedicated VQS Logger
LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOGS_DIR / "vqs.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (VQS): %(message)s"
)

class VirtualQuarantineSpace:
    """
    Manages the lifecycle of untrusted files within an isolated filesystem staging area.
    """

    def __init__(self, storage_dir: Path = QUARANTINE_DIR) -> None:
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_filename(self, original_name: str) -> str:
        """
        Strips unsafe path traversal characters and normalizes file name.
        """
        filename = os.path.basename(original_name)
        # Remove null bytes or control characters
        cleaned = "".join(c for c in filename if c.isprintable() and c not in r'<>:"/\|?*')
        return cleaned if cleaned else "untrusted_sample.bin"

    def stage_file(self, source_path: str) -> Dict[str, Any]:
        """
        Copies an untrusted file into the Virtual Quarantine Space, assigns a UUID,
        and enforces read-only file permissions.

        :param source_path: Local path to the newly downloaded untrusted file.
        :return: Quarantine manifest dict containing file metadata and isolated path.
        """
        src = Path(source_path).resolve()
        
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"Target file for quarantine does not exist: {source_path}")

        file_uuid = str(uuid.uuid4())
        safe_name = self._sanitize_filename(src.name)
        
        # Isolated path uses UUID directory to prevent filename collision attacks
        quarantine_folder = self.storage_dir / file_uuid
        quarantine_folder.mkdir(parents=True, exist_ok=True)
        
        staged_file_path = quarantine_folder / safe_name

        try:
            # Copy file bytes into quarantine
            shutil.copy2(src, staged_file_path)

            # Security Hardening: Revoke write/execute permissions on staged file (Read-Only)
            os.chmod(staged_file_path, 0o444)

            logging.info(f"File '{src.name}' successfully staged in VQS at '{staged_file_path}' (UUID: {file_uuid})")

            return {
                "uuid": file_uuid,
                "original_name": src.name,
                "sanitized_name": safe_name,
                "staged_path": str(staged_file_path),
                "file_size_bytes": staged_file_path.stat().st_size,
                "status": "QUARANTINED_READ_ONLY"
            }

        except Exception as e:
            logging.error(f"Failed to quarantine file '{source_path}': {str(e)}")
            # Cleanup on failure
            if quarantine_folder.exists():
                shutil.rmtree(quarantine_folder, ignore_errors=True)
            raise RuntimeError(f"VQS Staging Failure: {str(e)}") from e

    def release_file(self, file_uuid: str, destination_dir: str) -> str:
        """
        Releases a verified file from VQS into the user's destination folder.
        """
        quarantine_folder = self.storage_dir / file_uuid
        if not quarantine_folder.exists():
            raise FileNotFoundError(f"No quarantined sample found for UUID: {file_uuid}")

        staged_files = list(quarantine_folder.glob("*"))
        if not staged_files:
            raise FileNotFoundError(f"Quarantine folder for UUID {file_uuid} is empty.")

        staged_file = staged_files[0]
        dest_path = Path(destination_dir).resolve() / staged_file.name

        # Restore write permissions for release
        os.chmod(staged_file, 0o666)
        shutil.move(str(staged_file), str(dest_path))
        
        # Remove quarantine folder container
        shutil.rmtree(quarantine_folder, ignore_errors=True)
        logging.info(f"File UUID {file_uuid} released from VQS to '{dest_path}'")
        
        return str(dest_path)

    def purge_file(self, file_uuid: str) -> bool:
        """
        Permanently deletes a malicious or rejected file from VQS.
        """
        quarantine_folder = self.storage_dir / file_uuid
        if quarantine_folder.exists():
            # Grant write permissions back to delete read-only files
            for root, _, files in os.walk(quarantine_folder):
                for f in files:
                    os.chmod(os.path.join(root, f), 0o666)
            shutil.rmtree(quarantine_folder)
            logging.info(f"File UUID {file_uuid} permanently purged from VQS.")
            return True
        return False


if __name__ == "__main__":
    vqs = VirtualQuarantineSpace()
    print("[+] Module 1: Virtual Quarantine Space (VQS) Engine initialized successfully.")