"""
VaultSentry - Module 2 & 3: Identity & Integrity Scanner
Calculates cryptographic hashes, verifies Magic Byte headers, 
and detects double-extension spoofing (e.g., .pdf.exe).
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, List

from src.engine.scanners.base_scanner import BaseScanner

KNOWN_MAGIC_BYTES = {
    b"\x4d\x5a": {"family": "executable", "mime": "application/x-dosexec", "type": "PE Executable"},
    b"\x25\x50\x44\x46": {"family": "document", "mime": "application/pdf", "type": "PDF Document"},
    b"\x50\x4b\x03\x04": {"family": "archive", "mime": "application/zip", "type": "ZIP Archive"},
    b"\x37\x7a\xbc\xaf\x27\x1c": {"family": "archive", "mime": "application/x-7z-compressed", "type": "7z Archive"},
    b"\x52\x61\x72\x21\x1a\x07": {"family": "archive", "mime": "application/vnd.rar", "type": "RAR Archive"},
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": {"family": "document", "mime": "application/msword", "type": "Legacy Office Document"}
}

DANGEROUS_EXEC_EXTS = {".exe", ".scr", ".pif", ".bat", ".ps1", ".vbs", ".cmd", ".hta", ".js"}
DISGUISED_DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".txt", ".zip"}


class IdentityIntegrityScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "identity_integrity"

    def calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest()
        }

    def detect_file_identity(self, file_path: Path) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            header = f.read(16)

        for magic, meta in KNOWN_MAGIC_BYTES.items():
            if header.startswith(magic):
                return {
                    "matched": True,
                    "magic_hex": header[:len(magic)].hex().upper(),
                    "detected_type": meta["type"],
                    "mime_type": meta["mime"],
                    "family": meta["family"]
                }

        return {
            "matched": False,
            "magic_hex": header[:8].hex().upper(),
            "detected_type": "Unknown / Binary Stream",
            "mime_type": "application/octet-stream",
            "family": "unknown"
        }

    def scan(self, file_path: Path) -> Dict[str, Any]:
        """
        Unified entry point satisfying BaseScanner interface contract.
        """
        path = file_path.resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Target file does not exist: {file_path}")

        hashes = self.calculate_hashes(path)
        identity = self.detect_file_identity(path)

        warnings: List[str] = []
        spoofing_detected = False
        double_extension_detected = False

        suffixes = [s.lower() for s in path.suffixes]

        # 1. Double Extension Detection (e.g. invoice.pdf.exe)
        if len(suffixes) > 1:
            last_ext = suffixes[-1]
            second_last = suffixes[-2]

            if last_ext in DANGEROUS_EXEC_EXTS and second_last in DISGUISED_DOC_EXTS:
                double_extension_detected = True
                spoofing_detected = True
                warnings.append(
                    f"CRITICAL: Double extension detected! Disguised as '{second_last}' but executes as '{last_ext}'."
                )

        # 2. Header vs Primary Extension Mismatch
        if identity["matched"]:
            detected_family = identity["family"]
            primary_ext = path.suffix.lower()

            if primary_ext in DISGUISED_DOC_EXTS and detected_family == "executable":
                spoofing_detected = True
                warnings.append(
                    f"CRITICAL: File contains Executable header but uses disguised extension '{primary_ext}'"
                )

        return {
            "file_name": path.name,
            "file_size_bytes": path.stat().st_size,
            "file_extension": path.suffix.lower(),
            "hashes": hashes,
            "identity": identity,
            "spoofing_detected": spoofing_detected,
            "double_extension_detected": double_extension_detected,
            "warnings": warnings,
            "status": "COMPLETED"
        }