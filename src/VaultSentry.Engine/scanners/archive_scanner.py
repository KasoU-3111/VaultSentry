"""
VaultSentry - Module 6: Archive Analysis Engine
Statically inspects .zip, .7z, and .rar container structures without extraction.
Detects Zip Bombs, Zip Slip traversals, password encryption, and nested payloads.
"""

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import py7zr

try:
    import rarfile  # type: ignore
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False

from plugins.base_scanner import BaseScanner


class ArchiveScanner(BaseScanner):
    """Enterprise static archive structure and threat inspection engine."""

    MAGIC_ZIP = b"PK\x03\x04"
    MAGIC_7Z = b"7z\xbc\xaf\x27\x1c"
    MAGIC_RAR4 = b"Rar!\x1a\x07\x00"
    MAGIC_RAR5 = b"Rar!\x1a\x07\x01\x00"
    MAGIC_GZIP = b"\x1f\x8b\x08"
    MAGIC_BZIP2 = b"BZh"
    MAGIC_XZ = b"\xfd7zXZ\x00"

    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".pif", ".bat", ".cmd", ".vbs",
        ".ps1", ".msi", ".iso", ".img", ".hta", ".js", ".wsf", ".cpl", ".com"
    }

    NESTED_EXTENSIONS = {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab"
    }

    @property
    def scanner_id(self) -> str:
        return "ArchiveScanner"

    @property
    def priority(self) -> int:
        return 50

    def __init__(
        self,
        max_ratio: float = 100.0,
        max_uncompressed_bytes: int = 524_288_000,
        max_total_entries: int = 10_000
    ) -> None:
        self.max_ratio = max_ratio
        self.max_uncompressed_bytes = max_uncompressed_bytes
        self.max_total_entries = max_total_entries

    def is_applicable(self, path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        if context:
            identity_report = context.get("IdentityScanner", {})
            family = identity_report.get("identity", {}).get("family")
            if family == "archive":
                return True

        ext = path.suffix.lower()
        if ext in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}:
            return True

        try:
            with open(path, "rb") as f:
                header = f.read(16)
                return (
                    header.startswith(self.MAGIC_ZIP) or
                    header.startswith(self.MAGIC_7Z) or
                    header.startswith(self.MAGIC_RAR4) or
                    header.startswith(self.MAGIC_RAR5) or
                    header.startswith(self.MAGIC_GZIP) or
                    header.startswith(self.MAGIC_BZIP2) or
                    header.startswith(self.MAGIC_XZ)
                )
        except Exception:
            return False

    def _detect_format(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                header = f.read(16)
                if header.startswith(self.MAGIC_ZIP):
                    return "ZIP"
                if header.startswith(self.MAGIC_7Z):
                    return "7Z"
                if header.startswith(self.MAGIC_RAR4) or header.startswith(self.MAGIC_RAR5):
                    return "RAR"
                if header.startswith(self.MAGIC_GZIP):
                    return "GZIP"
                if header.startswith(self.MAGIC_BZIP2):
                    return "BZIP2"
                if header.startswith(self.MAGIC_XZ):
                    return "XZ"
        except Exception:
            pass

        ext = path.suffix.lower()
        if ext == ".zip":
            return "ZIP"
        if ext == ".7z":
            return "7Z"
        if ext == ".rar":
            return "RAR"
        return "UNKNOWN"

    def _check_zip_slip(self, entry_name: str) -> bool:
        normalized = entry_name.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized):
            return True
        return "../" in normalized or "/.." in normalized

    def _evaluate_bomb(
        self,
        compressed: int,
        uncompressed: int,
        entry_count: int
    ) -> Tuple[bool, float, Optional[str]]:
        if entry_count > self.max_total_entries:
            return True, 0.0, f"Excessive entry count ({entry_count} files) indicates decompression exhaustion attack."

        if uncompressed > self.max_uncompressed_bytes:
            return True, 0.0, f"Uncompressed payload ({uncompressed:,} bytes) exceeds safety threshold of {self.max_uncompressed_bytes:,} bytes."

        if compressed <= 0 and uncompressed > 1_048_576:
            return True, 0.0, "Zero-size compressed footprint declaring positive payload size."

        if compressed > 0:
            ratio = round(uncompressed / compressed, 2)
            if ratio > self.max_ratio:
                return True, ratio, f"Extreme compression ratio ({ratio}:1) exceeds safety threshold of {self.max_ratio}:1."

        return False, 0.0, None

    def scan(self, path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        archive_type = self._detect_format(path)
        if archive_type == "UNKNOWN":
            return {
                "scanner": self.scanner_id,
                "is_archive": False,
                "findings": []
            }

        findings: List[Dict[str, str]] = []
        entries: List[str] = []
        has_password = False
        total_compressed = 0
        total_uncompressed = 0
        has_zip_slip = False

        try:
            if archive_type == "ZIP":
                with zipfile.ZipFile(path, "r") as zf:
                    for info in zf.infolist():
                        entries.append(info.filename)
                        total_compressed += info.compress_size
                        total_uncompressed += info.file_size
                        if info.flag_bits & 0x1:
                            has_password = True
                        if self._check_zip_slip(info.filename):
                            has_zip_slip = True

            elif archive_type == "7Z":
                with py7zr.SevenZipFile(path, mode="r") as sz:
                    has_password = sz.password_protected
                    for info in sz.list():
                        entries.append(info.filename)
                        total_compressed += info.compressed or 0
                        total_uncompressed += info.uncompressed or 0
                        if self._check_zip_slip(info.filename):
                            has_zip_slip = True

            elif archive_type == "RAR":
                if not RAR_AVAILABLE:
                    findings.append({
                        "severity": "INFO",
                        "category": "Archive Analysis",
                        "finding": "RAR Parser Library Unavailable",
                        "explanation": "rarfile module is not installed or unrar library is missing from system PATH."
                    })
                    return {
                        "scanner": self.scanner_id,
                        "is_archive": True,
                        "archive_type": "RAR",
                        "findings": findings
                    }
                with rarfile.RarFile(path, "r") as rf:
                    has_password = rf.needs_password()
                    for info in rf.infolist():
                        entries.append(info.filename)
                        total_compressed += info.compress_size
                        total_uncompressed += info.file_size
                        if self._check_zip_slip(info.filename):
                            has_zip_slip = True

            is_bomb, ratio, bomb_reason = self._evaluate_bomb(total_compressed, total_uncompressed, len(entries))
            if is_bomb:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Archive Analysis",
                    "finding": "Decompression Bomb (Zip Bomb) Detected",
                    "explanation": bomb_reason or "Archive parameters indicate intent to exhaust storage/memory."
                })

            if has_zip_slip:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Archive Analysis",
                    "finding": "Path Traversal (Zip Slip) Exploit Detected",
                    "explanation": "Archive contains entry paths with directory traversal sequences designed to escape quarantine isolation."
                })

            if has_password:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Archive Analysis",
                    "finding": "Encrypted / Password-Protected Archive",
                    "explanation": "Archive contents are encrypted. Static deep inspection of internal binaries cannot be completed."
                })

            dangerous_found = [e for e in entries if Path(e).suffix.lower() in self.DANGEROUS_EXTENSIONS]
            if dangerous_found:
                findings.append({
                    "severity": "HIGH",
                    "category": "Archive Analysis",
                    "finding": f"High-Risk Executable/Script Inside Archive ({len(dangerous_found)} found)",
                    "explanation": f"Archive encapsulates executable or script payload(s): {', '.join(dangerous_found[:3])}"
                })

            nested_found = [e for e in entries if Path(e).suffix.lower() in self.NESTED_EXTENSIONS]
            if nested_found:
                findings.append({
                    "severity": "LOW",
                    "category": "Archive Analysis",
                    "finding": f"Nested Secondary Archive Structures ({len(nested_found)} found)",
                    "explanation": f"Archive packages nested archive containers: {', '.join(nested_found[:2])}"
                })

            return {
                "scanner": self.scanner_id,
                "is_archive": True,
                "archive_type": archive_type,
                "file_count": len(entries),
                "has_password": has_password,
                "total_compressed_bytes": total_compressed,
                "total_uncompressed_bytes": total_uncompressed,
                "findings_count": len(findings),
                "findings": findings
            }

        except Exception as ex:
            findings.append({
                "severity": "HIGH",
                "category": "Archive Analysis",
                "finding": "Corrupted or Obfuscated Archive Structure",
                "explanation": f"Failed parsing archive container headers: {str(ex)}"
            })
            return {
                "scanner": self.scanner_id,
                "is_archive": True,
                "archive_type": archive_type,
                "findings": findings
            }