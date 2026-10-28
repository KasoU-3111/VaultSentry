"""
VaultSentry - Module 6: Archive & Container Analysis Engine
Safely inspects ZIP, RAR, and 7z containers without arbitrary disk extraction.
Includes volumetric defenses against Decompression Quines (Zip Bombs) and flags encrypted evasion layers.
"""

import zipfile
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Tuple  # <-- FIXED: Added Tuple import

# Third-party archive dependencies
import py7zr
import rarfile

from plugins.base_scanner import BaseScanner


class ArchiveScanner(BaseScanner):
    """Static security inspector for compressed archives and nested file containers."""

    # Volumetric Defense Thresholds against Zip Bombs
    MAX_FILE_COUNT = 10000
    MAX_UNCOMPRESSED_SIZE_MB = 500
    MAX_COMPRESSION_RATIO = 200.0  # Uncompressed size / Compressed size

    SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".scr"}

    @property
    def scanner_id(self) -> str:
        return "ArchiveScanner"

    @property
    def priority(self) -> int:
        return 60

    def is_applicable(self, path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        ext = path.suffix.lower()
        return ext in {".zip", ".rar", ".7z"}

    @staticmethod
    def _inspect_member_path(member_path: str, findings: List[Dict[str, str]]) -> None:
        normalized_path = member_path.replace("\\", "/")
        windows_path = PureWindowsPath(member_path)
        has_traversal = (
            windows_path.is_absolute()
            or bool(windows_path.drive)
            or any(part == ".." for part in normalized_path.split("/"))
        )

        if has_traversal and not any(
            finding["finding"] == "Archive Path Traversal (Zip Slip) Detected"
            for finding in findings
        ):
            findings.append({
                "severity": "CRITICAL",
                "category": "Archive Analysis",
                "finding": "Archive Path Traversal (Zip Slip) Detected",
                "explanation": f"Archive contains a member path that escapes its extraction directory: {member_path}"
            })

    def _analyze_zip(self, path: Path, archive_size: int) -> Tuple[List[Dict[str, str]], int, int, bool]:
        findings: List[Dict[str, str]] = []
        total_uncompressed = 0
        file_count = 0
        is_encrypted = False

        try:
            with zipfile.ZipFile(path, 'r') as zf:
                for info in zf.infolist():
                    file_count += 1
                    total_uncompressed += info.file_size
                    self._inspect_member_path(info.filename, findings)

                    # Check for encryption evasion
                    if getattr(info, 'flag_bits', 0) & 0x1:
                        is_encrypted = True

                    # Zip Bomb Defense: File Count
                    if file_count > self.MAX_FILE_COUNT:
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Archive Analysis",
                            "finding": "Archive File Count Exceeded (Zip Bomb Indicator)",
                            "explanation": f"Archive contains more than {self.MAX_FILE_COUNT} files, indicating a potential resource exhaustion attack."
                        })
                        break

        except zipfile.BadZipFile:
            findings.append({
                "severity": "HIGH",
                "category": "Archive Analysis",
                "finding": "Malformed ZIP Structure",
                "explanation": "Archive headers are corrupted or intentionally malformed to evade parser detection."
            })

        return findings, total_uncompressed, file_count, is_encrypted

    def _analyze_rar(self, path: Path, archive_size: int) -> Tuple[List[Dict[str, str]], int, int, bool]:
        findings: List[Dict[str, str]] = []
        total_uncompressed = 0
        file_count = 0
        is_encrypted = False

        try:
            with rarfile.RarFile(path, 'r') as rf:
                is_encrypted = rf.needs_password()
                
                for info in rf.infolist():
                    file_count += 1
                    total_uncompressed += info.file_size
                    self._inspect_member_path(info.filename, findings)

                    if file_count > self.MAX_FILE_COUNT:
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Archive Analysis",
                            "finding": "Archive File Count Exceeded (Zip Bomb Indicator)",
                            "explanation": f"Archive contains more than {self.MAX_FILE_COUNT} files."
                        })
                        break

        except rarfile.Error as ex:
            findings.append({
                "severity": "HIGH",
                "category": "Archive Analysis",
                "finding": "Malformed RAR Structure",
                "explanation": f"RAR parser encountered a structural error: {str(ex)}"
            })

        return findings, total_uncompressed, file_count, is_encrypted

    def _analyze_7z(self, path: Path, archive_size: int) -> Tuple[List[Dict[str, str]], int, int, bool]:
        findings: List[Dict[str, str]] = []
        total_uncompressed = 0
        file_count = 0
        is_encrypted = False

        try:
            with py7zr.SevenZipFile(path, mode='r') as sz:
                is_encrypted = sz.password_protected
                
                for info in sz.list():
                    file_count += 1
                    total_uncompressed += info.uncompressed
                    self._inspect_member_path(info.filename, findings)

                    if file_count > self.MAX_FILE_COUNT:
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Archive Analysis",
                            "finding": "Archive File Count Exceeded (Zip Bomb Indicator)",
                            "explanation": f"Archive contains more than {self.MAX_FILE_COUNT} files."
                        })
                        break

        except py7zr.exceptions.Bad7zFile:
            findings.append({
                "severity": "HIGH",
                "category": "Archive Analysis",
                "finding": "Malformed 7z Structure",
                "explanation": "Archive headers are corrupted or intentionally malformed."
            })

        return findings, total_uncompressed, file_count, is_encrypted

    def scan(self, path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        ext = path.suffix.lower()
        archive_size = path.stat().st_size
        
        total_uncompressed = 0
        file_count = 0
        is_encrypted = False

        try:
            # Delegate to format-specific parser
            if ext == ".zip":
                fnd, total_uncompressed, file_count, is_encrypted = self._analyze_zip(path, archive_size)
            elif ext == ".rar":
                fnd, total_uncompressed, file_count, is_encrypted = self._analyze_rar(path, archive_size)
            elif ext == ".7z":
                fnd, total_uncompressed, file_count, is_encrypted = self._analyze_7z(path, archive_size)
            else:
                fnd = []
                
            findings.extend(fnd)

            # Volumetric Compression Ratio Check (Zip Bomb Defense)
            if archive_size > 0 and file_count > 0:
                compression_ratio = total_uncompressed / archive_size
                if compression_ratio > self.MAX_COMPRESSION_RATIO:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Archive Analysis",
                        "finding": f"Anomalous Compression Ratio ({compression_ratio:.1f}x)",
                        "explanation": f"Archive exhibits an extreme expansion ratio, highly indicative of a Zip Bomb designed to exhaust memory or disk space."
                    })

            # Encryption Evasion Check
            if is_encrypted:
                findings.append({
                    "severity": "HIGH",
                    "category": "Archive Analysis",
                    "finding": "Password Protected / Encrypted Archive",
                    "explanation": "Archive contents are encrypted, preventing deep static inspection. This is a common evasion technique for malware delivery."
                })

        except Exception as ex:
            findings.append({
                "severity": "HIGH",
                "category": "Archive Analysis",
                "finding": "Parser Engine Fault",
                "explanation": f"Archive parser encountered an unhandled container exception: {str(ex)}"
            })

        return {
            "scanner": self.scanner_id,
            "container_type": ext.strip('.').upper(),
            "file_count": file_count,
            "is_encrypted": is_encrypted,
            "findings_count": len(findings),
            "findings": findings
        }