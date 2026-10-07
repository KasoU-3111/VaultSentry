"""
VaultSentry - Surface Expansion: Disk Image & Virtual Container Scanner
Statically inspects .iso, .img, .vhd, and .vhdx containers to detect Mark-of-the-Web (MOTW) evasion,
embedded executables, and autorun configurations.
"""

from pathlib import Path
from typing import Any, Dict, List

from src.engine.plugins.base_scanner import BaseScanner


class DiskImageScanner(BaseScanner):
    """Static security inspector for virtual disk images and ISO containers."""

    # Signatures
    MAGIC_ISO_PRIMARY = b"CD001"   # ISO 9660 volume descriptor at offset 0x8000 / 0x8800 / 0x9000
    MAGIC_VHD = b"conectix"        # VHD footer cookie
    MAGIC_VHDX = b"vhdxfile"       # VHDX header signature

    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".vbs",
        ".ps1", ".msi", ".hta", ".js", ".wsf", ".cpl", ".lnk"
    }

    def __init__(self) -> None:
        super().__init__(scanner_id="DiskImageScanner", priority=52)

    def is_applicable(self, path: Path, context: Dict[str, Any]) -> bool:
        ext = path.suffix.lower()
        if ext in {".iso", ".img", ".vhd", ".vhdx"}:
            return True
        try:
            with open(path, "rb") as f:
                header = f.read(16)
                if header.startswith(self.MAGIC_VHDX) or self.MAGIC_VHD in header:
                    return True
                # Check ISO 9660 signature offset at 32KB
                f.seek(0x8000)
                iso_head = f.read(6)
                if self.MAGIC_ISO_PRIMARY in iso_head:
                    return True
        except Exception:
            pass
        return False

    def scan(self, path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        ext = path.suffix.lower()

        # MOTW Container Evasion Alert
        findings.append({
            "severity": "HIGH",
            "category": "Container Analysis",
            "finding": "Mark-of-the-Web (MOTW) Evasion Vector",
            "explanation": f"Disk image container ('{ext}') automatically mounts as a virtual drive in Windows, stripping MOTW security warnings from encapsulated payloads."
        })

        # Static Byte Inspection for embedded executables and autorun configurations
        try:
            with open(path, "rb") as f:
                sample_buffer = f.read(10 * 1024 * 1024)  # Scan first 10MB

            if b"autorun.inf" in sample_buffer.lower():
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Container Analysis",
                    "finding": "AutoRun Configuration Hook (autorun.inf)",
                    "explanation": "Disk image contains an autorun configuration directive designed to execute payloads upon mounting."
                })

            if b"MZ" in sample_buffer and b"This program cannot be run in DOS mode" in sample_buffer:
                findings.append({
                    "severity": "HIGH",
                    "category": "Container Analysis",
                    "finding": "Embedded PE Binary in Disk Image",
                    "explanation": "Raw disk image byte patterns contain embedded Windows Portable Executable headers."
                })

        except Exception as ex:
            findings.append({
                "severity": "LOW",
                "category": "Container Analysis",
                "finding": "Disk Image Read Error",
                "explanation": f"Could not complete container static scan: {str(ex)}"
            })

        return {
            "scanner": self.scanner_id,
            "is_container": True,
            "findings_count": len(findings),
            "findings": findings
        }