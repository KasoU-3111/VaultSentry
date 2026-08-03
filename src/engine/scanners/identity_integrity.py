"""
VaultSentry - Modules 2 & 3: Identity & Integrity Verification Scanner
Performs chunked cryptographic hashing (SHA256/SHA1/MD5), Magic Byte signature analysis,
MIME type resolution, and extension spoofing detection.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, List

# Standard Magic Byte Dictionary for Critical File Types
MAGIC_SIGNATURES: Dict[bytes, Dict[str, str]] = {
    b"MZ": {"type": "PE Executable", "mime": "application/x-dosexec", "family": "executable"},
    b"%PDF": {"type": "PDF Document", "mime": "application/pdf", "family": "document"},
    b"\x50\x4b\x03\x04": {"type": "ZIP / Office OpenXML Archive", "mime": "application/zip", "family": "archive"},
    b"\x37\x7a\xbc\xaf\x27\x1c": {"type": "7-Zip Archive", "mime": "application/x-7z-compressed", "family": "archive"},
    b"Rar!\x1a\x07": {"type": "RAR Archive", "mime": "application/x-rar-compressed", "family": "archive"},
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": {"type": "Compound File Binary (OLE)", "mime": "application/x-ole-storage", "family": "document"},
}

# Dangerous Extension Map
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".ps1", ".msi"}

class IdentityIntegrityScanner:
    """
    Analyzes raw byte streams to establish file integrity and verify true file identity.
    """

    def __init__(self, chunk_size: int = 65536) -> None:
        self.chunk_size = chunk_size

    def calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """
        Computes SHA256, SHA1, and MD5 hashes in chunked stream mode.
        """
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(self.chunk_size):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest()
        }

    def detect_magic_bytes(self, file_path: Path) -> Dict[str, Any]:
        """
        Reads initial file bytes to verify file type signature.
        """
        with open(file_path, "rb") as f:
            header = f.read(16)

        for magic, meta in MAGIC_SIGNATURES.items():
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

    def inspect_identity_integrity(self, file_path_str: str) -> Dict[str, Any]:
        """
        Main scanner execution pipeline.
        """
        path = Path(file_path_str).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Scanner target path does not exist: {file_path_str}")

        hashes = self.calculate_hashes(path)
        magic_info = self.detect_magic_bytes(path)
        
        file_ext = path.suffix.lower()
        warnings: List[str] = []
        is_spoofed = False

        # Extension Spoofing Check
        if magic_info["family"] == "executable" and file_ext not in EXECUTABLE_EXTENSIONS:
            is_spoofed = True
            warnings.append(f"CRITICAL: File contains PE Executable header but uses disguised extension '{file_ext}'")

        # Double Extension Detection (e.g., payload.pdf.exe)
        if len(path.suffixes) > 1:
            warnings.append(f"SUSPICIOUS: Multiple file extensions detected -> '{path.name}'")

        return {
            "file_name": path.name,
            "file_size_bytes": path.stat().st_size,
            "file_extension": file_ext,
            "hashes": hashes,
            "identity": magic_info,
            "spoofing_detected": is_spoofed,
            "warnings": warnings,
            "status": "COMPLETED"
        }


if __name__ == "__main__":
    import sys
    print("[+] Identity & Integrity Verification Scanner module loaded.")