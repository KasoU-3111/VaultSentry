"""
VaultSentry - Surface Expansion: MSI Windows Installer Package Scanner
Statically analyzes OLE Compound File Binary structures in .msi packages.
Inspects CustomAction tables, embedded binary streams, and script execution hooks.
"""

import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import olefile

from plugins.base_scanner import BaseScanner


class MSIScanner(BaseScanner):
    """Enterprise static security analyzer for Windows Installer (.msi) databases."""

    MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    SUSPICIOUS_CUSTOM_ACTION_KEYWORDS = [
        (re.compile(r"(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)", re.IGNORECASE), "Command Shell Invocation"),
        (re.compile(r"(?:downloadstring|downloadfile|curl|iwr|wget)", re.IGNORECASE), "Payload Retrieval Cradle"),
        (re.compile(r"(?:-enc|-encodedcommand)\s+[a-z0-9+/=]+", re.IGNORECASE), "Base64 Encoded Script Execution"),
        (re.compile(r"(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread)", re.IGNORECASE), "Process Injection API Reference"),
        (re.compile(r"(?:wscript\.shell|shell\.application)", re.IGNORECASE), "COM Shell Object Dispatch")
    ]

    @property
    def scanner_id(self) -> str:
        return "MSIScanner"

    @property
    def priority(self) -> int:
        return 48

    def is_applicable(self, path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        ext = path.suffix.lower()
        if ext == ".msi":
            return True
        try:
            with open(path, "rb") as f:
                header = f.read(8)
                if header.startswith(self.MAGIC_OLE):
                    if olefile.isOleFile(str(path)):
                        with olefile.OleFileIO(str(path)) as ole:
                            streams = ole.listdir()
                            for s in streams:
                                if any("CustomAction" in part or "_Tables" in part or "_Columns" in part for part in s):
                                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        occ: Dict[int, int] = {}
        for b in data:
            occ[b] = occ.get(b, 0) + 1
        entropy = 0.0
        for count in occ.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    def _inspect_ole_streams(self, ole: olefile.OleFileIO) -> Tuple[List[str], List[Dict[str, str]], bool]:
        stream_names: List[str] = []
        findings: List[Dict[str, str]] = []
        has_embedded_pe = False

        for stream_path in ole.listdir():
            name = "/".join(stream_path)
            stream_names.append(name)

            if name.startswith("\x05") or name.startswith("\x01"):
                continue

            try:
                stream_size = ole.get_size(stream_path)
                if stream_size == 0:
                    continue

                read_size = min(stream_size, 10 * 1024 * 1024)
                data = ole.openstream(stream_path).read(read_size)

                if data.startswith(b"MZ") or (b"MZ" in data[:1024] and b"PE\x00\x00" in data[:4096]):
                    has_embedded_pe = True
                    findings.append({
                        "severity": "HIGH",
                        "category": "Installer Analysis",
                        "finding": f"Embedded PE Binary in Stream '{name}'",
                        "explanation": f"MSI package encapsulates an executable Windows binary within internal OLE stream '{name}' ({stream_size:,} bytes)."
                    })

                stream_entropy = self.calculate_entropy(data)
                if stream_size > 32768 and stream_entropy >= 7.2:
                    findings.append({
                        "severity": "HIGH",
                        "category": "Installer Analysis",
                        "finding": f"High Entropy Stream '{name}' ({stream_entropy:.2f})",
                        "explanation": f"Stream '{name}' exhibits high entropy of {stream_entropy:.2f}/8.0, indicating encrypted or packed binary payloads."
                    })

            except Exception:
                continue

        return stream_names, findings, has_embedded_pe

    def _inspect_raw_custom_actions(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []

        try:
            with open(path, "rb") as f:
                content = f.read(25 * 1024 * 1024)

            content_str = content.decode("latin-1", errors="replace")

            for pattern, desc in self.SUSPICIOUS_CUSTOM_ACTION_KEYWORDS:
                matches = pattern.findall(content_str)
                if matches:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Installer Analysis",
                        "finding": f"High-Risk CustomAction Hook ({desc})",
                        "explanation": f"MSI Installer database contains dangerous custom execution directive matching pattern: {desc}"
                    })

        except Exception as ex:
            findings.append({
                "severity": "LOW",
                "category": "Installer Analysis",
                "finding": "MSI Content Analysis Warning",
                "explanation": f"Failed evaluating raw database patterns: {str(ex)}"
            })

        return findings

    def scan(self, path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        stream_list: List[str] = []
        has_embedded_pe = False

        if not olefile.isOleFile(str(path)):
            return {
                "scanner": self.scanner_id,
                "is_msi": False,
                "findings": []
            }

        try:
            with olefile.OleFileIO(str(path)) as ole:
                stream_list, ole_findings, has_embedded_pe = self._inspect_ole_streams(ole)
                findings.extend(ole_findings)

            action_findings = self._inspect_raw_custom_actions(path)
            findings.extend(action_findings)

            return {
                "scanner": self.scanner_id,
                "is_msi": True,
                "stream_count": len(stream_list),
                "has_embedded_pe": has_embedded_pe,
                "findings_count": len(findings),
                "findings": findings
            }

        except Exception as ex:
            findings.append({
                "severity": "HIGH",
                "category": "Installer Analysis",
                "finding": "Corrupted or Malformed MSI Database",
                "explanation": f"OLE storage parser failed to process MSI package: {str(ex)}"
            })
            return {
                "scanner": self.scanner_id,
                "is_msi": True,
                "findings": findings
            }