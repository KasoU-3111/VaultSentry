"""
VaultSentry - Surface Expansion: Shortcut & Script Container Scanner
Statically parses Windows Shell Link (.lnk) binary structures, HTML Applications (.hta),
Windows Script Files (.wsf), and Compiled HTML Help (.chm) without dynamic execution.
"""

import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.engine.plugins.base_scanner import BaseScanner


class ShortcutScriptScanner(BaseScanner):
    """Static inspector for Windows shortcut links and scripted attack containers."""

    # ShellLink Header CLSID: 00021401-0000-0000-C000-000000000046
    LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

    DANGEROUS_TARGET_BINARIES = {
        "powershell.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe"
    }

    SUSPICIOUS_CLI_PATTERNS = [
        (re.compile(r"-(?:enc|encodedcommand)\s+[a-z0-9+/=]+", re.IGNORECASE), "Base64 Encoded Command Execution"),
        (re.compile(r"-(?:w|windowstyle)\s+hidden", re.IGNORECASE), "Hidden Window Staging Parameter"),
        (re.compile(r"-(?:nop|noprofile)", re.IGNORECASE), "NoProfile Execution Bypass"),
        (re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.IGNORECASE), "ExecutionPolicy Bypass Switch"),
        (re.compile(r"(?:downloadstring|downloadfile|curl|iwr|wget)", re.IGNORECASE), "Payload Download Directive"),
        (re.compile(r"(?:iex|invoke-expression)", re.IGNORECASE), "In-Memory Expression Invocation"),
        (re.compile(r"\\\\[a-z0-9._-]+\\", re.IGNORECASE), "Remote UNC Path Execution")
    ]

    def __init__(self) -> None:
        super().__init__(scanner_id="ShortcutScriptScanner", priority=30)

    def is_applicable(self, path: Path, context: Dict[str, Any]) -> bool:
        ext = path.suffix.lower()
        if ext in {".lnk", ".hta", ".wsf", ".chm"}:
            return True
        # Check if header matches LNK CLSID regardless of extension
        try:
            with open(path, "rb") as f:
                header = f.read(20)
                if len(header) >= 20 and header[4:20] == self.LNK_CLSID:
                    return True
        except Exception:
            pass
        return False

    def _parse_lnk_string_data(self, data: bytes, offset: int, is_unicode: bool) -> Tuple[str, int]:
        """Safely extracts a counted string data block from MS-SHLLINK stream."""
        if offset + 2 > len(data):
            return "", offset
        
        char_count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        
        if is_unicode:
            byte_len = char_count * 2
            if offset + byte_len > len(data):
                return "", offset
            text = data[offset:offset + byte_len].decode("utf-16le", errors="ignore")
            offset += byte_len
        else:
            if offset + char_count > len(data):
                return "", offset
            text = data[offset:offset + char_count].decode("ascii", errors="ignore")
            offset += char_count

        return text.strip("\x00"), offset

    def _parse_lnk_file(self, data: bytes) -> Dict[str, Any]:
        """Parses MS-SHLLINK binary specification structures."""
        if len(data) < 76 or data[4:20] != self.LNK_CLSID:
            return {"valid_lnk": False, "error": "Invalid ShellLink CLSID"}

        flags = struct.unpack_from("<I", data, 0x14)[0]
        has_link_target_id_list = bool(flags & 0x01)
        has_link_info = bool(flags & 0x02)
        has_name = bool(flags & 0x04)
        has_relative_path = bool(flags & 0x08)
        has_working_dir = bool(flags & 0x10)
        has_arguments = bool(flags & 0x20)
        has_icon_location = bool(flags & 0x40)
        is_unicode = bool(flags & 0x80)

        offset = 76  # Header size

        # Skip IDList structure if present
        if has_link_target_id_list and offset + 2 <= len(data):
            id_list_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + id_list_size

        # Skip LinkInfo structure if present
        if has_link_info and offset + 4 <= len(data):
            link_info_size = struct.unpack_from("<I", data, offset)[0]
            offset += link_info_size

        # Read String Data Blocks
        name, rel_path, working_dir, arguments, icon_location = "", "", "", "", ""

        if has_name:
            name, offset = self._parse_lnk_string_data(data, offset, is_unicode)
        if has_relative_path:
            rel_path, offset = self._parse_lnk_string_data(data, offset, is_unicode)
        if has_working_dir:
            working_dir, offset = self._parse_lnk_string_data(data, offset, is_unicode)
        if has_arguments:
            arguments, offset = self._parse_lnk_string_data(data, offset, is_unicode)
        if has_icon_location:
            icon_location, offset = self._parse_lnk_string_data(data, offset, is_unicode)

        return {
            "valid_lnk": True,
            "flags_hex": hex(flags),
            "name": name,
            "relative_path": rel_path,
            "working_directory": working_dir,
            "command_line_arguments": arguments,
            "icon_location": icon_location
        }

    def _inspect_lnk(self, path: Path) -> List[Dict[str, str]]:
        """Evaluates extracted LNK parameters against weaponization indicators."""
        findings: List[Dict[str, str]] = []
        try:
            with open(path, "rb") as f:
                data = f.read(512 * 1024)  # Read first 512 KB
        except Exception as ex:
            findings.append({
                "severity": "LOW",
                "category": "Shortcut Analysis",
                "finding": "File Read Error",
                "explanation": f"Failed reading LNK file: {str(ex)}"
            })
            return findings

        lnk_meta = self._parse_lnk_file(data)
        if not lnk_meta.get("valid_lnk", False):
            return findings

        args = lnk_meta.get("command_line_arguments", "")
        rel_path = lnk_meta.get("relative_path", "")
        working_dir = lnk_meta.get("working_directory", "")
        combined_cmd = f"{rel_path} {args} {working_dir}".lower()

        # 1. Target Binary Abuse Check
        for bin_name in self.DANGEROUS_TARGET_BINARIES:
            if bin_name in combined_cmd:
                findings.append({
                    "severity": "HIGH",
                    "category": "Shortcut Analysis",
                    "finding": f"High-Risk Binary Execution Target ({bin_name})",
                    "explanation": f"Shortcut invokes administrative or scripting utility '{bin_name}' to stage execution."
                })
                break

        # 2. Suspicious CLI Pattern Checks
        for pattern, desc in self.SUSPICIOUS_CLI_PATTERNS:
            if pattern.search(args):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Shortcut Analysis",
                    "finding": f"Suspicious LNK Argument: {desc}",
                    "explanation": f"Shortcut CommandLine contains stealth/evasion argument pattern: {desc}"
                })

        # 3. Argument Length Evasion (White-space / Padding Attack)
        if len(args) > 200:
            findings.append({
                "severity": "HIGH",
                "category": "Shortcut Analysis",
                "finding": "Anomalous Shortcut Argument Length",
                "explanation": f"LNK command line arguments exceed standard size ({len(args)} characters), commonly used to push payloads past UI visual margins."
            })

        return findings

    def _inspect_script_containers(self, path: Path) -> List[Dict[str, str]]:
        """Inspects HTA, WSF, and CHM container files for script triggers."""
        findings: List[Dict[str, str]] = []
        ext = path.suffix.lower()

        if ext == ".hta":
            findings.append({
                "severity": "HIGH",
                "category": "Script Container",
                "finding": "HTML Application (.hta) Container",
                "explanation": "HTA files run under MSHTA.EXE with unconstrained Windows host permissions and access to ActiveX controls."
            })
        elif ext == ".wsf":
            findings.append({
                "severity": "HIGH",
                "category": "Script Container",
                "finding": "Windows Script File (.wsf) Container",
                "explanation": "WSF files encapsulate multi-engine script tags (VBScript/JScript) executed outside browser sandbox controls."
            })
        elif ext == ".chm":
            findings.append({
                "severity": "HIGH",
                "category": "Script Container",
                "finding": "Compiled HTML Help (.chm) Container",
                "explanation": "CHM files contain compiled HTML/ActiveX structures frequently leveraged for code execution via hh.exe."
            })

        return findings

    def scan(self, path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        """Main scanner execution loop."""
        findings: List[Dict[str, str]] = []

        # 1. Evaluate LNK binary data
        findings.extend(self._inspect_lnk(path))

        # 2. Evaluate Script containers
        findings.extend(self._inspect_script_containers(path))

        return {
            "scanner": self.scanner_id,
            "findings_count": len(findings),
            "findings": findings
        }