"""
VaultSentry - Module 4: PE File Analysis Engine
Parses Portable Executable structures, evaluates section characteristics,
calculates bounded Shannon entropy, verifies Authenticode presence, and analyzes IAT hooks.
Implements fail-closed fallback analysis for malformed/packed binaries.
"""

import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pefile

from src.engine.plugins.base_scanner import BaseScanner


class PEScanner(BaseScanner):
    """Enterprise static analyzer for Windows Portable Executable files."""

    SUSPICIOUS_APIS = {
        # Process Injection / Memory Modification
        "VirtualAlloc": "Memory Allocation",
        "VirtualAllocEx": "Remote Process Allocation",
        "VirtualProtect": "Memory Permission Modification",
        "VirtualProtectEx": "Remote Memory Permission Modification",
        "WriteProcessMemory": "Remote Process Memory Write",
        "CreateRemoteThread": "Remote Thread Injection",
        "NtQueueApcThread": "APC Queue Injection",
        "QueueUserAPC": "User APC Injection",
        "SetThreadContext": "Thread Hijacking",
        "SetWindowsHookExA": "System Hook Injection",
        "SetWindowsHookExW": "System Hook Injection",

        # Anti-Debugging & Evasion
        "IsDebuggerPresent": "Debugger Detection",
        "CheckRemoteDebuggerPresent": "Debugger Detection",
        "NtQueryInformationProcess": "Process Inspection / Evasion",
        "OutputDebugStringA": "Debug Output Probe",

        # Dynamic Resolution / Unpacking
        "LoadLibraryA": "Dynamic Module Loading",
        "LoadLibraryW": "Dynamic Module Loading",
        "GetProcAddress": "Dynamic API Resolution",

        # Payload Retrieval & Execution
        "URLDownloadToFileA": "HTTP Payload Retrieval",
        "URLDownloadToFileW": "HTTP Payload Retrieval",
        "WinHttpOpen": "HTTP Network Connection",
        "ShellExecuteA": "Shell Process Execution",
        "ShellExecuteW": "Shell Process Execution",
        "WinExec": "Legacy Process Execution"
    }

    KNOWN_PACKER_SECTIONS = {
        "UPX0", "UPX1", "UPX2", ".aspack", ".pcle", ".petite", 
        ".themida", ".vmp0", ".vmp1", ".vmp2", "PEC2", ".nsp0", ".packer"
    }

    def __init__(self) -> None:
        super().__init__(scanner_id="PEScanner", priority=40)

    def is_applicable(self, path: Path, context: Dict[str, Any]) -> bool:
        ext = path.suffix.lower()
        if ext in {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}:
            return True
        try:
            with open(path, "rb") as f:
                return f.read(2) == b"MZ"
        except Exception:
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

    def _inspect_sections(self, pe: pefile.PE) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], bool]:
        sections_info: List[Dict[str, Any]] = []
        findings: List[Dict[str, str]] = []
        has_high_entropy = False

        for section in pe.sections:
            sec_name = section.Name.decode("latin-1", errors="replace").strip("\x00")
            raw_size = section.SizeOfRawData
            inspect_size = min(raw_size, 50 * 1024 * 1024)
            sec_data = section.get_data()[:inspect_size] if inspect_size > 0 else b""
            sec_entropy = self.calculate_entropy(sec_data) if sec_data else 0.0

            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)

            # Check 1: W+X Sections
            if is_exec and is_write:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "PE Analysis",
                    "finding": f"Self-Modifying / W+X Section '{sec_name}'",
                    "explanation": f"Section '{sec_name}' is both Executable and Writable, indicating runtime code unpacking."
                })

            # Check 2: Known Packer Names
            if sec_name.upper() in self.KNOWN_PACKER_SECTIONS or "UPX" in sec_name.upper():
                has_high_entropy = True
                findings.append({
                    "severity": "HIGH",
                    "category": "PE Analysis",
                    "finding": f"Packer Section Identified ({sec_name})",
                    "explanation": f"Section signature matches runtime binary packer/crypter '{sec_name}'."
                })

            # Check 3: High Entropy (> 6.8)
            if sec_entropy >= 6.8:
                has_high_entropy = True
                findings.append({
                    "severity": "HIGH",
                    "category": "PE Analysis",
                    "finding": f"High Entropy Section '{sec_name}' ({sec_entropy:.2f})",
                    "explanation": f"Section '{sec_name}' exhibits high entropy of {sec_entropy:.2f}/8.0, indicating compressed or encrypted payload."
                })

            # Check 4: Zero Raw Size with Virtual Allocation (Unpacking Target)
            if raw_size == 0 and section.Misc_VirtualSize > 0 and is_exec:
                has_high_entropy = True
                findings.append({
                    "severity": "HIGH",
                    "category": "PE Analysis",
                    "finding": f"Empty Executable Section Header ({sec_name})",
                    "explanation": f"Section '{sec_name}' reserves {section.Misc_VirtualSize} virtual bytes with 0 raw bytes on disk (common in UPX/packers)."
                })

            sections_info.append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "is_executable": is_exec,
                "is_writable": is_write
            })

        return sections_info, findings, has_high_entropy

    def _inspect_imports(self, pe: pefile.PE) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
        imported_dlls: List[str] = []
        flagged_apis: List[str] = []
        findings: List[Dict[str, str]] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            findings.append({
                "severity": "HIGH",
                "category": "PE Analysis",
                "finding": "Missing / Stripped Import Directory (IAT)",
                "explanation": "Binary contains no standard import table, characteristic of packed shellcode or runtime loaders."
            })
            return imported_dlls, findings, flagged_apis

        total_imported_functions = 0
        detected_capabilities: Set[str] = set()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("latin-1", errors="replace")
            imported_dlls.append(dll_name)

            for imp in entry.imports:
                total_imported_functions += 1
                if not imp.name:
                    continue
                api_name = imp.name.decode("latin-1", errors="replace")
                if api_name in self.SUSPICIOUS_APIS:
                    capability = self.SUSPICIOUS_APIS[api_name]
                    detected_capabilities.add(capability)
                    flagged_apis.append(f"{dll_name}!{api_name}")

        # Flag Sparse Import Table (Packer Characteristic)
        if 0 < total_imported_functions <= 5:
            findings.append({
                "severity": "HIGH",
                "category": "PE Analysis",
                "finding": f"Abnormally Sparse Import Table ({total_imported_functions} functions)",
                "explanation": "Executable imports fewer than 6 functions, strongly indicating a packer stub resolving APIs dynamically at runtime."
            })

        if len(flagged_apis) >= 3:
            findings.append({
                "severity": "HIGH",
                "category": "PE Analysis",
                "finding": f"Monitored API Capabilities ({len(flagged_apis)} detected)",
                "explanation": f"PE imports sensitive APIs for: {', '.join(sorted(detected_capabilities))}"
            })

        return imported_dlls, findings, flagged_apis

    def _inspect_security_directory(self, pe: pefile.PE) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        security_dir = None
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

        if security_dir is None or security_dir.VirtualAddress == 0 or security_dir.Size == 0:
            findings.append({
                "severity": "MEDIUM",
                "category": "Digital Signature",
                "finding": "Unsigned Executable Binary",
                "explanation": "Binary does not contain an embedded Authenticode digital signature structure."
            })
        else:
            findings.append({
                "severity": "INFO",
                "category": "Digital Signature",
                "finding": "Embedded Authenticode Structure Present",
                "explanation": f"Binary contains digital signature certificate data ({security_dir.Size} bytes)."
            })

        return findings

    def _inspect_overlay(self, pe: pefile.PE, total_file_size: int) -> Tuple[bool, List[Dict[str, str]]]:
        findings: List[Dict[str, str]] = []
        overlay_offset = pe.get_overlay_data_start_offset()

        if overlay_offset is None or overlay_offset >= total_file_size:
            return False, findings

        overlay_size = total_file_size - overlay_offset
        overlay_ratio = overlay_size / total_file_size if total_file_size > 0 else 0
        overlay_data = pe.get_overlay()[:1024 * 1024] if overlay_size > 0 else b""
        overlay_entropy = self.calculate_entropy(overlay_data)

        if overlay_ratio > 0.30 and overlay_entropy >= 6.8:
            findings.append({
                "severity": "HIGH",
                "category": "PE Analysis",
                "finding": f"Suspicious High-Entropy Overlay ({overlay_size:,} bytes)",
                "explanation": f"Binary contains appended overlay ({overlay_ratio * 100:.1f}% of file) with entropy {overlay_entropy:.2f}."
            })

        return True, findings

    def _fallback_raw_analysis(self, path: Path, error_msg: str) -> Dict[str, Any]:
        """Fail-closed fallback analyzer for malformed/corrupt PE binaries."""
        findings: List[Dict[str, str]] = [
            {
                "severity": "HIGH",
                "category": "PE Analysis",
                "finding": "Malformed / Obfuscated PE Structure",
                "explanation": f"PE parser failed to interpret executable headers ({error_msg}), characteristic of packed or intentionally corrupted binaries."
            }
        ]

        try:
            with open(path, "rb") as f:
                raw_bytes = f.read(50 * 1024 * 1024)
            file_entropy = self.calculate_entropy(raw_bytes)

            if file_entropy >= 6.8:
                findings.append({
                    "severity": "HIGH",
                    "category": "PE Analysis",
                    "finding": f"High Whole-File Entropy ({file_entropy:.2f})",
                    "explanation": f"Binary exhibits raw entropy of {file_entropy:.2f}/8.0, confirming encrypted/packed payload structure."
                })
        except Exception:
            file_entropy = 0.0

        return {
            "scanner": self.scanner_id,
            "is_pe": True,
            "architecture": "Unknown / Obfuscated",
            "has_high_entropy": file_entropy >= 6.8,
            "findings_count": len(findings),
            "findings": findings
        }

    def scan(self, path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
        pe: Optional[pefile.PE] = None
        findings: List[Dict[str, str]] = []

        try:
            pe = pefile.PE(str(path), fast_load=False)
            file_size = path.stat().st_size
            is_64bit = getattr(pe, "PE_TYPE", None) == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            compile_time = pe.FILE_HEADER.TimeDateStamp if hasattr(pe, "FILE_HEADER") else 0
            number_of_sections = pe.FILE_HEADER.NumberOfSections if hasattr(pe, "FILE_HEADER") else 0

            # 1. Section Characteristics & Shannon Entropy
            sections_info, sec_findings, has_high_entropy = self._inspect_sections(pe)
            findings.extend(sec_findings)

            # 2. Import Address Table Analysis
            imported_dlls, iat_findings, flagged_apis = self._inspect_imports(pe)
            findings.extend(iat_findings)

            # 3. Authenticode Directory Check
            findings.extend(self._inspect_security_directory(pe))

            # 4. Appended Overlay Inspection
            has_overlay, overlay_findings = self._inspect_overlay(pe, file_size)
            findings.extend(overlay_findings)

            return {
                "scanner": self.scanner_id,
                "is_pe": True,
                "architecture": "x64" if is_64bit else "x86",
                "compile_timestamp": compile_time,
                "number_of_sections": number_of_sections,
                "sections": sections_info,
                "has_high_entropy": has_high_entropy,
                "imported_dll_count": len(imported_dlls),
                "flagged_apis": flagged_apis,
                "has_overlay": has_overlay,
                "findings_count": len(findings),
                "findings": findings
            }

        except Exception as ex:
            return self._fallback_raw_analysis(path, str(ex))

        finally:
            if pe:
                try:
                    pe.close()
                except Exception:
                    pass


if __name__ == "__main__":
    print("[+] VaultSentry - Hardened PE File Analysis Engine loaded.")