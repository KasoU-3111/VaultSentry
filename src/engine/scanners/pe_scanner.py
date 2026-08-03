"""
VaultSentry - Module 4: PE File Analysis Engine
Parses Portable Executable (PE32/PE32+) headers, computes section entropy, 
analyzes Import Address Tables (IAT), and identifies packing/obfuscation.
"""

import math
from pathlib import Path
from typing import Dict, Any, List

import pefile

# APIs frequently abused by malware for process injection, hooking, or persistence
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtQueueApcThread", "SetWindowsHookExA",
    "URLDownloadToFileA", "WinHttpOpen", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
}

class PEScanner:
    """
    Static analyzer for Windows Portable Executable (.exe, .dll, .sys, .scr) files.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon Entropy (0.0 to 8.0) for a byte array.
        High values indicate compression, encryption, or packing.
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        occ: Dict[int, int] = {}

        for byte in data:
            occ[byte] = occ.get(byte, 0) + 1

        for count in occ.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return round(entropy, 4)

    def scan_pe(self, file_path_str: str) -> Dict[str, Any]:
        """
        Parses PE structures using pefile and generates a security assessment.
        """
        path = Path(file_path_str).resolve()
        
        try:
            pe = pefile.PE(str(path))
        except pefile.PEFormatError:
            return {
                "is_pe": False,
                "error": "File does not contain a valid PE32/PE32+ header structure."
            }

        warnings: List[str] = []
        
        # 1. PE Basic Information
        is_64bit = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        compile_time = pe.FILE_HEADER.TimeDateStamp
        number_of_sections = pe.FILE_HEADER.NumberOfSections

        # 2. Section Analysis & Entropy Checking
        sections_info: List[Dict[str, Any]] = []
        has_high_entropy = False

        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_data = section.get_data()
            sec_entropy = self.calculate_entropy(sec_data)
            
            # Check for executable + writable flags (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)
            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)
            
            if is_exec and is_write:
                warnings.append(f"CRITICAL: Section '{sec_name}' is both Executable and Writable (Possible Code Injection risk).")

            if sec_entropy > 7.1:
                has_high_entropy = True
                warnings.append(f"SUSPICIOUS: Section '{sec_name}' exhibits high entropy ({sec_entropy}), indicating potential packing/encryption.")

            sections_info.append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": sec_entropy,
                "is_executable": is_exec,
                "is_writable": is_write
            })

        # 3. Import Table Analysis (IAT)
        imported_dlls: List[str] = []
        flagged_apis: List[str] = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imported_dlls.append(dll_name)
                
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        if api_name in SUSPICIOUS_APIS:
                            flagged_apis.append(f"{dll_name} -> {api_name}")

        if flagged_apis:
            warnings.append(f"RISK: Found {len(flagged_apis)} sensitive/suspicious Windows API imports.")

        # 4. Overlay Data Detection
        overlay_offset = pe.get_overlay_data_start_offset()
        has_overlay = overlay_offset is not None
        if has_overlay:
            overlay_size = len(pe.__data__) - overlay_offset # type: ignore
            warnings.append(f"INFO: Appended overlay data detected ({overlay_size} bytes after PE structure).")

        pe.close()

        return {
            "is_pe": True,
            "architecture": "x64" if is_64bit else "x86",
            "compile_timestamp": compile_time,
            "number_of_sections": number_of_sections,
            "sections": sections_info,
            "has_high_entropy": has_high_entropy,
            "imported_dll_count": len(imported_dlls),
            "flagged_apis": flagged_apis,
            "has_overlay": has_overlay,
            "warnings": warnings,
            "status": "COMPLETED"
        }


if __name__ == "__main__":
    print("[+] PE File Analysis Engine module loaded.")