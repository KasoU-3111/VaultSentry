"""
VaultSentry - Module 8: Heuristic Analysis Engine
Detects suspicious traits, double extensions, packed executables, 
script obfuscation (Base64/IEX), and high-risk API call combinations.
"""

import re
from pathlib import Path
from typing import Dict, Any, List

# Common obfuscation regex patterns in scripts/documents
BASE64_EXEC_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
SUSPICIOUS_SCRIPT_CMDS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "wscript.shell", "cmd.exe /c", "powershell -enc", "-nop -w hidden"
]

class HeuristicScanner:
    """
    Evaluates file characteristics to generate heuristic threat indicators.
    """

    def scan_heuristics(self, file_path_str: str, prior_metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """
        Runs heuristic evaluation across file structures and byte traits.
        
        :param file_path_str: Local target path.
        :param prior_metadata: Optional dict containing results from PE or Document scanners.
        """
        path = Path(file_path_str).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Target file for heuristic analysis does not exist: {file_path_str}")

        heuristic_flags: List[str] = []
        threat_score = 0  # Dynamic internal heuristic score (0 - 100)

        filename = path.name.lower()
        suffixes = path.suffixes

        # 1. Double Extension / Spoofing Heuristics
        if len(suffixes) > 1:
            last_ext = suffixes[-1].lower()
            second_last_ext = suffixes[-2].lower()
            if last_ext in [".exe", ".scr", ".pif", ".bat", ".ps1", ".vbs"] and second_last_ext in [".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".zip"]:
                heuristic_flags.append(f"HIGH_RISK_DOUBLE_EXTENSION: Disguised as '{second_last_ext}' but executes as '{last_ext}'.")
                threat_score += 40

        # 2. Executable Name Impersonation Check
        sys_impersonation_names = ["svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "taskmgr.exe"]
        if filename in sys_impersonation_names and "system32" not in str(path).lower():
            heuristic_flags.append(f"CRITICAL_IMPERSONATION: Binary uses core Windows process name '{filename}' outside System32.")
            threat_score += 50

        # 3. Script Content Obfuscation Heuristics
        text_extensions = [".ps1", ".vbs", ".bat", ".cmd", ".js", ".html"]
        if path.suffix.lower() in text_extensions:
            try:
                content = path.read_text(errors='ignore').lower()
                
                # Check for suspicious command triggers
                for cmd in SUSPICIOUS_SCRIPT_CMDS:
                    if cmd in content:
                        heuristic_flags.append(f"SUSPICIOUS_SCRIPT_CMD: Contains suspicious command pattern '{cmd}'.")
                        threat_score += 15

                # Base64 string detection
                if BASE64_EXEC_PATTERN.search(content):
                    heuristic_flags.append("OBFUSCATION_BASE64: Detected long Base64 encoded payload blocks in script.")
                    threat_score += 25

            except Exception as e:
                heuristic_flags.append(f"SCRIPT_READ_ERROR: Could not perform text heuristic analysis: {str(e)}")

        # 4. Integrate Prior Scanner Heuristics (PE entropy, sections, APIs)
        if prior_metadata:
            if prior_metadata.get("has_high_entropy", False):
                heuristic_flags.append("HIGH_ENTROPY_PACKED: Binary exhibits high entropy (packed/encrypted sections).")
                threat_score += 30
            
            flagged_apis = prior_metadata.get("flagged_apis", [])
            if len(flagged_apis) >= 3:
                heuristic_flags.append(f"SUSPICIOUS_API_COMBO: Multiple process injection APIs imported ({len(flagged_apis)} detected).")
                threat_score += 20

        # Normalize threat score
        threat_score = min(threat_score, 100)

        return {
            "file_name": path.name,
            "heuristic_score": threat_score,
            "flags": heuristic_flags,
            "flag_count": len(heuristic_flags),
            "status": "COMPLETED"
        }


if __name__ == "__main__":
    print("[+] Heuristic Analysis Engine module loaded.")