"""
VaultSentry - Module 8: Heuristic Analysis Engine
Detects evasive structural traits, double extensions, RTLO attacks,
script obfuscation (Base64/IEX), and correlated suspicious indicators.
"""

import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from plugins.base_scanner import BaseScanner


class HeuristicScanner(BaseScanner):
    """Enterprise static heuristic analysis and evasion detection engine."""

    MAX_SCRIPT_INSPECT_BYTES = 2 * 1024 * 1024

    SUSPICIOUS_EXECUTABLE_EXTENSIONS = {
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".wsf", ".cpl", ".com"
    }

    DECEPTIVE_DOCUMENT_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".txt", ".rtf", ".mp4", ".zip", ".7z"
    }

    CRITICAL_SYSTEM_NAMES = {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "smss.exe", "explorer.exe", "taskmgr.exe", "conhost.exe", "spoolsv.exe"
    }

    SUSPICIOUS_SCRIPT_PATTERNS = [
        (re.compile(r"(?:invoke-expression|iex)\b", re.IGNORECASE), "PowerShell In-Memory Execution Hook (IEX)"),
        (re.compile(r"(?:downloadstring|downloadfile)\b", re.IGNORECASE), "Web Payload Download Cradle"),
        (re.compile(r"wscript\.shell", re.IGNORECASE), "WScript Shell Invocation"),
        (re.compile(r"powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\b", re.IGNORECASE), "Encoded PowerShell Execution"),
        (re.compile(r"-(?:nop|noprofile)\s+.*-w(?:indowstyle)?\s+hidden\b", re.IGNORECASE), "Hidden Window PowerShell Launch")
    ]

    BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

    @property
    def scanner_id(self) -> str:
        return "HeuristicScanner"

    @property
    def priority(self) -> int:
        return 80

    def is_applicable(self, path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        return True

    def _calculate_string_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        return -sum(p * math.log2(p) for p in prob)

    def _inspect_naming_anomalies(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        name = path.name
        name_lower = name.lower()

        if "\u202e" in name:
            findings.append({
                "severity": "CRITICAL",
                "category": "Heuristics",
                "finding": "Right-to-Left Override (RTLO) Evasion",
                "explanation": "Filename contains Unicode RTLO character (U+202E) used to visually mask the actual file extension."
            })

        clean_parts = [p.strip().lower() for p in name.split(".") if p.strip()]
        if len(clean_parts) >= 3:
            second_last = f".{clean_parts[-2]}"
            last = f".{clean_parts[-1]}"
            if last in self.SUSPICIOUS_EXECUTABLE_EXTENSIONS and second_last in self.DECEPTIVE_DOCUMENT_EXTENSIONS:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Heuristics",
                    "finding": "Deceptive Double Extension Masquerade",
                    "explanation": f"File disguises an executable ('{last}') as a safe document format ('{second_last}')."
                })

        if name_lower in self.CRITICAL_SYSTEM_NAMES:
            path_str_lower = str(path).lower()
            if not ("c:\\windows\\system32" in path_str_lower or "c:\\windows\\syswow64" in path_str_lower):
                findings.append({
                    "severity": "HIGH",
                    "category": "Heuristics",
                    "finding": "Critical System Binary Impersonation",
                    "explanation": f"File matches protected system binary name '{name}' outside system directory."
                })

        return findings

    def _inspect_script_content(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        script_extensions = {".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta", ".wsf", ".html", ".htm"}
        if path.suffix.lower() not in script_extensions:
            return findings

        try:
            with open(path, "rb") as f:
                raw_bytes = f.read(self.MAX_SCRIPT_INSPECT_BYTES)

            text_content = raw_bytes.decode("utf-8", errors="ignore")

            for pattern, desc in self.SUSPICIOUS_SCRIPT_PATTERNS:
                if pattern.search(text_content):
                    findings.append({
                        "severity": "HIGH",
                        "category": "Heuristics",
                        "finding": f"Suspicious Command: {desc}",
                        "explanation": f"Script source contains high-risk execution pattern: {desc}"
                    })

            b64_matches = self.BASE64_REGEX.findall(text_content)
            for match in b64_matches:
                entropy = self._calculate_string_entropy(match)
                if len(match) > 80 and entropy > 4.5:
                    findings.append({
                        "severity": "HIGH",
                        "category": "Heuristics",
                        "finding": "Obfuscated High-Entropy Base64 Block",
                        "explanation": f"Detected dense Base64 block ({len(match)} chars, entropy {entropy:.2f}) indicating packed payload."
                    })
                    break
        except Exception as ex:
            findings.append({
                "severity": "LOW",
                "category": "Heuristics",
                "finding": "Script Analysis Error",
                "explanation": f"Could not complete script heuristics: {str(ex)}"
            })

        return findings

    def _correlate_context(self, context: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        if not context:
            return findings

        pe_report = context.get("PEScanner", {})
        if pe_report.get("has_high_entropy", False):
            findings.append({
                "severity": "HIGH",
                "category": "Heuristics",
                "finding": "Packed / Encrypted Binary Structure",
                "explanation": "Binary sections exhibit high entropy, strongly indicating crypter, packer, or encrypted code sections."
            })

        flagged_apis = pe_report.get("flagged_apis", [])
        if len(flagged_apis) >= 3:
            findings.append({
                "severity": "HIGH",
                "category": "Heuristics",
                "finding": f"Process Injection API Cluster ({len(flagged_apis)} detected)",
                "explanation": f"PE imports multiple APIs commonly combined for memory injection: {', '.join(flagged_apis[:4])}"
            })

        return findings

    def scan(self, path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        
        try:
            findings.extend(self._inspect_naming_anomalies(path))
            findings.extend(self._inspect_script_content(path))
            findings.extend(self._correlate_context(context))
        except Exception as ex:
            findings.append({
                "severity": "HIGH",
                "category": "Heuristics",
                "finding": "Heuristic Evaluation Exception",
                "explanation": f"Failed evaluating heuristic rules: {str(ex)}"
            })

        return {
            "scanner": self.scanner_id,
            "findings_count": len(findings),
            "findings": findings
        }