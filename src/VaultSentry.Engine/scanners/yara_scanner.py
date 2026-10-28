"""
VaultSentry - Module 7: YARA Signature Engine
Executes deterministic pattern matching against known malware families, 
packers, and offensive security tooling.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yara
from plugins.base_scanner import BaseScanner

class YaraScanner(BaseScanner):
    """Compiles and executes YARA signatures against quarantined payloads."""

    MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB limit for regex scanning
    SCAN_TIMEOUT_SECONDS = 30

    def __init__(self, workspace_root: Optional[str] = None):
        if workspace_root:
            self.rules_dir = Path(workspace_root) / "config" / "yara"
        else:
            # Dynamically resolve root: scanners(0) -> Engine(1) -> src(2) -> VaultSentry Root(3)
            self.rules_dir = Path(__file__).resolve().parents[3] / "config" / "yara"
            
        self.compiled_rules = self._compile_ruleset()

    @property
    def scanner_id(self) -> str:
        return "YaraScanner"

    @property
    def priority(self) -> int:
        return 70  # Executes after identity and extraction, before heuristics

    def is_applicable(self, path: Path, context: Optional[dict[str, Any]] = None) -> bool:
        if not path.exists():
            return False
        return path.stat().st_size <= self.MAX_FILE_SIZE_BYTES

    def _compile_ruleset(self) -> Optional[yara.Rules]:
        """Loads and compiles all .yar files in the configuration directory."""
        if not self.rules_dir.exists():
            print(f"[!] YARA Rules directory not found at: {self.rules_dir}")
            return None

        rule_files = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    rule_path = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = rule_path

        if not rule_files:
            return None

        try:
            return yara.compile(filepaths=rule_files)
        except yara.SyntaxError as e:
            print(f"[!] YARA Compilation Error: {e}")
            return None

    def scan(self, path: Path, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        findings: list[dict[str, str]] = []

        if not self.compiled_rules:
            return {
                "scanner": self.scanner_id,
                "status": "DISABLED",
                "message": "No valid YARA rules compiled.",
                "findings": []
            }

        try:
            matches = self.compiled_rules.match(
                filepath=str(path),
                timeout=self.SCAN_TIMEOUT_SECONDS
            )

            for match in matches:
                meta = match.meta
                severity = meta.get("severity", "HIGH").upper()
                description = meta.get("description", "Suspicious signature detected.")
                category = meta.get("category", "Signature Match")

                findings.append({
                    "severity": severity,
                    "category": category,
                    "finding": f"YARA Rule Match: {match.rule}",
                    "explanation": description
                })

        except yara.TimeoutError:
            findings.append({
                "severity": "HIGH",
                "category": "Engine Integrity",
                "finding": "YARA Scan Timeout",
                "explanation": f"Pattern matching exceeded {self.SCAN_TIMEOUT_SECONDS}s. The file may be packed or designed to cause regular expression denial of service."
            })
        except Exception as e:
            findings.append({
                "severity": "ERROR",
                "category": "Execution Failure",
                "finding": "YARA Engine Fault",
                "explanation": f"Unhandled exception during signature analysis: {str(e)}"
            })

        return {
            "scanner": self.scanner_id,
            "rule_namespaces_loaded": len(self.compiled_rules) if self.compiled_rules else 0,
            "findings_count": len(findings),
            "findings": findings
        }