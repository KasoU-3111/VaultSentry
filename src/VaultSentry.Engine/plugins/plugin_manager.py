"""
VaultSentry - Plugin Manager & Isolated Execution Sandbox
Manages lifecycle, priority sorting, and isolated execution of scanner plugins.
Prevents individual scanner exceptions from breaking the global analysis pipeline.
"""

import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from plugins.base_scanner import BaseScanner


class PluginManager:
    """Enterprise plugin coordinator with isolated per-scanner exception boundaries."""

    def __init__(self) -> None:
        self._plugins: List[BaseScanner] = []

    def register_plugin(self, plugin: BaseScanner) -> None:
        """Registers a scanner plugin and maintains execution order sorted by priority."""
        if not isinstance(plugin, BaseScanner):
            raise TypeError(f"Invalid plugin type: {type(plugin)}. Must inherit from BaseScanner.")
        
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: p.priority)

    def execute_pipeline(self, target_path: Path) -> Dict[str, Any]:
        """
        Executes all applicable scanner plugins sequentially in priority order.
        Wraps every plugin execution in an isolated exception boundary to ensure
        the analysis pipeline never crashes on malformed or packed binaries.
        """
        context: Dict[str, Any] = {}
        reports: Dict[str, Any] = {}
        aggregated_findings: List[Dict[str, Any]] = []

        for plugin in self._plugins:
            scanner_id = plugin.scanner_id

            try:
                # 1. Check Applicability
                if not plugin.is_applicable(target_path, context):
                    continue

                # 2. Execute Isolated Scan
                scan_output = plugin.scan(target_path, context)
                
                if not isinstance(scan_output, dict):
                    scan_output = {
                        "scanner": scanner_id,
                        "findings": [{
                            "severity": "HIGH",
                            "category": "Scanner Interface Error",
                            "finding": "Invalid Output Format",
                            "explanation": f"Scanner '{scanner_id}' returned non-dictionary response."
                        }]
                    }

                # 3. Store Report and Context
                reports[scanner_id] = scan_output
                context[scanner_id] = scan_output

                # 4. Extract and Aggregate Findings
                plugin_findings = scan_output.get("findings", [])
                if isinstance(plugin_findings, list):
                    for finding in plugin_findings:
                        if isinstance(finding, dict):
                            aggregated_findings.append(finding)

            except Exception as ex:
                # Hardened Fault Isolation: Prevent scanner crash from killing the pipeline
                error_finding = {
                    "severity": "HIGH",
                    "category": "Engine Fault Isolation",
                    "finding": f"Scanner Execution Anomaly ({scanner_id})",
                    "explanation": f"Scanner encountered an unhandled exception while inspecting malformed payload: {str(ex)}"
                }
                
                failure_report = {
                    "scanner": scanner_id,
                    "status": "FAILED",
                    "error": str(ex),
                    "traceback": traceback.format_exc(),
                    "findings": [error_finding]
                }
                
                reports[scanner_id] = failure_report
                context[scanner_id] = failure_report
                aggregated_findings.append(error_finding)

        return {
            "reports": reports,
            "aggregated_findings": aggregated_findings
        }