"""
VaultSentry - Dynamic Plugin Subsystem: Plugin Registry & Orchestrator
Manages discovery, lifecycle, prioritization, and fail-closed execution of scanner plugins.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.engine.plugins.base_scanner import BaseScanner

logger = logging.getLogger("VaultSentry.PluginManager")


class PluginManager:
    """Registry and execution coordinator for VaultSentry scanner plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, BaseScanner] = {}

    def register_plugin(self, plugin: BaseScanner) -> None:
        """Registers a scanner plugin instance into the management registry."""
        if not isinstance(plugin, BaseScanner):
            raise TypeError(f"Plugin {plugin} must inherit from BaseScanner.")
        
        if plugin.scanner_id in self._plugins:
            logger.warning(f"Overwriting existing plugin registration: {plugin.scanner_id}")
        
        self._plugins[plugin.scanner_id] = plugin
        logger.debug(f"Registered plugin: {plugin.scanner_id} (Priority: {plugin.priority})")

    def get_plugin(self, scanner_id: str) -> Optional[BaseScanner]:
        """Retrieves a registered plugin by its unique ID."""
        return self._plugins.get(scanner_id)

    def get_registered_plugins(self) -> List[BaseScanner]:
        """Returns all registered plugins sorted by ascending execution priority."""
        return sorted(self._plugins.values(), key=lambda p: p.priority)

    def execute_pipeline(self, target_path: Path) -> Dict[str, Any]:
        """
        Executes all applicable scanner plugins against the target file sequentially.
        Maintains cumulative context and guarantees fail-closed error handling.
        """
        resolved_path = target_path.resolve()
        if not resolved_path.is_file():
            raise FileNotFoundError(f"Quarantined analysis target not found: {resolved_path}")

        context: Dict[str, Any] = {
            "target_path": str(resolved_path),
            "file_name": resolved_path.name,
            "file_size": resolved_path.stat().st_size
        }

        all_findings: List[Dict[str, str]] = []
        scanner_reports: Dict[str, Any] = {}

        plugins_to_run = self.get_registered_plugins()

        for plugin in plugins_to_run:
            # 1. Applicability Filter
            try:
                if not plugin.is_applicable(resolved_path, context):
                    continue
            except Exception as ex:
                logger.error(f"Plugin '{plugin.scanner_id}' is_applicable check failed: {ex}")
                continue

            # 2. Isolated Execution (Fail-Closed Boundary)
            try:
                report = plugin.scan(resolved_path, context)
                scanner_reports[plugin.scanner_id] = report

                # Extract and aggregate normalized security findings
                findings = report.get("findings", [])
                if isinstance(findings, list):
                    all_findings.extend(findings)

                # Update shared execution context for downstream scanners
                context[plugin.scanner_id] = report

            except Exception as ex:
                logger.error(f"Plugin '{plugin.scanner_id}' execution crashed: {ex}", exc_info=True)
                
                # Emit a high-severity finding so scanner crashes never produce a false-clean verdict
                fault_finding = {
                    "severity": "HIGH",
                    "category": "Engine Diagnostics",
                    "finding": f"Scanner Engine Fault ({plugin.scanner_id})",
                    "explanation": f"The scanner encountered an unexpected internal error during analysis: {str(ex)}"
                }
                all_findings.append(fault_finding)
                scanner_reports[plugin.scanner_id] = {
                    "error": str(ex),
                    "status": "FAULTED",
                    "findings": [fault_finding]
                }

        return {
            "context": context,
            "reports": scanner_reports,
            "aggregated_findings": all_findings
        }