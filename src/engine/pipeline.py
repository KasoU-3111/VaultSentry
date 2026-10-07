"""
VaultSentry - Core Analysis Pipeline Controller
Orchestrates Virtual Quarantine Space (VQS) staging, dynamically executes scanner plugins
via PluginManager, and aggregates explainable security reports via Risk Engine.
"""

from pathlib import Path
from typing import Any, Dict

from src.engine.plugins.plugin_manager import PluginManager
from src.engine.scanners.archive_scanner import ArchiveScanner
from src.engine.scanners.document_scanner import DocumentScanner
from src.engine.scanners.heuristic_scanner import HeuristicScanner
from src.engine.scanners.identity_scanner import IdentityIntegrityScanner
from src.engine.scanners.malware_scanner import MalwareScanner
from src.engine.scanners.pe_scanner import PEScanner
from src.engine.scanners.risk_explainability import RiskAndExplainabilityEngine
from src.engine.scanners.shortcut_script_scanner import ShortcutScriptScanner
from src.engine.scanners.disk_image_scanner import DiskImageScanner
from src.engine.vqs import VirtualQuarantineSpace
from src.engine.scanners.msi_scanner import MSIScanner


class PipelineController:
    """Enterprise scan orchestrator and quarantine workflow coordinator."""

    def __init__(self) -> None:
        self.vqs = VirtualQuarantineSpace()
        self.risk_engine = RiskAndExplainabilityEngine()
        self.plugin_manager = PluginManager()
        self._initialize_plugins()

    def _initialize_plugins(self) -> None:
        """Discovers and registers all analysis scanner plugins."""
        self.plugin_manager.register_plugin(IdentityIntegrityScanner())
        self.plugin_manager.register_plugin(ShortcutScriptScanner())
        self.plugin_manager.register_plugin(PEScanner())
        self.plugin_manager.register_plugin(DocumentScanner())
        self.plugin_manager.register_plugin(ArchiveScanner())
        self.plugin_manager.register_plugin(MalwareScanner())
        self.plugin_manager.register_plugin(HeuristicScanner())
        self.plugin_manager.register_plugin(DiskImageScanner())
        self.plugin_manager.register_plugin(MSIScanner())

    def run_pipeline(self, raw_file_path: str) -> Dict[str, Any]:
        """
        Executes end-to-end static security analysis pipeline within VQS isolation.
        """
        source_path = Path(raw_file_path).resolve()
        if not source_path.is_file():
            return {
                "status": "ERROR",
                "message": f"Target file does not exist: {raw_file_path}",
                "verdict": "ERROR",
                "risk_score": 0,
                "findings": []
            }

        # 1. Stage file into Virtual Quarantine Space (VQS)
        staging_info = self.vqs.stage_file(source_path)
        isolated_path = Path(staging_info["staged_path"])
        quarantine_id = staging_info.get("quarantine_id", "UNKNOWN_SESSION")

        try:
            # 2. Execute Dynamic Scanner Plugins via PluginManager
            pipeline_result = self.plugin_manager.execute_pipeline(isolated_path)
            aggregated_findings = pipeline_result.get("aggregated_findings", [])

            # 3. Evaluate Risk and Compute Explainable Assessment
            assessment = self.risk_engine.assess_risk(aggregated_findings)

            # 4. Extract Hashes and Identity for Response DTO
            identity_report = pipeline_result["reports"].get("IdentityScanner", {})
            hashes = identity_report.get("hashes", {})
            identity = identity_report.get("identity", {})

            return {
                "status": "SUCCESS",
                "file_name": source_path.name,
                "file_size_bytes": isolated_path.stat().st_size,
                "quarantine_id": quarantine_id,
                "staged_path": str(isolated_path),
                "hashes": hashes,
                "identity": identity,
                "verdict": assessment["verdict"],
                "risk_score": assessment["risk_score"],
                "recommendation": assessment["recommendation"],
                "severity_breakdown": assessment.get("severity_breakdown", {}),
                "finding_count": assessment["finding_count"],
                "findings": assessment["findings"],
                "scanner_reports": pipeline_result["reports"]
            }

        finally:
            # Staged item retained in VQS until user/client issues a release or purge command
            pass


if __name__ == "__main__":
    print("[+] VaultSentry Pipeline Controller initialized.")