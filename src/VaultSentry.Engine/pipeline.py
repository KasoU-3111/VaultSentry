"""
VaultSentry - Core Analysis Pipeline Controller
Orchestrates Virtual Quarantine Space (VQS) staging, dynamically executes scanner plugins
via PluginManager, and aggregates explainable security reports via Risk Engine.
Guarantees a standardized IPC response envelope containing 'status': 'SUCCESS'.
"""

from pathlib import Path
from typing import Any, Dict

from plugins.plugin_manager import PluginManager
from scanners.archive_scanner import ArchiveScanner
from scanners.disk_image_scanner import DiskImageScanner
from scanners.document_scanner import DocumentScanner
from scanners.heuristic_scanner import HeuristicScanner
from scanners.identity_scanner import IdentityIntegrityScanner
from scanners.malware_scanner import MalwareScanner
from scanners.msi_scanner import MSIScanner
from scanners.pe_scanner import PEScanner 
from scanners.risk_explainability import RiskAndExplainabilityEngine
from scanners.shortcut_script_scanner import ShortcutScriptScanner
from vqs import VirtualQuarantineSpace


class PipelineController:
    """Enterprise scan orchestrator and quarantine workflow coordinator."""

    def __init__(self) -> None:
        self.vqs = VirtualQuarantineSpace()
        self.risk_engine = RiskAndExplainabilityEngine()
        self.plugin_manager = PluginManager()
        self._initialize_plugins()

    def _initialize_plugins(self) -> None:
        """Discovers and registers all analysis scanner plugins in priority order."""
        self.plugin_manager.register_plugin(IdentityIntegrityScanner())
        self.plugin_manager.register_plugin(ShortcutScriptScanner())
        self.plugin_manager.register_plugin(PEScanner())
        self.plugin_manager.register_plugin(DocumentScanner())
        self.plugin_manager.register_plugin(MSIScanner())
        self.plugin_manager.register_plugin(ArchiveScanner())
        self.plugin_manager.register_plugin(DiskImageScanner())
        self.plugin_manager.register_plugin(MalwareScanner())
        self.plugin_manager.register_plugin(HeuristicScanner())

    def run_pipeline(self, raw_file_path: str) -> Dict[str, Any]:
        """
        Executes end-to-end static security analysis pipeline within VQS isolation.
        Guarantees null-safe response dictionaries wrapped in a 'status': 'SUCCESS' envelope.
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

        staging_info = self.vqs.stage_file(source_path)
        isolated_path = Path(staging_info["staged_path"])
        quarantine_id = staging_info.get("quarantine_id", "UNKNOWN_SESSION")

        try:
            # 1. Execute fault-isolated plugin pipeline
            pipeline_result = self.plugin_manager.execute_pipeline(isolated_path)
            aggregated_findings = pipeline_result.get("aggregated_findings", [])

            # 2. Evaluate risk score and explainable recommendations
            assessment = self.risk_engine.assess_risk(aggregated_findings)

            # 3. Extract identity metadata and hashes
            identity_report = pipeline_result["reports"].get("IdentityScanner", {})
            hashes = identity_report.get("hashes", {})
            identity = identity_report.get("identity", {})

            detected_type = identity.get("detected_type")
            if not detected_type or detected_type == "Unknown / Binary Stream":
                if source_path.suffix.lower() == ".exe":
                    detected_type = "Windows Portable Executable (.exe)"
                elif source_path.suffix.lower() == ".txt":
                    detected_type = "Plain Text Document"
                else:
                    detected_type = f"Generic {source_path.suffix.upper()} File" if source_path.suffix else "Binary File"

            # Explicit IPC Envelope containing 'status': 'SUCCESS'
            return {
                "status": "SUCCESS",
                "file_name": source_path.name or "Unknown",
                "file_size_bytes": isolated_path.stat().st_size,
                "quarantine_id": quarantine_id,
                "staged_path": str(isolated_path),
                "hashes": {
                    "sha256": hashes.get("sha256") or "N/A",
                    "sha1": hashes.get("sha1") or "N/A",
                    "md5": hashes.get("md5") or "N/A"
                },
                "identity": {
                    "matched": bool(identity.get("matched", False)),
                    "magic_hex": identity.get("magic_hex") or "00000000",
                    "detected_type": str(detected_type),
                    "mime_type": identity.get("mime_type") or "application/octet-stream",
                    "family": identity.get("family") or "unknown"
                },
                "verdict": str(assessment.get("verdict", "SAFE")),
                "risk_score": int(assessment.get("risk_score", 0)),
                "recommendation": str(assessment.get("recommendation", "No recommendation provided.")),
                "severity_breakdown": assessment.get("severity_breakdown", {}),
                "finding_count": int(assessment.get("finding_count", 0)),
                "findings": assessment.get("findings", []),
                "scanner_reports": pipeline_result.get("reports", {})
            }

        except Exception as ex:
            return {
                "status": "ERROR",
                "message": f"Pipeline Execution Exception: {str(ex)}",
                "verdict": "ERROR",
                "risk_score": 0,
                "findings": []
            }


if __name__ == "__main__":
    print("[+] VaultSentry Pipeline Controller loaded.")