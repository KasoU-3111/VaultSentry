"""
VaultSentry - Scan Engine Pipeline Controller
Orchestrates file staging, scanner execution, and JSON report generation.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any

from src.engine.config import LOGS_DIR
from src.engine.vqs import VirtualQuarantineSpace
from src.engine.scanners.identity_scanner import IdentityIntegrityScanner
from src.engine.scanners.pe_scanner import PEScanner
from src.engine.scanners.document_scanner import DocumentScanner
from src.engine.scanners.archive_scanner import ArchiveScanner
from src.engine.scanners.malware_scanner import MalwareScanner
from src.engine.scanners.heuristic_scanner import HeuristicScanner
from src.engine.scanners.risk_explainability import RiskAndExplainabilityEngine

# Logging Configuration
LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOGS_DIR / "pipeline.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (Pipeline): %(message)s"
)

class PipelineController:
    """
    Central orchestration engine for VaultSentry static security scanning.
    """

    def __init__(self) -> None:
        self.vqs = VirtualQuarantineSpace()
        self.identity_scanner = IdentityIntegrityScanner()
        self.pe_scanner = PEScanner()
        self.document_scanner = DocumentScanner()
        self.archive_scanner = ArchiveScanner()
        self.malware_scanner = MalwareScanner()
        self.heuristic_scanner = HeuristicScanner()
        self.risk_explainability_engine = RiskAndExplainabilityEngine()

    def run_pipeline(self, target_file_path: str) -> Dict[str, Any]:
        """
        Runs the end-to-end VaultSentry analysis workflow on a file.
        """
        logging.info(f"Initiating pipeline scan for target: {target_file_path}")

        # Step 1: Stage file inside Virtual Quarantine Space
        try:
            quarantine_manifest = self.vqs.stage_file(target_file_path)
            staged_path = Path(quarantine_manifest["staged_path"])
        except Exception as e:
            logging.error(f"Failed to quarantine target file: {str(e)}")
            return {
                "status": "ERROR",
                "error_stage": "VQS_STAGING",
                "message": f"Quarantine initialization failed: {str(e)}"
            }

        scan_outputs: Dict[str, Any] = {}

        # Step 2: Identity & Integrity Scan
        try:
            scan_outputs["identity_integrity"] = self.identity_scanner.inspect_identity_integrity(str(staged_path))
        except Exception as e:
            scan_outputs["identity_integrity"] = {"error": f"Identity scan failed: {str(e)}"}

        # Step 3: Conditional Structural Scanners
        # PE Scanner
        try:
            pe_res = self.pe_scanner.scan_pe(str(staged_path))
            scan_outputs["pe"] = pe_res
        except Exception as e:
            scan_outputs["pe"] = {"error": f"PE scan failed: {str(e)}"}

        # Document Scanner
        try:
            doc_res = self.document_scanner.scan_document(str(staged_path))
            scan_outputs["document"] = doc_res
        except Exception as e:
            scan_outputs["document"] = {"error": f"Document scan failed: {str(e)}"}

        # Archive Scanner
        try:
            arch_res = self.archive_scanner.scan_archive(str(staged_path))
            scan_outputs["archive"] = arch_res
        except Exception as e:
            scan_outputs["archive"] = {"error": f"Archive scan failed: {str(e)}"}

        # Step 4: Malware & Signature Scanner (YARA / ClamAV)
        try:
            scan_outputs["malware"] = self.malware_scanner.scan_malware(str(staged_path))
        except Exception as e:
            scan_outputs["malware"] = {"error": f"Malware scan failed: {str(e)}"}

        # Step 5: Heuristic Scanner
        try:
            prior_pe = scan_outputs.get("pe", {})
            scan_outputs["heuristics"] = self.heuristic_scanner.scan_heuristics(
                str(staged_path),
                prior_metadata=prior_pe if prior_pe.get("is_pe", False) else None
            )
        except Exception as e:
            scan_outputs["heuristics"] = {"error": f"Heuristic scan failed: {str(e)}"}

        # Step 6: Generate Risk Assessment & Explainable Security Report
        try:
            final_report = self.risk_explainability_engine.generate_report(
                file_info=quarantine_manifest,
                scan_results=scan_outputs
            )
            logging.info(f"Pipeline successfully completed for UUID {quarantine_manifest['uuid']}. Risk Score: {final_report['assessment']['risk_score']}")
            return final_report

        except Exception as e:
            logging.error(f"Failed to generate final report: {str(e)}")
            return {
                "status": "ERROR",
                "error_stage": "REPORT_GENERATION",
                "message": f"Report synthesis failed: {str(e)}"
            }


if __name__ == "__main__":
    print("[+] Pipeline Controller module loaded.")