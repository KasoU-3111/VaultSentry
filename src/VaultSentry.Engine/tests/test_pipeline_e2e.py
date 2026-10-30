"""
VaultSentry - End-to-End Integration & Regression Test Suite
Validates all 11 core modules against synthetic attack vectors and evasion techniques.
"""

import os
import sys
import unittest
import zipfile
from pathlib import Path

# Add the current engine directory so its top-level imports resolve as in main.py.
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
ENGINE_DIR = WORKSPACE_ROOT / "src" / "VaultSentry.Engine"
sys.path.insert(0, str(ENGINE_DIR))

from pipeline import PipelineController


class TestVaultSentryPipelineE2E(unittest.TestCase):
    """Automated security verification test harness for VaultSentry static analysis engine."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = PipelineController()
        cls.test_dir = ENGINE_DIR / "tests" / "temp_e2e"
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        cls.samples_dir = ENGINE_DIR / "tests" / "samples"

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_01_double_extension_evasion_detected(self) -> None:
        """Asserts that double extension masquerading files are flagged as MALICIOUS."""
        sample_path = self.samples_dir / "invoice_details.pdf.exe"
        if not sample_path.exists():
            self.skipTest(f"Sample not found: {sample_path}")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "MALICIOUS")
        self.assertGreaterEqual(report["risk_score"], 75)

        # Assert specific heuristic finding presence
        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Double Extension" in f for f in finding_names),
            f"Expected double extension finding missing from {finding_names}"
        )

    def test_02_packed_binary_entropy_detected(self) -> None:
        """Asserts that packed/encrypted PE binaries receive a MALICIOUS or SUSPICIOUS verdict."""
        sample_path = self.samples_dir / "sample_packed.exe"
        if not sample_path.exists():
            self.skipTest(f"Sample not found: {sample_path}")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertIn(report["verdict"], ["SUSPICIOUS", "MALICIOUS"])
        self.assertGreaterEqual(report["risk_score"], 20)

        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Entropy" in f or "Packer" in f or "Malformed" in f for f in finding_names),
            f"Expected entropy/packer finding missing from {finding_names}"
        )

    def test_03_spoofed_pdf_header_detected(self) -> None:
        """Asserts that PE binaries disguised with a .pdf extension trigger header mismatch detections."""
        sample_path = self.samples_dir / "sample_spoofed_invoice.pdf"
        if not sample_path.exists():
            self.skipTest(f"Sample not found: {sample_path}")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "MALICIOUS")

        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Header vs Extension Mismatch" in f for f in finding_names),
            f"Expected header mismatch finding missing from {finding_names}"
        )

    def test_04_safe_text_file_passes(self) -> None:
        """Asserts that clean, harmless text files receive a SAFE verdict."""
        sample_path = self.samples_dir / "hello.txt"
        if not sample_path.exists():
            # Create hello.txt if missing
            sample_path.write_text("Hello VaultSentry Enterprise Security.")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "SAFE")
        self.assertLess(report["risk_score"], 20)


if __name__ == "__main__":
    unittest.main()