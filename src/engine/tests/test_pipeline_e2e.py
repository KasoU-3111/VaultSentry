"""
VaultSentry - End-to-End Integration & Regression Test Suite
Validates all 11 core modules against synthetic attack vectors and evasion techniques.
"""

import io
import os
import sys
import unittest
import zipfile
from pathlib import Path

# Adjust path to locate workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from src.engine.pipeline import PipelineController


class TestVaultSentryPipelineE2E(unittest.TestCase):
    """Automated security verification test harness for VaultSentry static analysis engine."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = PipelineController()
        cls.test_dir = WORKSPACE_ROOT / "src" / "engine" / "tests" / "temp_e2e"
        cls.test_dir.mkdir(parents=True, exist_ok=True)
        cls.samples_dir = WORKSPACE_ROOT / "src" / "engine" / "tests" / "samples"

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
        self.assertIn(report["verdict"], ["MALICIOUS", "SUSPICIOUS"])
        self.assertGreaterEqual(report["risk_score"], 45)

        # Assert entropy or packer finding presence
        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Entropy" in f or "Packer" in f or "Malformed" in f for f in finding_names),
            f"Expected packer/entropy finding missing from {finding_names}"
        )

    def test_03_magic_byte_masquerade_detected(self) -> None:
        """Asserts that executable headers disguised as document extensions are flagged."""
        sample_path = self.samples_dir / "sample_spoofed_invoice.pdf"
        if not sample_path.exists():
            self.skipTest(f"Sample not found: {sample_path}")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "MALICIOUS")
        self.assertGreaterEqual(report["risk_score"], 75)

        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Masquerade" in f or "Mismatch" in f for f in finding_names),
            f"Expected header masquerade finding missing from {finding_names}"
        )

    def test_04_zip_slip_path_traversal_flagged(self) -> None:
        """Asserts that archives containing directory traversal sequences are caught."""
        zip_path = self.test_dir / "zip_slip_exploit.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../Windows/System32/calc.exe", b"MOCK_PAYLOAD")

        report = self.controller.run_pipeline(str(zip_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "MALICIOUS")

        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Zip Slip" in f or "Path Traversal" in f for f in finding_names),
            f"Expected Zip Slip finding missing from {finding_names}"
        )

    def test_05_zip_bomb_exhaustion_flagged(self) -> None:
        """Asserts that extreme compression ratios are flagged as Decompression Bombs."""
        bomb_path = self.test_dir / "zip_bomb.zip"
        with zipfile.ZipFile(bomb_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 10 MB of zeros compresses to a few hundred bytes (> 1000:1 ratio)
            zf.writestr("huge_payload.bin", b"\x00" * (10 * 1024 * 1024))

        report = self.controller.run_pipeline(str(bomb_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["verdict"], "MALICIOUS")

        finding_names = [f["finding"] for f in report["findings"]]
        self.assertTrue(
            any("Zip Bomb" in f or "Decompression" in f for f in finding_names),
            f"Expected Zip Bomb finding missing from {finding_names}"
        )

    def test_06_vqs_staging_isolation_and_permissions(self) -> None:
        """Verifies that VQS assigns UUID container and enforces read-only attributes."""
        sample_path = self.test_dir / "clean_sample.txt"
        sample_path.write_text("Hello VaultSentry Security Engine")

        report = self.controller.run_pipeline(str(sample_path))
        self.assertEqual(report["status"], "SUCCESS")
        self.assertIn("quarantine_id", report)
        self.assertTrue(os.path.exists(report["staged_path"]))

        # Verify staged permissions (Read-only on Windows/Linux)
        staged_file = Path(report["staged_path"])
        file_stat = staged_file.stat().st_mode
        self.assertEqual(file_stat & 0o222, 0, "Staged file should not possess write permissions")


if __name__ == "__main__":
    unittest.main(verbosity=2)