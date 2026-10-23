"""
VaultSentry - Modules 9 & 10: Risk Assessment Engine & Explainable Security Report Engine
Calculates unified threat scores (0 - 100), assigns risk categories, and produces 
explainable, human-readable security reports for the user and GUI.
"""

from typing import Any, Dict, List


class RiskAndExplainabilityEngine:
    """
    Enterprise risk evaluation and explainable security report generator.
    Processes normalized security findings aggregated across all static scanners.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 45,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
    }

    def assess_risk(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates a bounded risk score (0 - 100) and assigns an actionable verdict
        based on aggregated findings from the plugin execution pipeline.
        """
        raw_score = 0
        severity_breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        deduplicated_findings: List[Dict[str, Any]] = []
        seen_findings = set()

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            category = str(finding.get("category", "General Security")).strip()
            title = str(finding.get("finding", "Unspecified Finding")).strip()
            explanation = str(finding.get("explanation", "")).strip()
            severity = str(finding.get("severity", "INFO")).strip().upper()

            if severity not in self.SEVERITY_WEIGHTS:
                severity = "INFO"

            finding_key = (category, title, severity)
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            normalized_finding = {
                "severity": severity,
                "category": category,
                "finding": title,
                "explanation": explanation
            }

            severity_breakdown[severity] += 1
            raw_score += self.SEVERITY_WEIGHTS[severity]
            deduplicated_findings.append(normalized_finding)

        # Apply score cap bounded to range [0, 100]
        final_score = min(max(raw_score, 0), 100)

        # Verdict Assignment Logic
        if final_score < 20:
            verdict = "SAFE"
            recommendation = "The file passed static security checks with no high-risk indicators detected."
        elif final_score < 55:
            verdict = "SUSPICIOUS"
            recommendation = "Suspicious traits identified. Keep file isolated in quarantine or inspect detailed findings before opening."
        else:
            verdict = "MALICIOUS"
            recommendation = "CRITICAL RISK: Dangerous characteristics or malware signatures detected. Deletion is strongly recommended."

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "recommendation": recommendation,
            "severity_breakdown": severity_breakdown,
            "finding_count": len(deduplicated_findings),
            "findings": deduplicated_findings
        }

    def generate_report(self, file_info: Dict[str, Any], pipeline_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds a complete explainable security report object suitable for JSON serialization and GUI display.
        """
        aggregated_findings = pipeline_output.get("aggregated_findings", [])
        assessment = self.assess_risk(aggregated_findings)

        return {
            "report_header": {
                "platform": "VaultSentry",
                "engine_version": "1.0.0",
                "file_name": file_info.get("original_name", "Unknown File"),
                "quarantine_id": file_info.get("quarantine_id", "N/A"),
                "file_size_bytes": file_info.get("file_size_bytes", 0)
            },
            "assessment": assessment,
            "scanner_reports": pipeline_output.get("reports", {})
        }