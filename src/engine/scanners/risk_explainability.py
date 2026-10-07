"""
VaultSentry - Modules 9 & 10: Risk Assessment Engine & Explainable Security Report Engine
Calculates unified threat scores (0 - 100), assigns risk categories, and produces 
explainable, human-readable security reports for the user and GUI.
"""

from typing import Dict, Any, List

class RiskAndExplainabilityEngine:

    def calculate_risk_score(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        raw_score = 0
        flagged_reasons: List[Dict[str, Any]] = []

        # 1. Identity & Integrity Checks
        identity = scan_results.get("identity_integrity", {})
        if identity.get("double_extension_detected", False):
            raw_score += 50
            flagged_reasons.append({
                "severity": "CRITICAL",
                "category": "Identity / Extension",
                "finding": "Double Extension Disguise Detected",
                "explanation": "This file uses a deceptive double extension (e.g., .pdf.exe). It appears as a document but executes binary code when opened."
            })
        elif identity.get("spoofing_detected", False):
            raw_score += 40
            flagged_reasons.append({
                "severity": "CRITICAL",
                "category": "Identity / Header",
                "finding": "Extension Spoofing Detected",
                "explanation": "The file extension does not match its actual magic byte header."
            })

        # 2. PE Scanner Checks
        pe = scan_results.get("pe", {})
        if pe.get("is_pe", False):
            if pe.get("has_high_entropy", False):
                raw_score += 25
                flagged_reasons.append({
                    "severity": "HIGH",
                    "category": "Structure",
                    "finding": "High Entropy / Packed Executable",
                    "explanation": "Portions of this executable are compressed or encrypted to obscure inner code."
                })
            
            flagged_apis = pe.get("flagged_apis", [])
            if flagged_apis:
                points = min(len(flagged_apis) * 10, 30)
                raw_score += points
                flagged_reasons.append({
                    "severity": "MEDIUM",
                    "category": "API Imports",
                    "finding": f"Sensitive Windows APIs ({len(flagged_apis)} detected)",
                    "explanation": "The program requests system APIs capable of process injection or dynamic memory modification."
                })

        # 3. Document Scanner Checks
        doc = scan_results.get("document", {})
        if doc.get("has_macros", False):
            raw_score += 30
            flagged_reasons.append({
                "severity": "HIGH",
                "category": "Macro Code",
                "finding": "Embedded VBA Macros",
                "explanation": "This document contains automated scripts that run when opened."
            })

        # 4. Heuristic Checks Integration
        heuristics = scan_results.get("heuristics", {})
        heur_flags = heuristics.get("flags", [])
        for flag in heur_flags:
            if "HIGH_RISK_DOUBLE_EXTENSION" in flag and not identity.get("double_extension_detected", False):
                raw_score += 40
                flagged_reasons.append({
                    "severity": "CRITICAL",
                    "category": "Heuristics",
                    "finding": "Double Extension Flagged",
                    "explanation": flag
                })
            elif "CRITICAL_IMPERSONATION" in flag:
                raw_score += 50
                flagged_reasons.append({
                    "severity": "CRITICAL",
                    "category": "Heuristics",
                    "finding": "System Executable Impersonation",
                    "explanation": flag
                })

        heur_score = heuristics.get("heuristic_score", 0)
        raw_score += int(heur_score * 0.3)

        # Final Bounded Score
        final_score = min(max(raw_score, 0), 100)

        # Verdict Assignment
        if final_score < 20:
            verdict = "SAFE"
            recommendation = "The file passed static security checks. Safe to move to local storage."
        elif final_score < 55:
            verdict = "SUSPICIOUS"
            recommendation = "The file exhibits suspicious traits. Retain in quarantine or review findings before opening."
        else:
            verdict = "MALICIOUS"
            recommendation = "CRITICAL RISK: Highly dangerous characteristics detected. Permanent deletion is strongly recommended."

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "recommendation": recommendation,
            "finding_count": len(flagged_reasons),
            "findings": flagged_reasons
        }

    def generate_report(self, file_info: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        assessment = self.calculate_risk_score(scan_results)

        return {
            "report_header": {
                "platform": "VaultSentry",
                "version": "1.0.0",
                "file_name": file_info.get("original_name", "unknown"),
                "staged_uuid": file_info.get("uuid", "N/A"),
                "file_size_bytes": file_info.get("file_size_bytes", 0)
            },
            "assessment": assessment,
            "detailed_scanner_outputs": scan_results
        }