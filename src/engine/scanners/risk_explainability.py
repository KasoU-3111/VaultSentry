"""
VaultSentry - Modules 9 & 10: Risk Assessment Engine & Explainable Security Report Engine
Calculates unified threat scores (0 - 100), assigns risk categories, and produces 
explainable, human-readable security reports for the user and GUI.
"""

from typing import Dict, Any, List

class RiskAndExplainabilityEngine:
    """
    Aggregates multi-scanner outputs into a weighted risk score and natural language security report.
    """

    def calculate_risk_score(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes findings from all scanners to calculate a normalized risk score (0-100).
        """
        raw_score = 0
        flagged_reasons: List[Dict[str, Any]] = []

        # 1. Identity & Integrity Checks
        identity = scan_results.get("identity_integrity", {})
        if identity.get("spoofing_detected", False):
            raw_score += 40
            flagged_reasons.append({
                "severity": "CRITICAL",
                "category": "Identity",
                "finding": "Extension Spoofing Detected",
                "explanation": "The file extension does not match its actual byte header. Attackers often disguise executable malware as documents or images."
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
                    "explanation": "Portions of this executable are encrypted or compressed, which is commonly done to hide malicious code from antivirus inspection."
                })
            
            flagged_apis = pe.get("flagged_apis", [])
            if flagged_apis:
                points = min(len(flagged_apis) * 10, 30)
                raw_score += points
                flagged_reasons.append({
                    "severity": "MEDIUM",
                    "category": "API Imports",
                    "finding": f"Sensitive Windows APIs ({len(flagged_apis)} detected)",
                    "explanation": "The program requests access to system APIs that allow process memory modification, hook injection, or network downloading."
                })

        # 3. Document Scanner Checks
        doc = scan_results.get("document", {})
        if doc.get("has_macros", False):
            raw_score += 30
            flagged_reasons.append({
                "severity": "HIGH",
                "category": "Macro Code",
                "finding": "Embedded VBA Macros",
                "explanation": "This document contains automated scripts that run when opened. Malicious documents use macros to download and install payloads."
            })
        
        if "/JavaScript" in doc.get("found_suspicious_keys", []):
            raw_score += 35
            flagged_reasons.append({
                "severity": "HIGH",
                "category": "PDF Script",
                "finding": "PDF Embedded JavaScript",
                "explanation": "This PDF contains embedded JavaScript code that runs automatically, which can exploit vulnerabilities in PDF readers."
            })

        # 4. Archive Scanner Checks
        archive = scan_results.get("archive", {})
        if archive.get("is_zip_bomb", False):
            raw_score += 50
            flagged_reasons.append({
                "severity": "CRITICAL",
                "category": "Archive",
                "finding": "Potential Decompression Bomb (Zip Bomb)",
                "explanation": "The archive expands to an abnormally large size compared to its compressed state, which can exhaust storage or system RAM."
            })
        if archive.get("has_password", False):
            raw_score += 15
            flagged_reasons.append({
                "severity": "MEDIUM",
                "category": "Archive",
                "finding": "Password Protected Archive",
                "explanation": "The archive contents are encrypted with a password, preventing static analysis from verifying inner files."
            })

        # 5. YARA & ClamAV Signature Checks
        malware = scan_results.get("malware", {})
        yara_matches = malware.get("yara", {}).get("matches", [])
        if yara_matches:
            raw_score += 50
            for match in yara_matches:
                flagged_reasons.append({
                    "severity": "CRITICAL",
                    "category": "YARA Signature",
                    "finding": f"YARA Rule Triggered: {match['rule']}",
                    "explanation": f"File matched known malware pattern rules ({match.get('meta', {})})."
                })

        if malware.get("clamav", {}).get("is_infected", False):
            raw_score += 60
            flagged_reasons.append({
                "severity": "CRITICAL",
                "category": "ClamAV Signature",
                "finding": "Known Malware Signature Detected",
                "explanation": "ClamAV database identified this file as a known virus or trojan."
            })

        # 6. Heuristic Checks
        heuristics = scan_results.get("heuristics", {})
        heur_score = heuristics.get("heuristic_score", 0)
        raw_score += int(heur_score * 0.4)

        # Final Bounded Score
        final_score = min(max(raw_score, 0), 100)

        # Verdict Assignment
        if final_score < 20:
            verdict = "SAFE"
            recommendation = "The file passed all static security checks. It is safe to move to local storage."
        elif final_score < 55:
            verdict = "SUSPICIOUS"
            recommendation = "The file exhibits unusual characteristics. Retain in quarantine or review findings before opening."
        else:
            verdict = "MALICIOUS"
            recommendation = "CRITICAL RISK: Highly dangerous characteristics or signatures found. Permanent deletion is strongly recommended."

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "recommendation": recommendation,
            "finding_count": len(flagged_reasons),
            "findings": flagged_reasons
        }

    def generate_report(self, file_info: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates the complete Explainable Security Report JSON payload.
        """
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


if __name__ == "__main__":
    print("[+] Risk Assessment & Explainable Security Report Engine loaded.")