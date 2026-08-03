"""
VaultSentry - Module 5: Document Analysis Engine
Statically analyzes Microsoft Office files (OLE/OpenXML macros) via oletools 
and PDF structure/JavaScript streams via PyMuPDF (fitz).
"""

from pathlib import Path
from typing import Dict, Any, List

import fitz  # PyMuPDF
from oletools.olevba import VBA_Parser  # type: ignore

# Suspicious PDF actions and keys
SUSPICIOUS_PDF_KEYS = [
    "/JavaScript", "/JS", "/Launch", "/EmbeddedFiles", 
    "/OpenAction", "/AA", "/SubmitForm", "/ImportData"
]

class DocumentScanner:
    """
    Static security analyzer for Office documents and PDF files.
    """

    def scan_office_document(self, path: Path) -> Dict[str, Any]:
        """
        Parses Office files to detect suspicious VBA macros, AutoExec triggers, and obfuscation.
        """
        warnings: List[str] = []
        has_macros = False
        macro_results: List[Dict[str, Any]] = []

        try:
            vba_parser = VBA_Parser(str(path))
            has_macros = vba_parser.detect_vba_macros()

            if has_macros:
                warnings.append("SUSPICIOUS: Microsoft Office VBA Macros detected inside document.")
                
                for _, _, _, vba_code in vba_parser.extract_macros():
                    # Analyze extracted macro code using oletools heuristics
                    analysis = vba_parser.analyze_macros()
                    for kw_type, keyword, description in analysis:
                        if kw_type == "AutoExec":
                            warnings.append(f"CRITICAL Macro Trigger: '{keyword}' ({description})")
                        elif kw_type in ("Suspicious", "IOC"):
                            warnings.append(f"RISK Macro Keyword: '{keyword}' ({description})")

                        macro_results.append({
                            "type": kw_type,
                            "keyword": keyword,
                            "description": description
                        })

            vba_parser.close()

            return {
                "is_office_doc": True,
                "has_macros": has_macros,
                "macro_findings": macro_results,
                "warnings": warnings,
                "status": "COMPLETED"
            }

        except Exception as e:
            return {
                "is_office_doc": False,
                "error": f"Failed to parse as Office document: {str(e)}"
            }

    def scan_pdf_document(self, path: Path) -> Dict[str, Any]:
        """
        Inspects PDF streams for embedded JavaScript, launch triggers, and hidden attachments.
        """
        warnings: List[str] = []
        found_suspicious_keys: List[str] = []

        try:
            doc = fitz.open(str(path))
            
            # 1. Scan xref object graph for suspicious actions
            for i in range(1, doc.xref_length()):
                try:
                    obj_str = doc.xref_object(i)
                    for key in SUSPICIOUS_PDF_KEYS:
                        if key in obj_str and key not in found_suspicious_keys:
                            found_suspicious_keys.append(key)
                            if key in ["/JavaScript", "/JS"]:
                                warnings.append(f"CRITICAL: PDF contains embedded JavaScript stream ({key}).")
                            elif key == "/Launch":
                                warnings.append("CRITICAL: PDF contains executable /Launch action.")
                            else:
                                warnings.append(f"SUSPICIOUS: PDF contains action trigger '{key}'.")
                except Exception:
                    continue

            # 2. Inspect embedded attachments
            embedded_count = doc.embfile_count()
            if embedded_count > 0:
                warnings.append(f"RISK: PDF contains {embedded_count} embedded attachment(s).")

            doc.close()

            return {
                "is_pdf": True,
                "page_count": len(doc) if 'doc' in locals() else 0,
                "found_suspicious_keys": found_suspicious_keys,
                "embedded_files_count": embedded_count,
                "warnings": warnings,
                "status": "COMPLETED"
            }

        except Exception as e:
            return {
                "is_pdf": False,
                "error": f"Failed to parse as PDF document: {str(e)}"
            }

    def scan_document(self, file_path_str: str) -> Dict[str, Any]:
        """
        Unified router for document analysis based on file extension.
        """
        path = Path(file_path_str).resolve()
        ext = path.suffix.lower()

        if ext in [".doc", ".docx", ".xls", ".xlsx", ".docm", ".xlsm", ".ppt", ".pptm"]:
            return self.scan_office_document(path)
        elif ext == ".pdf":
            return self.scan_pdf_document(path)
        else:
            return {
                "is_document": False,
                "message": f"File extension '{ext}' is not supported by DocumentScanner."
            }


if __name__ == "__main__":
    print("[+] Document Analysis Engine module loaded.")