"""
VaultSentry - Module 5: Document Analysis Engine
Statically analyzes Microsoft Office files (OLE/OpenXML macros, remote templates) 
via oletools/zipfile and PDF structural streams/attachments via PyMuPDF (fitz).
"""

import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import fitz  # PyMuPDF
from oletools.olevba import VBA_Parser  # type: ignore

from plugins.base_scanner import BaseScanner


class DocumentScanner(BaseScanner):
    """Enterprise static security analyzer for Office documents and PDF files."""

    MAGIC_PDF = b"%PDF-"
    MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    MAGIC_ZIP = b"PK\x03\x04"

    OFFICE_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".rtf"
    }

    SUSPICIOUS_PDF_ACTIONS = {
        "/JavaScript": ("CRITICAL", "Embedded JavaScript Engine Stream Detected"),
        "/JS": ("CRITICAL", "Embedded JavaScript Engine Stream Detected"),
        "/Launch": ("CRITICAL", "Arbitrary Executable /Launch Directive Detected"),
        "/OpenAction": ("HIGH", "Document Auto-Execution (/OpenAction) Trigger Present"),
        "/AA": ("HIGH", "Additional Action (/AA) Auto-Execution Hook Present"),
        "/SubmitForm": ("MEDIUM", "Form Data Exfiltration (/SubmitForm) Endpoint Present"),
        "/ImportData": ("MEDIUM", "Dynamic Data Import (/ImportData) Hook Present"),
        "/EmbeddedFiles": ("MEDIUM", "Embedded File Container Tree (/EmbeddedFiles) Present")
    }

    DANGEROUS_ATTACHMENT_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".dll", ".pif", ".cpl"
    }

    @property
    def scanner_id(self) -> str:
        return "DocumentScanner"

    @property
    def priority(self) -> int:
        return 45

    def is_applicable(self, path: Path, context: Optional[Dict[str, Any]] = None) -> bool:
        ext = path.suffix.lower()
        if ext == ".pdf" or ext in self.OFFICE_EXTENSIONS:
            return True
        try:
            with open(path, "rb") as f:
                header = f.read(8)
                return (
                    header.startswith(self.MAGIC_PDF) or 
                    header.startswith(self.MAGIC_OLE) or 
                    header.startswith(self.MAGIC_ZIP)
                )
        except Exception:
            return False

    def _identify_document_type(self, path: Path) -> str:
        try:
            with open(path, "rb") as f:
                header = f.read(8)
                if header.startswith(self.MAGIC_PDF):
                    return "PDF"
                if header.startswith(self.MAGIC_OLE):
                    return "OFFICE_OLE"
                if header.startswith(self.MAGIC_ZIP):
                    return "OFFICE_OPENXML"
        except Exception:
            pass

        ext = path.suffix.lower()
        if ext == ".pdf":
            return "PDF"
        if ext in self.OFFICE_EXTENSIONS:
            return "OFFICE_GENERIC"
        return "UNKNOWN"

    def _scan_remote_template_injection(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        try:
            if not zipfile.is_zipfile(path):
                return findings

            with zipfile.ZipFile(path, "r") as zf:
                rels_files = [f for f in zf.namelist() if f.endswith(".rels")]
                for rels in rels_files:
                    content = zf.read(rels).decode("utf-8", errors="ignore")
                    if "attachedTemplate" in content and 'TargetMode="External"' in content:
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Document Analysis",
                            "finding": "Remote Template Injection Detected",
                            "explanation": f"Document relationships in '{rels}' instruct Word to load a remote macro-enabled template payload."
                        })
        except Exception:
            pass
        return findings

    def _scan_office_document(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        findings.extend(self._scan_remote_template_injection(path))

        vba_parser: Optional[VBA_Parser] = None
        try:
            vba_parser = VBA_Parser(str(path))
            if vba_parser.detect_vba_macros():
                findings.append({
                    "severity": "HIGH",
                    "category": "Document Analysis",
                    "finding": "VBA Macros Present",
                    "explanation": "Document contains embedded Visual Basic for Applications (VBA) macro modules."
                })

                analysis_results = vba_parser.analyze_macros()
                autoexec_found = False
                suspicious_ioc_count = 0

                for kw_type, keyword, description in analysis_results:
                    if kw_type == "AutoExec" and not autoexec_found:
                        findings.append({
                            "severity": "CRITICAL",
                            "category": "Document Analysis",
                            "finding": f"Macro Auto-Execution Trigger ({keyword})",
                            "explanation": f"Document automatically triggers macro execution on open/close: {description}"
                        })
                        autoexec_found = True
                    elif kw_type in ("Suspicious", "IOC"):
                        suspicious_ioc_count += 1
                        if suspicious_ioc_count <= 3:
                            findings.append({
                                "severity": "HIGH",
                                "category": "Document Analysis",
                                "finding": f"Suspicious Macro Command ({keyword})",
                                "explanation": f"Macro executes high-risk functions or commands: {description}"
                            })

                if suspicious_ioc_count > 3:
                    findings.append({
                        "severity": "HIGH",
                        "category": "Document Analysis",
                        "finding": f"Multiple Suspicious Macro Capabilities ({suspicious_ioc_count} total)",
                        "explanation": "Document contains an extensive set of suspicious execution, API call, or network indicators."
                    })
        except Exception as e:
            findings.append({
                "severity": "LOW",
                "category": "Document Analysis",
                "finding": "Office Parser Exception",
                "explanation": f"Non-standard Office container structure: {str(e)}"
            })
        finally:
            if vba_parser:
                try:
                    vba_parser.close()
                except Exception:
                    pass

        return findings

    def _scan_pdf_document(self, path: Path) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        doc: Optional[fitz.Document] = None

        try:
            doc = fitz.open(str(path))
            detected_keys = set()
            for i in range(1, doc.xref_length()):
                try:
                    obj_str = doc.xref_object(i)
                    for key, (severity, description) in self.SUSPICIOUS_PDF_ACTIONS.items():
                        if key in obj_str and key not in detected_keys:
                            detected_keys.add(key)
                            findings.append({
                                "severity": severity,
                                "category": "Document Analysis",
                                "finding": f"Suspicious PDF Action ({key})",
                                "explanation": f"PDF stream object {i} declares interactive action: {description}"
                            })
                except Exception:
                    continue

            embedded_count = doc.embfile_count()
            if embedded_count > 0:
                has_dangerous_attachment = False
                attachment_names: List[str] = []

                for idx in range(embedded_count):
                    try:
                        emb_info = doc.embfile_info(idx)
                        filename = emb_info.get("filename", f"attachment_{idx}")
                        attachment_names.append(filename)
                        ext = Path(filename).suffix.lower()
                        if ext in self.DANGEROUS_ATTACHMENT_EXTENSIONS:
                            has_dangerous_attachment = True
                    except Exception:
                        continue

                if has_dangerous_attachment:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Document Analysis",
                        "finding": "Executable/Script Embedded in PDF",
                        "explanation": f"PDF encapsulates high-risk executable attachments: {', '.join(attachment_names)}"
                    })
                else:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Document Analysis",
                        "finding": f"Embedded File Attachments ({embedded_count})",
                        "explanation": f"PDF contains embedded file objects: {', '.join(attachment_names)}"
                    })
        except Exception as e:
            findings.append({
                "severity": "HIGH",
                "category": "Document Analysis",
                "finding": "Corrupted or Malformed PDF Stream",
                "explanation": f"PDF engine failed to parse document structure: {str(e)}"
            })
        finally:
            if doc:
                try:
                    doc.close()
                except Exception:
                    pass

        return findings

    def scan(self, path: Path, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        doc_type = self._identify_document_type(path)
        if doc_type == "UNKNOWN":
            return {
                "scanner": self.scanner_id,
                "is_document": False,
                "findings": []
            }

        findings: List[Dict[str, str]] = []
        if doc_type == "PDF":
            findings = self._scan_pdf_document(path)
        else:
            findings = self._scan_office_document(path)

        return {
            "scanner": self.scanner_id,
            "is_document": True,
            "document_type": doc_type,
            "findings_count": len(findings),
            "findings": findings
        }