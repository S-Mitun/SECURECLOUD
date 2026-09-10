"""
SecureCloud - Security & Compliance Report Generation Service
Exports security scans, audit logs, ML model training metrics, and storage reports in PDF, CSV, and JSON.
"""

import io
import csv
import json
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from backend.app.models.models import SecurityScan, AuditLog, FileRecord, User
from ml.model_registry import ModelRegistry

class ReportService:
    @staticmethod
    def generate_threat_report_data(db: Session) -> Dict[str, Any]:
        """Gathers threat detection and scan history."""
        scans = db.query(SecurityScan).order_by(SecurityScan.scanned_at.desc()).limit(100).all()
        registry = ModelRegistry()
        active_model = registry.get_active_model_info()

        records = []
        for s in scans:
            records.append({
                "scan_id": s.id,
                "file_hash": s.file_hash,
                "threat_score": s.threat_score,
                "final_verdict": s.final_verdict,
                "security_status": s.security_status,
                "ml_prediction": s.ml_prediction,
                "model_version": s.model_version,
                "heuristic_score": s.heuristic_score,
                "heuristic_verdict": s.heuristic_verdict,
                "scanned_at": s.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
            })

        return {
            "title": "SecureCloud - Threat Intelligence & Security Scan Report",
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_scans_analyzed": len(records),
            "active_ml_model": active_model.get("version", "N/A") if active_model else "N/A",
            "active_model_accuracy": f"{active_model.get('accuracy', 0)}%" if active_model else "N/A",
            "active_model_malicious_recall": f"{active_model.get('malicious_recall', 0)}%" if active_model else "N/A",
            "records": records
        }

    @staticmethod
    def export_csv(report_data: Dict[str, Any]) -> str:
        """Exports report records to CSV format string."""
        records = report_data.get("records", [])
        if not records:
            return "No records found.\n"

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(records[0].keys()))
        writer.writeheader()
        for row in records:
            writer.writerow(row)
        return output.getvalue()

    @staticmethod
    def export_pdf(report_data: Dict[str, Any]) -> bytes:
        """Generates a professional executive PDF report using ReportLab."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=12
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14
        )

        elements = []
        elements.append(Paragraph(report_data.get("title", "SecureCloud Security Report"), title_style))
        elements.append(Paragraph(f"Generated: {report_data.get('generated_at')} | Active Model: {report_data.get('active_ml_model')} | Malicious Recall: {report_data.get('active_model_malicious_recall')}", subtitle_style))
        elements.append(Spacer(1, 10))

        records = report_data.get("records", [])[:30] # Top 30 in PDF summary
        if records:
            table_data = [["Scan ID", "File Hash (SHA-256)", "Threat Score", "Verdict", "Status", "Timestamp"]]
            for r in records:
                table_data.append([
                    str(r.get("scan_id", "")),
                    str(r.get("file_hash", ""))[:14] + "...",
                    f"{r.get('threat_score', 0)}/100",
                    str(r.get("final_verdict", "")),
                    str(r.get("security_status", "")),
                    str(r.get("scanned_at", ""))
                ])

            t = Table(table_data, colWidths=[50, 110, 75, 110, 80, 115])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")])
            ]))
            elements.append(t)
        else:
            elements.append(Paragraph("No threat scan entries recorded yet.", styles['Normal']))

        doc.build(elements)
        return buffer.getvalue()
