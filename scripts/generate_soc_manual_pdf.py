import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

def build_soc_manual():
    pdf_path = "SecureCloud_SOC_Operational_Guide_and_Incident_Playbooks.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    primary_color = colors.HexColor("#0f172a") # Slate 900
    accent_color = colors.HexColor("#0284c7") # Sky 600
    rose_color = colors.HexColor("#be123c") # Rose 700
    amber_color = colors.HexColor("#b45309") # Amber 700
    purple_color = colors.HexColor("#7e22ce") # Purple 700
    emerald_color = colors.HexColor("#047857") # Emerald 700
    dark_bg = colors.HexColor("#1e293b") # Slate 800

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#93c5fd"),
        alignment=TA_CENTER
    )

    h1_style = ParagraphStyle(
        'Header1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=accent_color,
        spaceBefore=14,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'Header2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
        alignment=TA_JUSTIFY,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6,
        spaceAfter=6
    )

    callout_style = ParagraphStyle(
        'Callout',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title Banner Block
    header_data = [
        [
            Paragraph("SECURECLOUD ENTERPRISE SOC MANUAL", title_style),
        ],
        [
            Paragraph("Threat Intelligence Correlation • SOAR Policies • User Risk Matrix • Incident Playbooks", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[540])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), primary_color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 16),
        ('RIGHTPADDING', (0,0), (-1,-1), 16),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))

    # Executive Summary
    story.append(Paragraph("1. EXECUTIVE OVERVIEW & ARCHITECTURE", h1_style))
    story.append(Paragraph(
        "SecureCloud is an enterprise cloud storage security platform featuring LightGBM machine learning threat inference, "
        "graph-based threat correlation, Security Orchestration, Automation, and Response (SOAR) policies, and dynamic user behavioral risk matrix profiling. "
        "This operational manual provides Security Operations Center (SOC) administrators and system users with step-by-step procedures to understand, execute, and respond to incidents.",
        body_style
    ))
    story.append(Spacer(1, 8))

    # SECTION 1: Threat Intelligence Correlation Engine
    story.append(Paragraph("2. THREAT INTELLIGENCE CORRELATION ENGINE (/admin/correlation)", h1_style))
    story.append(Paragraph(
        "<b>What It Does:</b> Rather than analyzing file uploads in isolation, the Correlation Engine uses graph analytics to connect disparate telemetry signals across the entire system into actionable <b>Threat Clusters</b>.",
        body_style
    ))

    cluster_corr_table_data = [
        [Paragraph("<b>Telemetry Point</b>", callout_style), Paragraph("<b>Correlation Mechanism</b>", callout_style), Paragraph("<b>Threat Detection Objective</b>", callout_style)],
        [Paragraph("File SHA-256 Hashes", body_style), Paragraph("Tracks cross-account identical payload distribution", body_style), Paragraph("Detects coordinated malware spreading", body_style)],
        [Paragraph("Obfuscated Extensions", body_style), Paragraph("Flags double-extensions (e.g. .pdf.exe, .zip.iso)", body_style), Paragraph("Prevents Trojan disguise deception", body_style)],
        [Paragraph("IP Address Anomalies", body_style), Paragraph("Monitors rapid ingress from non-standard ASNs/Tor nodes", body_style), Paragraph("Detects brute-force credential stuffing & bots", body_style)],
        [Paragraph("Shared Link Exfiltration", body_style), Paragraph("Tracks anomalous view/download spikes on shared links", body_style), Paragraph("Halts rapid external data exfiltration", body_style)]
    ]
    t_corr = Table(cluster_corr_table_data, colWidths=[130, 200, 210])
    t_corr.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_corr)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>How Admin Executes Mitigation:</b>", h2_style))
    story.append(Paragraph("1. Navigate to <b>SOC -> Correlation</b> in the admin navbar.", bullet_style))
    story.append(Paragraph("2. Inspect active clusters (e.g., <i>THREAT CLUSTER #0042: Coordinated Ingress & Dual-Stage Disguised PE Infiltration</i>).", bullet_style))
    story.append(Paragraph("3. Under Recommended Automated Actions, click <b>'Execute Mitigation'</b>.", bullet_style))
    story.append(Paragraph("4. <b>What Happens Immediately in the Backend:</b>", bullet_style))
    story.append(Paragraph("   • Associated IP addresses (e.g., 198.51.100.42, 203.0.113.19) are automatically added to <b>IP Guard</b> blacklist.", bullet_style))
    story.append(Paragraph("   • High-risk payloads across affected accounts are quarantined in the Quarantine Vault.", bullet_style))
    story.append(Paragraph("   • Active public share tokens associated with the threat are instantly revoked.", bullet_style))
    story.append(Paragraph("   • The cluster status changes live to <font color='#047857'><b>MITIGATED & RESOLVED (0% Threat Score)</b></font>.", bullet_style))

    story.append(Paragraph("<b>Immediate User & Admin Response:</b>", h2_style))
    story.append(Paragraph("• <b>Administrator:</b> Review the Mitigation Report modal and confirm blacklisted IPs in IP Guard.", bullet_style))
    story.append(Paragraph("• <b>Affected User:</b> The user receives notification that suspicious files were quarantined. User should reset credentials and check active sessions.", bullet_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=10))

    # SECTION 2: SOAR Automated Security Response Policies
    story.append(Paragraph("3. SOAR SECURITY RESPONSE POLICIES ENGINE (/admin/policies)", h1_style))
    story.append(Paragraph(
        "<b>What It Does:</b> The SOAR engine provides autonomous, sub-second security orchestration that monitors system events in real-time and triggers defensive playbooks automatically without requiring human intervention.",
        body_style
    ))

    policy_table_data = [
        [Paragraph("<b>Policy Rule Name</b>", callout_style), Paragraph("<b>Trigger Condition (IF)</b>", callout_style), Paragraph("<b>Autonomous Mitigation (THEN)</b>", callout_style)],
        [
            Paragraph("<b>Rapid Malware Ingress Containment</b>", body_style),
            Paragraph("Malicious payload uploads >= 2 within 10 minutes", body_style),
            Paragraph("→ Quarantine files<br/>→ Revoke active public share links<br/>→ Escalate Sentinel VM to Phase 3<br/>→ Trigger military breach siren alert", body_style)
        ],
        [
            Paragraph("<b>Brute Force IP Containment & Ban</b>", body_style),
            Paragraph("Failed login attempts >= 5 from same IP in 5 min", body_style),
            Paragraph("→ Permanently blacklist IP in IP Guard<br/>→ Terminate active sessions<br/>→ Log critical SOC security alert", body_style)
        ],
        [
            Paragraph("<b>Repeated Suspicious Anomaly Escalation</b>", body_style),
            Paragraph("User uploads suspicious files >= 3", body_style),
            Paragraph("→ Enforce mandatory 2FA on account<br/>→ Notify SOC analyst<br/>→ Increase user risk level", body_style)
        ]
    ]
    t_pol = Table(policy_table_data, colWidths=[140, 180, 220])
    t_pol.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_pol)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>How Admin Executes & Tests Policies:</b>", h2_style))
    story.append(Paragraph("• <b>Automated Trigger:</b> Policies execute automatically when live telemetry thresholds are met during user uploads or login spikes.", bullet_style))
    story.append(Paragraph("• <b>Manual Execution:</b> On the policy card, click <b>'Test / Execute'</b>. The engine executes the real quarantine and revocation routines, increments the execution counter live, and updates the timestamp.", bullet_style))
    story.append(Paragraph("• <b>Audit Trail:</b> Click <b>'History'</b> on any policy card to review chronological execution records and exact actions applied.", bullet_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=10))

    # SECTION 3: User Risk Profiling Matrix
    story.append(Paragraph("4. USER RISK PROFILING MATRIX (/admin/risk-profiling)", h1_style))
    story.append(Paragraph(
        "<b>What It Does:</b> Assigns every account a multi-factor risk score (0 to 100) and classifies them into <b>CRITICAL (>=85)</b>, <b>HIGH (50-84)</b>, <b>MEDIUM (25-49)</b>, and <b>LOW (&lt;25)</b> tiers based on real behavior.",
        body_style
    ))

    risk_factors_data = [
        [Paragraph("<b>Risk Metric</b>", callout_style), Paragraph("<b>Weight / Impact</b>", callout_style), Paragraph("<b>Underlying Evidence Evaluated</b>", callout_style)],
        [Paragraph("Malicious Uploads", body_style), Paragraph("High (+30 to +50 pts)", body_style), Paragraph("Payloads identified as malware by LightGBM model", body_style)],
        [Paragraph("Suspicious Uploads", body_style), Paragraph("Medium (+15 to +25 pts)", body_style), Paragraph("High entropy, PE headers, or disguised extensions", body_style)],
        [Paragraph("Failed Auth Spikes", body_style), Paragraph("Medium (+10 to +20 pts)", body_style), Paragraph("Repeated bad password attempts in audit logs", body_style)],
        [Paragraph("Public Link Exposure", body_style), Paragraph("Low (+5 to +10 pts)", body_style), Paragraph("Volume of unrestricted active download links", body_style)],
        [Paragraph("2FA Compliance", body_style), Paragraph("Mitigating (-20 pts)", body_style), Paragraph("Active Two-Factor Authentication reduces overall account risk", body_style)]
    ]
    t_risk = Table(risk_factors_data, colWidths=[130, 140, 270])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_risk)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Administrative Remediation Actions:</b>", h2_style))
    story.append(Paragraph("1. <b>Enforce 2FA:</b> Clicking <i>'Enforce 2FA'</i> immediately sets <code>two_factor_enforced=True</code> in the database. The user will be required to configure TOTP upon their next authentication, and their risk score drops by 20 points.", bullet_style))
    story.append(Paragraph("2. <b>Lockdown User:</b> Clicking <i>'Lockdown User'</i> terminates all active sessions in <code>user_sessions</code>, revokes public share tokens, and marks the user as LOCKED DOWN. The user cannot access repositories until restored.", bullet_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=10))

    # SECTION 4: Confidential Vault Progressive Lockout
    story.append(Paragraph("5. CONFIDENTIAL VAULT PROGRESSIVE LOCKOUT & COUNTDOWN", h1_style))
    story.append(Paragraph(
        "<b>Zero-Knowledge Architecture:</b> Files in the Confidential Vault are encrypted using AES-256-GCM with PBKDF2 PIN key derivation. Administrators cannot access or view plain content.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Progressive Lockout Enforcement:</b>", h2_style
    ))
    story.append(Paragraph("• <b>Stage 0 (Active):</b> User has 3 consecutive attempts. After attempt 2, system warns: <i>'Only 1 attempt remaining before 30-minute lockout!'</i>", bullet_style))
    story.append(Paragraph("• <b>Stage 1 (30-Minute Lockout):</b> After 3 consecutive failed PIN attempts, file enters a 30-minute lockout. A live countdown timer (<code>mm:ss remaining</code>) displays at the side of the file card and inside the unlock modal. PIN input is disabled.", bullet_style))
    story.append(Paragraph("• <b>Stage 2 (2-Hour Lockout):</b> If unlocked after 30 minutes and 3 additional incorrect PINs are entered, file locks for 2 hours (<code>01h 59m 59s remaining</code>).", bullet_style))
    story.append(Paragraph("• <b>Stage 3 (Permanent Vault Lock):</b> If 3 further failed attempts occur, the file is <b>permanently locked</b>. The key derivation slot is wiped to protect confidential data from brute force.", bullet_style))
    story.append(Paragraph("• <b>Auto-Expiry Recovery:</b> As soon as the countdown timer hits <code>00:00</code>, the frontend automatically re-enables the PIN input and refreshes vault status.", bullet_style))

    story.append(Spacer(1, 14))

    # Summary Footer Table
    footer_data = [
        [Paragraph("<b>SecureCloud SOC Operational Acceptance</b> • Generated for Security Engineering & Compliance", ParagraphStyle('Foot', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#64748b"), alignment=TA_CENTER))]
    ]
    t_foot = Table(footer_data, colWidths=[540])
    t_foot.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_foot)

    doc.build(story)
    print(f"PDF successfully generated at: {pdf_path}")

if __name__ == "__main__":
    build_soc_manual()
