import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

def generate_friendly_guide():
    pdf_path = "SecureCloud_Easy_SOC_Guide_With_Examples.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=32,
        rightMargin=32,
        topMargin=32,
        bottomMargin=32
    )

    styles = getSampleStyleSheet()

    # Color Palette
    primary = colors.HexColor("#0f172a") # Slate 900
    sky_blue = colors.HexColor("#0284c7") # Sky 600
    card_bg = colors.HexColor("#f8fafc") # Slate 50
    border_color = colors.HexColor("#cbd5e1") # Slate 300
    rose = colors.HexColor("#e11d48") # Rose 600
    amber = colors.HexColor("#d97706") # Amber 600
    purple = colors.HexColor("#9333ea") # Purple 600
    emerald = colors.HexColor("#059669") # Emerald 600

    # Custom Typography
    title_style = ParagraphStyle(
        'MainTitle',
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    sub_style = ParagraphStyle(
        'SubTitle',
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#bae6fd"),
        alignment=TA_CENTER
    )

    h1_style = ParagraphStyle(
        'Heading1',
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'Heading2',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=sky_blue,
        spaceBefore=8,
        spaceAfter=4
    )

    body = ParagraphStyle(
        'NormalBody',
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4
    )

    body_bold = ParagraphStyle(
        'BoldBody',
        parent=body,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#0f172a")
    )

    callout_text = ParagraphStyle(
        'CalloutText',
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )

    example_box_style = ParagraphStyle(
        'ExampleText',
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title Block Table
    t_header = Table([
        [Paragraph("SECURECLOUD 2.0 - SIMPLE & EASY SOC GUIDE", title_style)],
        [Paragraph("How Correlation, SOAR Policies & User Risk Matrix Work with Real Examples", sub_style)]
    ], colWidths=[548])
    t_header.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), primary),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 10))

    # Quick Summary Table
    story.append(Paragraph("QUICK OVERVIEW: WHAT IS THE DIFFERENCE?", h1_style))
    summary_data = [
        [
            Paragraph("<b>Section</b>", body_bold),
            Paragraph("<b>Simple Analogy</b>", body_bold),
            Paragraph("<b>What It Does</b>", body_bold),
            Paragraph("<b>Main Button Admin Clicks</b>", body_bold)
        ],
        [
            Paragraph("<font color='#e11d48'><b>1. Threat Correlation</b></font><br/>(/admin/correlation)", body),
            Paragraph("<b>The Detective</b> 🕵️‍♂️", body),
            Paragraph("Connects different clues (IPs + virus files + failed logins) into one big attack cluster.", body),
            Paragraph("<b>'Execute Mitigation'</b> (Bans IP, quarantines files, revokes links)", body)
        ],
        [
            Paragraph("<font color='#d97706'><b>2. SOAR Policies</b></font><br/>(/admin/policies)", body),
            Paragraph("<b>The Automatic Alarm / Sprinkler</b> ⚡", body),
            Paragraph("Automatic rules: IF virus uploaded > 2, THEN immediately isolate and sound alarm.", body),
            Paragraph("<b>'Test / Execute'</b> (Runs the automatic defense rule instantly)", body)
        ],
        [
            Paragraph("<font color='#9333ea'><b>3. Risk Matrix</b></font><br/>(/admin/risk-profiling)", body),
            Paragraph("<b>The Employee Safety Score</b> 👤", body),
            Paragraph("Gives every user a risk score (0-100). Flags hacked or careless accounts.", body),
            Paragraph("<b>'Enforce 2FA'</b> or <b>'Lockdown User'</b>", body)
        ]
    ]
    t_sum = Table(summary_data, colWidths=[110, 110, 190, 138])
    t_sum.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_sum)
    story.append(Spacer(1, 12))

    # SECTION 1: Threat Intelligence Correlation
    story.append(Paragraph("1. 🧠 THREAT INTELLIGENCE CORRELATION ENGINE", h1_style))
    story.append(Paragraph(
        "<b>In Simple Words:</b> If an attacker tries to hack the system, they don't just do one thing. They might upload a bad file, try passwords, and share links. "
        "The Correlation Engine gathers all these clues from different users and IPs and puts them together into a <b>Threat Cluster</b>.",
        body
    ))

    # Real Example Box
    ex1_data = [
        [
            Paragraph(
                "<b>REAL-WORLD EXAMPLE SCENARIO:</b><br/>"
                "• <b>Step 1 (Attack):</b> An attacker from Russia (IP: <code>198.51.100.42</code>) uploads a fake PDF named <code>invoice.pdf.exe</code> into User 17's account.<br/>"
                "• <b>Step 2 (Exfiltration):</b> The attacker generates a public share link to spread the file to other employees.<br/>"
                "• <b>Step 3 (Correlation):</b> SecureCloud notices: same bad IP + double-extension virus + active share link. It creates <b>THREAT CLUSTER #0042</b>.<br/>"
                "• <b>Step 4 (Admin Action):</b> Admin opens <i>/admin/correlation</i>, sees the 92% Danger Cluster, and clicks <b>'Execute Mitigation'</b>.<br/>"
                "• <b>Step 5 (What Happens Immediately):</b><br/>"
                "   1. Attacker's IP <code>198.51.100.42</code> is permanently banned in IP Guard.<br/>"
                "   2. <code>invoice.pdf.exe</code> is locked into Quarantine Vault.<br/>"
                "   3. The public share link is destroyed so no one can download it.<br/>"
                "   4. Cluster status changes live to <b>MITIGATED & RESOLVED (0% Threat)</b>.",
                example_box_style
            )
        ]
    ]
    t_ex1 = Table(ex1_data, colWidths=[548])
    t_ex1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#fff1f2")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#fecdd3")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_ex1)
    story.append(Spacer(1, 12))

    # SECTION 2: SOAR Policies
    story.append(Paragraph("2. ⚡ SOAR AUTOMATED RESPONSE POLICIES", h1_style))
    story.append(Paragraph(
        "<b>In Simple Words:</b> SOAR stands for <i>Security Orchestration, Automation, and Response</i>. "
        "It is like a smart home security system. You give it rules: <b>'IF something dangerous happens, THEN take action in 0.1 seconds without waiting for human approval.'</b>",
        body
    ))

    # Example Rules Table
    policy_data = [
        [
            Paragraph("<b>Rule Name</b>", body_bold),
            Paragraph("<b>IF (Trigger Condition)</b>", body_bold),
            Paragraph("<b>THEN (Automatic Reaction)</b>", body_bold)
        ],
        [
            Paragraph("<b>Rapid Malware Ingress Containment</b>", body),
            Paragraph("Someone uploads 2 or more virus files within 10 minutes.", body),
            Paragraph("1. Quarantine all virus files immediately.<br/>2. Revoke all active public share links.<br/>3. Sound the military breach alarm on admin navbar.", body)
        ],
        [
            Paragraph("<b>Brute Force IP Containment & Ban</b>", body),
            Paragraph("5 failed login attempts occur from the same IP address in 5 minutes.", body),
            Paragraph("1. Blacklist the IP address in IP Guard.<br/>2. Terminate any active sessions from that IP.<br/>3. Create a high-priority security audit log.", body)
        ],
        [
            Paragraph("<b>Suspicious Anomaly Escalation</b>", body),
            Paragraph("A user account uploads 3 suspicious files.", body),
            Paragraph("1. Enforce Two-Factor Authentication (2FA) on the user.<br/>2. Send an alert to SOC Admin.<br/>3. Increase user risk score.", body)
        ]
    ]
    t_pol = Table(policy_data, colWidths=[150, 180, 218])
    t_pol.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fef3c7")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_pol)
    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>How Admin Uses /admin/policies:</b> Click <b>'Test / Execute'</b> to manually test any policy anytime. The execution counter increments and saves to the history log.", body))
    story.append(Spacer(1, 12))

    # SECTION 3: User Risk Profiling Matrix
    story.append(Paragraph("3. 👤 USER RISK PROFILING MATRIX", h1_style))
    story.append(Paragraph(
        "<b>In Simple Words:</b> Gives every user a Safety Score from 0 to 100 so the Admin instantly knows who is safe and who is at risk.",
        body
    ))

    # Risk Tiers Box
    tier_data = [
        [
            Paragraph("<b>CRITICAL (85-100)</b> 🔴<br/>Account has uploaded malware or is being brute-forced.", body),
            Paragraph("<b>HIGH (50-84)</b> 🟠<br/>Multiple suspicious files or unencrypted public links.", body),
            Paragraph("<b>MEDIUM (25-49)</b> 🟡<br/>Occasional failed logins or missing 2FA.", body),
            Paragraph("<b>LOW (0-24)</b> 🟢<br/>Clean files, active 2FA, normal behavior.", body)
        ]
    ]
    t_tier = Table(tier_data, colWidths=[137, 137, 137, 137])
    t_tier.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#ffe4e6")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#ffedd5")),
        ('BACKGROUND', (2,0), (2,0), colors.HexColor("#fef9c3")),
        ('BACKGROUND', (3,0), (3,0), colors.HexColor("#dcfce7")),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (0,0), (-1,-1), 'CENTER')
    ]))
    story.append(t_tier)
    story.append(Spacer(1, 8))

    # Risk Action Example Box
    ex3_data = [
        [
            Paragraph(
                "<b>HOW ADMIN RESPONDS TO A HIGH-RISK USER:</b><br/>"
                "• <b>Example:</b> User <i>'Rahul'</i> has Risk Score <b>88/100 (CRITICAL)</b> because his account uploaded a virus and had 4 failed logins.<br/>"
                "• <b>Action 1 - Click 'Enforce 2FA':</b> The system immediately locks the requirement for 2FA. Next time Rahul logs in, he must use Google Authenticator/TOTP. His risk score drops by 20 points.<br/>"
                "• <b>Action 2 - Click 'Lockdown User':</b> If the admin suspects Rahul's account is currently being hacked, clicking Lockdown severs all open browser sessions, cancels his links, and prevents login until admin re-enables it.",
                example_box_style
            )
        ]
    ]
    t_ex3 = Table(ex3_data, colWidths=[548])
    t_ex3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f3e8ff")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e9d5ff")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_ex3)
    story.append(Spacer(1, 12))

    # SECTION 4: Confidential Countdown Summary
    story.append(Paragraph("4. 🔒 CONFIDENTIAL VAULT LOCKOUT COUNTDOWN", h1_style))
    story.append(Paragraph(
        "• <b>Wrong PIN 1 & 2:</b> Warning message: <i>'Incorrect PIN. Only 1 attempt remaining!'</i><br/>"
        "• <b>Wrong PIN 3:</b> File locks for <b>30 minutes</b>. A live ticking clock (<code>29m 45s remaining</code>) appears at the side of the file.<br/>"
        "• <b>Wrong PIN 6:</b> File locks for <b>2 hours</b> (<code>01h 59m 50s remaining</code>).<br/>"
        "• <b>Wrong PIN 9:</b> <b>Permanently Locked</b>. Decryption key is permanently destroyed to protect private data from brute force.<br/>"
        "• <b>When timer reaches 00:00:</b> Input automatically unlocks so the user can enter the correct PIN.",
        body
    ))

    story.append(Spacer(1, 10))

    # Footer
    t_foot = Table([
        [Paragraph("<b>SecureCloud 2.0</b> • User-Friendly SOC Operations Manual", ParagraphStyle('Foot', fontName='Helvetica', fontSize=8, textColor=colors.HexColor("#64748b"), alignment=TA_CENTER))]
    ], colWidths=[548])
    t_foot.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_foot)

    doc.build(story)
    print(f"User-Friendly PDF generated at: {pdf_path}")

if __name__ == "__main__":
    generate_friendly_guide()
