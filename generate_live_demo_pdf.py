"""
Live Attack Demonstration PDF Generator
Creates step-by-step guide for demonstrating all 7 OWASP attacks with real-time dashboard
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.lib import colors

def create_live_demo_pdf():
    """Create comprehensive live attack demo PDF."""
    
    filename = "AI_Honeypot_Live_Attack_Demo.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter,
                           topMargin=0.5*inch, bottomMargin=0.5*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#2C3E50'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#7F8C8D'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#E74C3C'),
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    attack_style = ParagraphStyle(
        'Attack',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#3498DB'),
        spaceAfter=6,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    step_style = ParagraphStyle(
        'Step',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#2C3E50'),
        spaceAfter=4,
        leftIndent=10,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#34495E'),
        spaceAfter=6,
        leftIndent=20,
        alignment=TA_JUSTIFY
    )
    
    url_style = ParagraphStyle(
        'URL',
        parent=styles['Code'],
        fontSize=8,
        fontName='Courier',
        textColor=colors.HexColor('#27AE60'),
        leftIndent=20,
        spaceAfter=6,
        backColor=colors.HexColor('#ECF0F1')
    )
    
    dashboard_style = ParagraphStyle(
        'Dashboard',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#8E44AD'),
        spaceAfter=4,
        leftIndent=20,
        fontName='Helvetica-Oblique'
    )
    
    # Title Page
    story.append(Paragraph("AI Honeypot", title_style))
    story.append(Paragraph("Live Attack Demonstration Guide", subtitle_style))
    story.append(Paragraph("Step-by-Step Demo of All 7 OWASP Attacks", subtitle_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Quick Setup
    story.append(Paragraph("PRE-DEMO SETUP", section_style))
    story.append(Paragraph("1. Start the server", step_style))
    story.append(Paragraph("<font name='Courier' size=8>python app.py</font>", url_style))
    
    story.append(Paragraph("2. Open the Demo Controller (Primary Method)", step_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/controller</font>", url_style))
    story.append(Paragraph(
        "For a smooth demo, use this controller to execute attacks with one click.",
        body_style
    ))
    
    story.append(Paragraph("3. Open Dashboard (Can do from Controller)", step_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/demo</font>", url_style))
    
    story.append(Paragraph("4. Position windows side-by-side", step_style))
    story.append(Paragraph(
        "Left: Demo Controller | Right: Live Dashboard showing real-time updates",
        body_style
    ))
    
    story.append(Paragraph("5. Have this PDF ready as a script/backup", step_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Demo Flow Overview
    story.append(Paragraph("DEMO FLOW (7-10 minutes)", section_style))
    story.append(Paragraph(
        "You will demonstrate 7 attack types in sequence.",
        body_style
    ))
    story.append(Paragraph("<b>Primary Method:</b> Click buttons on the Demo Controller (Recommended)", body_style))
    story.append(Paragraph("<b>Backup Method:</b> Copy-paste URLs from this PDF if controller fails", body_style))
    story.append(Paragraph("<b>For each attack:</b>", body_style))
    story.append(Paragraph("• Click attack button (or navigate to URL)", body_style))
    story.append(Paragraph("• Point out the detected attack on the dashboard", body_style))
    story.append(Paragraph("• Highlight the new <b>LLM Reasoning</b> steps", body_style))
    story.append(Paragraph("• Show the <b>Attacker Profile</b> updating", body_style))
    story.append(Paragraph("• Explain the <b>Threat Intelligence</b> score", body_style))
    
    story.append(PageBreak())
    
    # ==================== ATTACK 1: SQL INJECTION ====================
    story.append(Paragraph("ATTACK 1: SQL INJECTION", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=' OR 1=1--</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is a classic SQL injection attack. The payload ' OR 1=1-- attempts to bypass authentication "
        "by injecting SQL logic. Notice the single quote, OR condition, and comment marker.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ <b>LLM Reasoning:</b> Shows step-by-step analysis of the payload", dashboard_style))
    story.append(Paragraph("✓ <b>Attacker Profile:</b> Shows 'NOVICE' skill level and 'SQLMap' tool detection", dashboard_style))
    story.append(Paragraph("✓ <b>Threat Intelligence:</b> Updates threat score (likely >60)", dashboard_style))
    story.append(Paragraph("✓ <b>Intelligence Analysis:</b> Maps to MITRE T1190", dashboard_style))
    
    story.append(Paragraph("Step 4: Highlight the LLM Analysis", step_style))
    story.append(Paragraph(
        "\"Notice the 'LLM Reasoning Process' panel. It's not just logging the attack; it's explaining "
        "WHY it's an attack: 'Detected SQL metacharacters', 'Analyzing intent', and 'Recommended response'.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 5: Show the response", step_style))
    story.append(Paragraph(
        "\"The honeypot returns fake database results to keep the attacker engaged. "
        "Notice it looks realistic - fake usernames, emails, passwords.\"",
        body_style
    ))
    
    story.append(Spacer(1, 0.15*inch))
    
    # ==================== ATTACK 2: XSS ====================
    story.append(Paragraph("ATTACK 2: CROSS-SITE SCRIPTING (XSS)", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is a reflected XSS attack. The attacker injects JavaScript that would execute in the victim's browser. "
        "In a real application, this could steal cookies or hijack sessions.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type changes to 'XSS'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 2", dashboard_style))
    story.append(Paragraph("✓ Behavioral analysis: Attacker using multiple vectors", dashboard_style))
    story.append(Paragraph("✓ Skill level may upgrade to INTERMEDIATE", dashboard_style))
    
    story.append(Paragraph("Step 4: Show attack sequence", step_style))
    story.append(Paragraph(
        "\"Notice the timeline now shows: SQL Injection → XSS. "
        "The system is tracking the attack progression and building an attacker profile.\"",
        body_style
    ))
    
    story.append(Spacer(1, 0.15*inch))
    
    # ==================== ATTACK 3: PATH TRAVERSAL ====================
    story.append(Paragraph("ATTACK 3: PATH TRAVERSAL", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=../../etc/passwd</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is a path traversal attack trying to access /etc/passwd. "
        "The ../ sequences attempt to navigate up the directory tree to read sensitive files.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type: 'PATH_TRAVERSAL'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 3", dashboard_style))
    story.append(Paragraph("✓ Attack stage may escalate to PRIVILEGE_ESCALATION", dashboard_style))
    story.append(Paragraph("✓ Threat level increases (MEDIUM → HIGH)", dashboard_style))
    
    story.append(Paragraph("Step 4: Show the fake response", step_style))
    story.append(Paragraph(
        "\"The honeypot returns a realistic-looking /etc/passwd file with fake user accounts. "
        "This keeps the attacker engaged while we study their techniques.\"",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== ATTACK 4: COMMAND INJECTION ====================
    story.append(Paragraph("ATTACK 4: COMMAND INJECTION", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=test;ls -la</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is OS command injection. The semicolon terminates the intended command and executes 'ls -la' "
        "to list directory contents. This could lead to full system compromise.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type: 'CMD_INJECTION'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 4", dashboard_style))
    story.append(Paragraph("✓ MITRE technique: T1059 (Command and Scripting Interpreter)", dashboard_style))
    story.append(Paragraph("✓ Threat level: HIGH (attacker attempting system access)", dashboard_style))
    
    story.append(Paragraph("Step 4: Show AI prediction update", step_style))
    story.append(Paragraph(
        "\"After 4 attacks, our ML model has learned this attacker's pattern. "
        "It now predicts they'll likely attempt data exfiltration or admin access next.\"",
        body_style
    ))
    
    story.append(Spacer(1, 0.15*inch))
    
    # ==================== ATTACK 5: SSRF ====================
    story.append(Paragraph("ATTACK 5: SERVER-SIDE REQUEST FORGERY (SSRF)", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=http://localhost/admin</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is SSRF - the attacker tries to make our server request internal resources. "
        "They're targeting http://localhost/admin to access internal admin panels.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type: 'SSRF'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 5", dashboard_style))
    story.append(Paragraph("✓ Attack stage: PRIVILEGE_ESCALATION", dashboard_style))
    story.append(Paragraph("✓ Skill level may upgrade to ADVANCED", dashboard_style))
    
    story.append(Paragraph("Step 4: Highlight the sophistication", step_style))
    story.append(Paragraph(
        "\"SSRF is a more advanced attack. The system recognizes this and upgrades the attacker's skill level. "
        "This affects our threat assessment and response strategy.\"",
        body_style
    ))
    
    story.append(Spacer(1, 0.15*inch))
    
    # ==================== ATTACK 6: AUTH BYPASS ====================
    story.append(Paragraph("ATTACK 6: AUTHENTICATION BYPASS", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/admin?user=admin&pass=admin:admin</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This is a credential stuffing attack using default credentials admin:admin. "
        "Attackers often try common username/password combinations.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type: 'Authentication Bypass'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 6", dashboard_style))
    story.append(Paragraph("✓ Endpoint: /admin (high-value target)", dashboard_style))
    story.append(Paragraph("✓ MITRE technique: T1078 (Valid Accounts)", dashboard_style))
    story.append(Paragraph("✓ Threat level: HIGH or CRITICAL", dashboard_style))
    
    story.append(Paragraph("Step 4: Show the complete attack chain", step_style))
    story.append(Paragraph(
        "\"Look at the timeline: SQL Injection → XSS → Path Traversal → Command Injection → SSRF → Auth Bypass. "
        "This is a sophisticated multi-stage attack. Our system has mapped it to MITRE ATT&CK tactics.\"",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== ATTACK 7: DESERIALIZATION ====================
    story.append(Paragraph("ATTACK 7: INSECURE DESERIALIZATION", attack_style))
    
    story.append(Paragraph("Step 1: Execute the attack", step_style))
    story.append(Paragraph(
        "<font name='Courier' size=8>http://localhost:8000/search?q=__reduce__</font>",
        url_style
    ))
    
    story.append(Paragraph("Step 2: What to say to judges", step_style))
    story.append(Paragraph(
        "\"This targets Python's pickle deserialization. The __reduce__ method can execute arbitrary code "
        "during unpickling, leading to remote code execution.\"",
        body_style
    ))
    
    story.append(Paragraph("Step 3: Point out dashboard changes", step_style))
    story.append(Paragraph("✓ Attack type: 'Insecure Deserialization'", dashboard_style))
    story.append(Paragraph("✓ Attack counter: 7", dashboard_style))
    story.append(Paragraph("✓ All 7 OWASP attack types demonstrated!", dashboard_style))
    story.append(Paragraph("✓ Threat level: CRITICAL (RCE attempt)", dashboard_style))
    
    story.append(Paragraph("Step 4: Show the complete picture", step_style))
    story.append(Paragraph(
        "\"We've now demonstrated all 7 OWASP vulnerabilities our honeypot detects. "
        "The dashboard shows the complete attack timeline, MITRE mapping, threat level, and AI predictions.\"",
        body_style
    ))
    
    story.append(Spacer(1, 0.2*inch))
    
    # ==================== ADVANCED FEATURES DEMO ====================
    story.append(Paragraph("PART 2: POST-EXPLOITATION ANALYSIS (USING ATTACKER ID)", section_style))
    story.append(Paragraph(
        "By this point, we have successfully tracked the attacker's unique ID across the session. "
        "Now we use this ID to generate deep forensic insights:",
        body_style
    ))
    
    story.append(Paragraph("Feature 1: AI Prediction (Probabilistic Modeling)", attack_style))
    story.append(Paragraph("Click Button: <b>🤖 AI Prediction</b>", step_style))
    story.append(Paragraph(
        "\"Using the captured Attacker ID, our Markov chain model analyzes their specific sequence. "
        "It predicts the next likely attack vector (e.g., 'Admin Access') with calculated probability.\"",
        body_style
    ))
    
    story.append(Paragraph("Feature 2: MITRE ATT&CK Matrix", attack_style))
    story.append(Paragraph("Click Button: <b>🎯 MITRE Mapping</b>", step_style))
    story.append(Paragraph(
        "\"We map this specific attacker's actions to the MITRE ATT&CK framework. "
        "You can see the Tactics (e.g., Initial Access) and Techniques (e.g., T1190) used in this session.\"",
        body_style
    ))
    
    story.append(Paragraph("Feature 3: Forensic Timeline", attack_style))
    story.append(Paragraph("Click Button: <b>📅 Forensic Timeline</b>", step_style))
    story.append(Paragraph(
        "\"This generates a complete chronological timeline for this Attacker ID. "
        "Every payload, timestamp, and response is logged for forensic reconstruction.\"",
        body_style
    ))
    
    story.append(Paragraph("Feature 4: Incident Playbook Generation", attack_style))
    story.append(Paragraph("Click Button: <b>📖 Incident Playbook</b>", step_style))
    story.append(Paragraph(
        "\"Based on the dominant attack type (e.g., SQL Injection), the system auto-generates "
        "an actionable incident response playbook with detection rules and containment steps.\"",
        body_style
    ))
    
    story.append(Paragraph("Feature 5: STIX 2.1 Threat Intel Export", attack_style))
    story.append(Paragraph("Click Button: <b>🔗 STIX Export</b>", step_style))
    story.append(Paragraph(
        "\"We package all intelligence about this Attacker ID into a standardized STIX 2.1 JSON bundle. "
        "This is ready for immediate sharing with other SOCs or import into a SIEM.\"",
        body_style
    ))
    
    story.append(Paragraph("Feature 6: Canary Token Analytics", attack_style))
    story.append(Paragraph("Click Button: <b>🕯️ Canary Analytics</b>", step_style))
    story.append(Paragraph(
        "\"If the attacker accessed our honeytokens (fake credentials/files), this dashboard shows "
        "exactly where and how those tokens were used, revealing their post-compromise movement.\"",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== CLOSING DEMO ====================
    story.append(Paragraph("CLOSING THE DEMO", section_style))
    
    story.append(Paragraph("Summary Points", attack_style))
    story.append(Paragraph(
        "\"Let me summarize what we just demonstrated:\"",
        body_style
    ))
    story.append(Paragraph(
        "1. <b>Real-time detection</b> of 7 OWASP attack types with instant dashboard updates",
        body_style
    ))
    story.append(Paragraph(
        "2. <b>AI-powered prediction</b> using Markov chains to forecast next attacks",
        body_style
    ))
    story.append(Paragraph(
        "3. <b>Automatic MITRE mapping</b> to industry-standard ATT&CK framework",
        body_style
    ))
    story.append(Paragraph(
        "4. <b>Forensic timeline</b> with complete attack reconstruction",
        body_style
    ))
    story.append(Paragraph(
        "5. <b>Auto-generated playbooks</b> for instant incident response",
        body_style
    ))
    story.append(Paragraph(
        "6. <b>STIX 2.1 export</b> for threat intelligence sharing",
        body_style
    ))
    story.append(Paragraph(
        "7. <b>Production-ready security</b> with rate limiting, signed cookies, and resource protection",
        body_style
    ))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Key Differentiators", attack_style))
    story.append(Paragraph(
        "\"What makes this different from traditional honeypots:\"",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Proactive vs Reactive:</b> We predict attacks, not just log them",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Automated Intelligence:</b> MITRE mapping and playbooks happen automatically",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Real-time Analytics:</b> Sub-second dashboard updates via WebSockets",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Production Ready:</b> Enterprise-grade security with all vulnerabilities fixed",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Integration Ready:</b> STIX export, API access, SIEM compatibility",
        body_style
    ))
    
    story.append(Spacer(1, 0.2*inch))
    
    # ==================== TROUBLESHOOTING ====================
    story.append(Paragraph("TROUBLESHOOTING", section_style))
    
    story.append(Paragraph("Dashboard not updating?", attack_style))
    story.append(Paragraph("• Refresh the browser (F5)", body_style))
    story.append(Paragraph("• Check WebSocket connection in browser console", body_style))
    story.append(Paragraph("• Restart the server: Ctrl+C, then python app.py", body_style))
    
    story.append(Paragraph("Attack not detected?", attack_style))
    story.append(Paragraph("• Verify the URL is correct (copy-paste from this PDF)", body_style))
    story.append(Paragraph("• Check server console for errors", body_style))
    story.append(Paragraph("• Ensure special characters are properly encoded", body_style))
    
    story.append(Paragraph("Server crashed?", attack_style))
    story.append(Paragraph("• Don't panic! Restart with: python app.py", body_style))
    story.append(Paragraph("• Previous attacks are logged in attacks.json", body_style))
    story.append(Paragraph("• Continue demo from where you left off", body_style))
    
    story.append(Spacer(1, 0.2*inch))
    
    # ==================== QUICK REFERENCE ====================
    story.append(Paragraph("QUICK REFERENCE - ALL ATTACK URLS", section_style))
    
    attack_urls = [
        ['Attack Type', 'URL'],
        ['SQL Injection', "http://localhost:8000/search?q=' OR 1=1--"],
        ['XSS', "http://localhost:8000/search?q=<script>alert('XSS')</script>"],
        ['Path Traversal', "http://localhost:8000/search?q=../../etc/passwd"],
        ['Command Injection', "http://localhost:8000/search?q=test;ls -la"],
        ['SSRF', "http://localhost:8000/search?q=http://localhost/admin"],
        ['Auth Bypass', "http://localhost:8000/admin?user=admin&pass=admin:admin"],
        ['Deserialization', "http://localhost:8000/search?q=__reduce__"],
    ]
    
    url_table = Table(attack_urls, colWidths=[1.5*inch, 4.5*inch])
    url_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ECF0F1')]),
    ]))
    story.append(url_table)
    
    story.append(Spacer(1, 0.2*inch))
    
    # Footer
    story.append(Paragraph(
        "<b>Pro Tip:</b> Keep this PDF open during your demo. Copy-paste URLs directly to avoid typos!",
        ParagraphStyle('Footer', parent=body_style, fontSize=10, textColor=colors.HexColor('#E74C3C'), 
                      alignment=TA_CENTER, leftIndent=0)
    ))
    
    # Build PDF
    doc.build(story)
    return filename

if __name__ == "__main__":
    filename = create_live_demo_pdf()
    print(f"PDF created successfully: {filename}")
    print(f"Location: {filename}")
    print("Live attack demonstration guide ready!")
