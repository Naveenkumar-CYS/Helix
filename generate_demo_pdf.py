"""
Live Demo Guide PDF Generator
Creates a printable PDF from the live demo script
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfgen import canvas
from datetime import datetime

def create_demo_pdf():
    """Create live demo guide PDF."""
    
    filename = "AI_Honeypot_Live_Demo_Guide.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter,
                           topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    # Container for content
    story = []
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor='#2C3E50',
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor='#E74C3C',
        spaceAfter=8,
        spaceBefore=12
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor='#3498DB',
        spaceAfter=6,
        spaceBefore=8
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=9,
        fontName='Courier',
        textColor='#27AE60',
        leftIndent=20
    )
    
    # Title
    story.append(Paragraph("AI Honeypot - Live Demo Guide", title_style))
    story.append(Paragraph("Quick Reference for Hackathon Presentation", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Pre-Demo Setup
    story.append(Paragraph("PRE-DEMO SETUP (5 minutes before)", heading_style))
    
    story.append(Paragraph("1. Start the Honeypot", subheading_style))
    story.append(Paragraph("<font name='Courier' size=9>python app.py</font>", body_style))
    story.append(Paragraph("Wait for: 'Uvicorn running on http://127.0.0.1:8000'", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    story.append(Paragraph("2. Open Dashboard", subheading_style))
    story.append(Paragraph("<font name='Courier' size=9>http://localhost:8000/demo</font>", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    story.append(Paragraph("3. Prepare Browser Tabs", subheading_style))
    story.append(Paragraph("• Tab 1: Dashboard", body_style))
    story.append(Paragraph("• Tab 2: Attack URLs", body_style))
    story.append(Paragraph("• Tab 3: DevTools (F12 → Cookies)", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Opening Pitch
    story.append(Paragraph("OPENING PITCH (30 seconds)", heading_style))
    story.append(Paragraph(
        '"We built an AI-powered honeypot that <b>predicts attacker behavior</b> using machine learning. '
        'It detects <b>7 different OWASP vulnerability types</b> - that\'s <b>70% coverage</b>. '
        'Every attack is mapped to <b>MITRE ATT&CK</b>, and we generate <b>incident response playbooks</b> instantly."',
        body_style
    ))
    story.append(Spacer(1, 0.2*inch))
    
    # Demo Steps
    story.append(Paragraph("LIVE DEMO FLOW (5-7 minutes)", heading_style))
    
    # Step 1
    story.append(Paragraph("STEP 1: Show Clean Dashboard (15 sec)", subheading_style))
    story.append(Paragraph("Point to attack counter (0 attacks) and threat level", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Step 2
    story.append(Paragraph("STEP 2: Launch SQL Injection (30 sec)", subheading_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/search?q=' OR 1=1--</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'Dashboard updates in real-time. System detected SQL Injection.'", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Step 3
    story.append(Paragraph("STEP 3: Launch XSS Attack (30 sec)", subheading_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'System tracks different attack types and builds timeline.'", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Step 4
    story.append(Paragraph("STEP 4: Escalate to Privilege Escalation (45 sec)", subheading_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/search?q=' UNION SELECT * FROM users--</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'Watch threat level climb to HIGH as AI detects escalation.'", body_style))
    
    story.append(PageBreak())
    
    # Step 5
    story.append(Paragraph("STEP 5: Show Attack Prediction (60 sec)", subheading_style))
    story.append(Paragraph("1. Get attacker_id: F12 → Application → Cookies", body_style))
    story.append(Paragraph("2. Open: <font name='Courier' size=8>http://localhost:8000/api/prediction/{ID}</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'AI predicts next attack: 60% probability of admin access. Time to compromise: 10 minutes.'", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Step 6
    story.append(Paragraph("STEP 6: Show MITRE ATT&CK Mapping (45 sec)", subheading_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/api/mitre/{ID}</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'Automatically mapped to MITRE ATT&CK. Matches APT28 tactics.'", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Step 7
    story.append(Paragraph("STEP 7: Show Auto-Generated Playbook (45 sec)", subheading_style))
    story.append(Paragraph("<font name='Courier' size=8>http://localhost:8000/api/playbook/SQL%20Injection</font>", body_style))
    story.append(Paragraph("<b>Say:</b> 'Complete incident response playbook with containment, investigation, and Sigma rules.'", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Closing
    story.append(Paragraph("CLOSING STATEMENT (30 seconds)", heading_style))
    story.append(Paragraph(
        '"To summarize: <b>Real-time detection</b> of 7 OWASP types, <b>AI prediction</b> of next attack, '
        '<b>MITRE mapping</b>, <b>auto-generated playbooks</b>, <b>100% test success</b>, and <b>production-ready</b>. '
        'This is a tool security teams can actually use. Thank you!"',
        body_style
    ))
    story.append(Spacer(1, 0.2*inch))
    
    # Quick Reference
    story.append(Paragraph("QUICK REFERENCE - ATTACK URLS", heading_style))
    story.append(Paragraph("<font name='Courier' size=8>SQL Injection: http://localhost:8000/search?q=' OR 1=1--</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>XSS: http://localhost:8000/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>Escalation: http://localhost:8000/search?q=' UNION SELECT * FROM users--</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>Path Traversal: http://localhost:8000/search?q=../../../etc/passwd</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>SSRF: http://localhost:8000/search?q=http://localhost:8080/admin</font>", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # API URLs
    story.append(Paragraph("API ENDPOINTS (Replace {ID} with attacker_id)", heading_style))
    story.append(Paragraph("<font name='Courier' size=8>Prediction: /api/prediction/{ID}</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>MITRE: /api/mitre/{ID}</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>Timeline: /api/timeline/{ID}</font>", body_style))
    story.append(Paragraph("<font name='Courier' size=8>Playbook: /api/playbook/SQL%20Injection</font>", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Key Points
    story.append(Paragraph("KEY TALKING POINTS", heading_style))
    story.append(Paragraph("• <b>7/10 OWASP Top 10</b> - 70% coverage", body_style))
    story.append(Paragraph("• <b>ML predicts next attack</b> - Unique differentiator", body_style))
    story.append(Paragraph("• <b>MITRE ATT&CK integration</b> - Industry standard", body_style))
    story.append(Paragraph("• <b>Auto-generated playbooks</b> - Saves time", body_style))
    story.append(Paragraph("• <b>100% test success</b> - Production ready", body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Q&A
    story.append(Paragraph("JUDGE Q&A - QUICK ANSWERS", heading_style))
    
    story.append(Paragraph("<b>Q: What makes this unique?</b>", subheading_style))
    story.append(Paragraph(
        '"ML-based prediction, MITRE mapping, and auto-playbooks. Traditional honeypots just log - we predict and respond."',
        body_style
    ))
    
    story.append(Paragraph("<b>Q: Is it production-ready?</b>", subheading_style))
    story.append(Paragraph(
        '"Yes. Docker deployment, 10/10 APIs tested, comprehensive logging, SIEM integration."',
        body_style
    ))
    
    story.append(Paragraph("<b>Q: How does ML work?</b>", subheading_style))
    story.append(Paragraph(
        '"Markov chains track attack sequences. After SQL injection, 60% probability of admin access next."',
        body_style
    ))
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("<b>GOOD LUCK! Remember: Speak confidently and emphasize AI prediction!</b>", 
                          ParagraphStyle('Bold', parent=body_style, fontSize=12, textColor='#E74C3C', alignment=TA_CENTER)))
    
    # Build PDF
    doc.build(story)
    
    return filename

if __name__ == "__main__":
    filename = create_demo_pdf()
    print(f"PDF created successfully: {filename}")
    print(f"Location: {filename}")
    print("Ready to print and use for your live demo!")
