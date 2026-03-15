"""
PDF Generator for User Guide
Converts USER_GUIDE.md to a professional PDF for judges
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import re

def create_pdf():
    # Read the markdown file
    with open('USER_GUIDE.md', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create PDF
    pdf_filename = 'AI_Honeypot_User_Guide.pdf'
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter,
                           rightMargin=0.75*inch, leftMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    heading3_style = ParagraphStyle(
        'CustomHeading3',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=9,
        textColor=colors.HexColor('#c7254e'),
        backColor=colors.HexColor('#f9f2f4'),
        fontName='Courier',
        leftIndent=20,
        rightIndent=20,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=6,
        leading=14
    )
    
    # Add title
    elements.append(Paragraph("🛡️ AI Honeypot", title_style))
    elements.append(Paragraph("User Guide", title_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Process content
    lines = content.split('\n')
    in_code_block = False
    code_buffer = []
    
    for line in lines:
        # Skip the first title (already added)
        if line.startswith('# 🛡️ AI Honeypot'):
            continue
            
        # Handle code blocks
        if line.startswith('```'):
            if in_code_block:
                # End of code block
                if code_buffer:
                    code_text = '<br/>'.join(code_buffer)
                    elements.append(Paragraph(code_text, code_style))
                    elements.append(Spacer(1, 0.1*inch))
                code_buffer = []
                in_code_block = False
            else:
                # Start of code block
                in_code_block = True
            continue
        
        if in_code_block:
            code_buffer.append(line.replace('<', '&lt;').replace('>', '&gt;'))
            continue
        
        # Handle headings
        if line.startswith('## '):
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(line[3:], heading1_style))
        elif line.startswith('### '):
            elements.append(Paragraph(line[4:], heading2_style))
        elif line.startswith('#### '):
            elements.append(Paragraph(line[5:], heading3_style))
        
        # Handle horizontal rules
        elif line.strip() == '---':
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Table([['']], colWidths=[6.5*inch], 
                                 style=[('LINEABOVE', (0,0), (-1,-1), 1, colors.grey)]))
            elements.append(Spacer(1, 0.1*inch))
        
        # Handle bold text and regular paragraphs
        elif line.strip():
            # Convert markdown bold to HTML
            line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
            # Convert inline code
            line = re.sub(r'`(.*?)`', r'<font face="Courier" color="#c7254e">\1</font>', line)
            # Convert links (simplified)
            line = re.sub(r'\[(.*?)\]\((.*?)\)', r'<u>\1</u>', line)
            
            if line.strip().startswith('- ') or line.strip().startswith('* '):
                # Bullet point
                text = line.strip()[2:]
                elements.append(Paragraph(f"• {text}", body_style))
            elif line.strip().startswith('**') and line.strip().endswith('**'):
                # Bold paragraph
                text = line.strip()[2:-2]
                elements.append(Paragraph(f"<b>{text}</b>", body_style))
            else:
                # Regular paragraph
                elements.append(Paragraph(line, body_style))
        else:
            # Empty line
            elements.append(Spacer(1, 0.05*inch))
    
    # Build PDF
    doc.build(elements)
    print(f"PDF created successfully: {pdf_filename}")
    print(f"Location: {pdf_filename}")
    print("Ready to print and distribute to judges!")

if __name__ == '__main__':
    create_pdf()
