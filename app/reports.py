from io import BytesIO
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from xml.sax.saxutils import escape

def create_pdf(rows):
    buffer=BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=(595,842))
    styles=getSampleStyleSheet()
    story=[Paragraph('CyberGuard URL Risk Report',styles['Title']),Spacer(1,12),Paragraph('Scores are model estimates, not proof of maliciousness or safety.',styles['BodyText']),Spacer(1,16)]
    cells=[['URL (truncated)','Score','Risk band']]
    for row in rows[:500]:
        cells.append([Paragraph(escape(str(row['url'])[:75]),styles['BodyText']),str(row['risk_score']),str(row['risk_band'])])
    table=Table(cells,colWidths=[360,75,90],repeatRows=1,hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dae8f5')),('GRID',(0,0),(-1,-1),.3,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
    story.append(table);doc.build(story)
    return buffer.getvalue()
