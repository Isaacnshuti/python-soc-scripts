from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor

doc = SimpleDocTemplate("CyberSec_Lab_Report.pdf", pagesize=letter)
styles = getSampleStyleSheet()
doc.build([Paragraph("Test", styles["Normal"])])
print("Success")
