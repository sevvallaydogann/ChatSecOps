"""
ChatSecOps_Analytics.py
Raporlama, Grafik Oluşturma ve PDF Çıktı Modülü
"""
import os
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime

# Sunucuda grafik hatası almamak için
plt.switch_backend('Agg')

class PDFReport(FPDF):
    def header(self):
        self.set_fill_color(30, 60, 114) # Kurumsal Lacivert
        self.rect(0, 0, 210, 20, 'F')
        self.set_font('Arial', 'B', 16)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, 'ChatSecOps - Threat Intelligence Report', 0, 1, 'C')
        self.ln(10)

def generate_charts(domain, risk_score, vt_stats):
    """Matplotlib ile analiz grafikleri oluşturur"""
    charts = {}
    
    # Klasör kontrolü
    if not os.path.exists("static/charts"):
        os.makedirs("static/charts", exist_ok=True)

    # 1. VirusTotal Pasta Grafiği
    try:
        malicious = vt_stats.get('malicious', 0)
        harmless = vt_stats.get('harmless', 0) + vt_stats.get('undetected', 0)
        
        # Eğer veri yoksa boş grafik basmayalım
        if malicious + harmless > 0:
            fig, ax = plt.subplots(figsize=(5, 4))
            colors = ['#ff4d4d', '#4dff4d']
            labels = ['Malicious', 'Clean']
            
            sizes = [malicious, harmless] if malicious > 0 else [0, 100]
            
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
            ax.set_title(f"VirusTotal Consensus")
            
            fn_vt = f"static/charts/vt_{domain.replace('.', '_')}.png"
            plt.savefig(fn_vt, bbox_inches='tight')
            plt.close(fig)
            charts['vt'] = fn_vt
    except Exception as e:
        print(f"Grafik Hatası (VT): {e}")

    # 2. Risk Skoru Barı
    try:
        fig, ax = plt.subplots(figsize=(8, 2))
        risk_color = 'red' if risk_score > 50 else 'green'
        
        ax.barh(['Risk Score'], [risk_score], color=risk_color, height=0.5)
        ax.set_xlim(0, 100)
        ax.axvline(x=50, color='gray', linestyle='--') # Eşik değeri çizgisi
        ax.set_title(f"ML Model Confidence: {risk_score:.2f}%")
        
        fn_risk = f"static/charts/risk_{domain.replace('.', '_')}.png"
        plt.tight_layout()
        plt.savefig(fn_risk)
        plt.close(fig)
        charts['risk'] = fn_risk
    except Exception as e:
        print(f"Grafik Hatası (Risk): {e}")
    
    return charts

def create_pdf_report(domain, ai_summary, risk_score, vt_stats):
    """Analiz sonuçlarını PDF'e basar"""
    
    # Grafikleri oluştur
    charts = generate_charts(domain, risk_score, vt_stats)
    
    pdf = PDFReport()
    pdf.add_page()
    
    # Türkçe karakter sorunu için basit temizleme
    def clean(t): 
        return t.encode('latin-1', 'replace').decode('latin-1')
    
    # --- Rapor İçeriği ---
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(0,0,0)
    pdf.cell(0, 10, f"Target Asset: {domain}", 0, 1)
    
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.cell(0, 8, f"AI Risk Score: {risk_score:.2f}%", 0, 1)
    pdf.ln(5)
    
    # Grafikleri Yerleştir
    y = pdf.get_y()
    if 'vt' in charts: 
        pdf.image(charts['vt'], x=10, y=y, w=80)
    if 'risk' in charts: 
        pdf.image(charts['risk'], x=100, y=y+10, w=90)
    
    pdf.ln(80) # Resimler için boşluk bırak
    
    # AI Özeti
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Executive Summary (AI Generated):", 0, 1)
    
    pdf.set_font("Arial", '', 10)
    # Markdown yıldızlarını temizle
    clean_summary = ai_summary.replace('**', '').replace('__', '')
    pdf.multi_cell(0, 6, clean(clean_summary))
    
    # Klasör kontrolü
    if not os.path.exists("static/reports"):
        os.makedirs("static/reports", exist_ok=True)
        
    filename = f"static/reports/report_{domain.replace('.', '_')}.pdf"
    pdf.output(filename)
    
    return filename