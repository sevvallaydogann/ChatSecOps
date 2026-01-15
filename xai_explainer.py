import shap
import matplotlib.pyplot as plt
import pandas as pd
import os

# Grafik arayüzü olmayan sunucularda (backend) hata almamak için ayar
plt.switch_backend('Agg') 

def generate_shap_explanation(model, input_df, domain_name):
    """
    Verilen domain için modelin neden bu kararı verdiğini açıklayan
    bir SHAP (Waterfall) grafiği oluşturur ve kaydeder.
    """
    print(f"      [XAI] '{domain_name}' için SHAP analizi başlatılıyor...")
    
    try:
        # 1. Klasör Kontrolü (DÜZENLEME BURADA)
        # Resimleri ana dizine değil, düzenli bir klasöre atalım.
        save_dir = "static/graphs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)

        # 2. Explainer Oluştur 
        # (TreeExplainer, LightGBM gibi ağaç tabanlı modeller için en hızlısıdır)
        explainer = shap.TreeExplainer(model)
        
        # 3. SHAP Değerlerini Hesapla
        shap_values = explainer(input_df)
        
        # 4. Grafik Çizimi (Waterfall Plot)
        fig = plt.figure(figsize=(10, 6))
        
        # max_display=12 -> En etkili 12 özelliği göster
        shap.plots.waterfall(shap_values[0], max_display=12, show=False)
        
        # 5. Grafiği Kaydet
        safe_domain = "".join([c for c in domain_name if c.isalpha() or c.isdigit() or c in "_-"]).rstrip()
        filename = f"{save_dir}/shap_explanation_{safe_domain}.png"
        
        plt.tight_layout()
        plt.savefig(filename, bbox_inches='tight', dpi=100)
        
        # Belleği temizle (Sunucu şişmesin diye kritik)
        plt.close(fig)
        plt.close('all')
        
        print(f"      [XAI] Grafik başarıyla oluşturuldu: {filename}")
        return filename

    except Exception as e:
        print(f"      ❌ [XAI HATASI] Grafik oluşturulamadı: {e}")
        return None