import re
from typing import Union

import joblib
import pandas as pd
import numpy as np

# SHAP kütüphanesi için import - yüklü değilse açık bir hata mesajı verir
try:
    import shap  # noqa: F401
except ImportError as e:
    raise ImportError(
        "❌ [HATA] 'shap' kütüphanesi yüklü değil. "
        "Lütfen şu komutu çalıştırın: pip install shap"
    ) from e


class ModelExplainer:
    """
    LightGBM modeli için SHAP değerlerini hesaplayan ve açıklama üreten sınıf.
    """
    
    def __init__(self, model_path='lgbm_domain_classifier.joblib'):
        """
        ModelExplainer'ı başlatır ve LightGBM modelini yükler.
        
        Args:
            model_path (str): LightGBM model dosyasının yolu
        """
        try:
            self.model = joblib.load(model_path)
            print(f"✅ [BAŞARILI] LightGBM modeli '{model_path}' dosyasından yüklendi.")
        except FileNotFoundError:
            raise FileNotFoundError(f"❌ [HATA] Model dosyası bulunamadı: '{model_path}'")
        except Exception as e:
            raise Exception(f"❌ [HATA] Model yüklenirken hata oluştu: {e}")
        
        # SHAP TreeExplainer'ı oluştur
        try:
            self.explainer = shap.TreeExplainer(self.model)
            print("✅ [BAŞARILI] SHAP TreeExplainer oluşturuldu.")
        except Exception as e:
            raise Exception(f"❌ [HATA] SHAP TreeExplainer oluşturulurken hata: {e}")
    
    @staticmethod
    def _ensure_dataframe(X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        """Girdi veri yapısını DataFrame olacak şekilde garanti eder."""
        if isinstance(X, pd.DataFrame):
            return X.copy()
        return pd.DataFrame(X)

    @staticmethod
    def _clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
        """
        Sütun adlarını main.py'deki ile aynı regex kullanarak temizler.
        (Yalnızca A-Z, a-z, 0-9 ve alt çizgi karakterlerine izin verilir.)
        """
        cleaned_columns = [
            re.sub(r"[^A-Za-z0-9_]+", "", str(col))
            for col in df.columns
        ]
        df.columns = cleaned_columns
        return df

    def generate_explanation(self, X):
        """
        Verilen veri için SHAP değerlerini hesaplar ve en etkili 5 pozitif 
        ve 5 negatif özelliği listeler.
        
        Args:
            X (pd.DataFrame veya np.ndarray): Açıklanacak veri örneği(leri)
            
        Returns:
            dict: SHAP değerleri ve özellik sıralaması içeren sözlük
        """
        try:
            # X'in DataFrame olduğundan emin ol ve sütun adlarını temizle
            X = self._ensure_dataframe(X)
            X = self._clean_column_names(X)
            
            # SHAP değerlerini hesapla
            shap_values = self.explainer.shap_values(X)
            
            # Binary classification için shap_values bir liste olabilir
            # Eğer liste ise, pozitif sınıf (1) için olanları al
            if isinstance(shap_values, list):
                shap_values = shap_values[1]  # Pozitif sınıf için

            shap_values_array = np.array(shap_values)
            
            # Tek bir örnek için ortalama SHAP değerlerini hesapla
            if len(shap_values_array.shape) > 1:
                mean_shap_values = np.mean(np.abs(shap_values_array), axis=0)
                # İşaret koruyarak ortalama hesapla
                signed_mean_shap = np.mean(shap_values_array, axis=0)
            else:
                mean_shap_values = np.abs(shap_values_array)
                signed_mean_shap = shap_values_array
            
            # Özellik isimlerini al
            if isinstance(X, pd.DataFrame):
                feature_names = X.columns.tolist()
            else:
                feature_names = [f'feature_{i}' for i in range(len(mean_shap_values))]
            
            # Özellikler ve SHAP değerlerini birleştir
            feature_shap_pairs = list(zip(feature_names, signed_mean_shap, mean_shap_values))
            
            # Pozitif ve negatif SHAP değerlerine göre ayır
            positive_features = [(name, shap_val, abs_val) for name, shap_val, abs_val 
                                in feature_shap_pairs if shap_val > 0]
            negative_features = [(name, shap_val, abs_val) for name, shap_val, abs_val 
                                in feature_shap_pairs if shap_val < 0]
            
            # Mutlak değere göre sırala (en etkili olanlar üstte)
            positive_features.sort(key=lambda x: x[2], reverse=True)
            negative_features.sort(key=lambda x: x[2], reverse=True)
            
            # En etkili 5 pozitif ve 5 negatif özelliği al
            top_5_positive = positive_features[:5]
            top_5_negative = negative_features[:5]
            
            # Sonuçları formatla
            result = {
                'shap_values': shap_values_array.tolist(),
                'top_5_positive_features': [
                    {
                        'feature': feat[0],
                        'shap_value': float(feat[1]),
                        'abs_shap_value': float(feat[2])
                    }
                    for feat in top_5_positive
                ],
                'top_5_negative_features': [
                    {
                        'feature': feat[0],
                        'shap_value': float(feat[1]),
                        'abs_shap_value': float(feat[2])
                    }
                    for feat in top_5_negative
                ]
            }
            
            return result
            
        except Exception as e:
            raise Exception(f"❌ [HATA] SHAP değerleri hesaplanırken hata: {e}")
    
    def print_explanation(self, explanation_result):
        """
        Açıklama sonuçlarını güzel bir formatta yazdırır.
        
        Args:
            explanation_result (dict): generate_explanation metodunun döndürdüğü sonuç
        """
        print("\n" + "="*70)
        print("SHAP DEĞER ANALİZİ - EN ETKİLİ ÖZELLİKLER")
        print("="*70)
        
        print("\n🔺 EN ETKİLİ 5 POZİTİF ÖZELLİK (Zararlı Olma İhtimalini Artıran):")
        print("-" * 70)
        for i, feat in enumerate(explanation_result['top_5_positive_features'], 1):
            print(f"{i}. {feat['feature']:40s} SHAP: {feat['shap_value']:>10.6f} (|{feat['abs_shap_value']:.6f}|)")
        
        print("\n🔻 EN ETKİLİ 5 NEGATİF ÖZELLİK (Zararsız Olma İhtimalini Artıran):")
        print("-" * 70)
        for i, feat in enumerate(explanation_result['top_5_negative_features'], 1):
            print(f"{i}. {feat['feature']:40s} SHAP: {feat['shap_value']:>10.6f} (|{feat['abs_shap_value']:.6f}|)")
        
        print("\n" + "="*70 + "\n")


# Örnek kullanım
if __name__ == "__main__":
    # ModelExplainer'ı oluştur
    try:
        explainer = ModelExplainer('lgbm_domain_classifier.joblib')
        
        # Örnek: Test için rastgele bir veri oluştur
        # Gerçek kullanımda burada modele girecek veriyi hazırlamanız gerekir
        print("\n💡 Not: Gerçek kullanım için modele uygun formatta veri hazırlayın.")
        print("   Örnek: explanation = explainer.generate_explanation(X_test.iloc[0:1])")
        print("         explainer.print_explanation(explanation)")
        
    except Exception as e:
        print(f"❌ Hata: {e}")

