"""
xai_explainer.py - FIXED VERSION
ModelExplainer sınıfı eklendi
"""
import shap
import matplotlib.pyplot as plt
import pandas as pd
import os
import joblib

# Grafik arayüzü olmayan sunucularda hata almamak için
plt.switch_backend('Agg') 


class ModelExplainer:
    """
    SHAP-based Model Explainer
    Explains LightGBM model predictions using SHAP values
    """
    
    def __init__(self, model_path: str):
        """
        Initialize explainer with trained model
        
        Args:
            model_path: Path to the trained model (.joblib)
        """
        try:
            self.model = joblib.load(model_path)
            self.explainer = shap.TreeExplainer(self.model)
            print(f"      [XAI] Model loaded from {model_path}")
        except Exception as e:
            print(f"      [XAI ERROR] Failed to load model: {e}")
            self.model = None
            self.explainer = None
    
    def generate_explanation(self, input_df: pd.DataFrame) -> dict:
        """
        Generate SHAP explanation for a single prediction
        
        Args:
            input_df: DataFrame with model features (single row)
        
        Returns:
            dict with top positive and negative features
        """
        if self.explainer is None:
            return {"error": "Explainer not initialized"}
        
        try:
            # Calculate SHAP values
            shap_values = self.explainer(input_df)
            
            # Get SHAP values for the first (and only) sample
            sample_shap = shap_values[0]
            
            # Extract feature names and values
            feature_names = input_df.columns.tolist()
            shap_vals = sample_shap.values
            
            # Create feature-value pairs
            feature_impacts = [
                {"feature": name, "shap_value": float(val)}
                for name, val in zip(feature_names, shap_vals)
            ]
            
            # Sort by absolute impact
            feature_impacts.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            
            # Separate positive and negative
            positive_features = [f for f in feature_impacts if f["shap_value"] > 0][:5]
            negative_features = [f for f in feature_impacts if f["shap_value"] < 0][:5]
            
            return {
                "top_5_positive_features": positive_features,
                "top_5_negative_features": negative_features,
                "base_value": float(sample_shap.base_values),
                "prediction": float(sample_shap.base_values + shap_vals.sum())
            }
        
        except Exception as e:
            print(f"      [XAI ERROR] Explanation failed: {e}")
            return {"error": str(e)}
    
    def generate_shap_waterfall(self, input_df: pd.DataFrame, domain_name: str) -> str:
        """
        Generate SHAP waterfall chart and save as image
        
        Args:
            input_df: DataFrame with model features
            domain_name: Domain name for filename
        
        Returns:
            Path to saved image, or None if failed
        """
        if self.explainer is None:
            print("      [XAI] Explainer not initialized")
            return None
        
        try:
            # Create directory
            save_dir = "static/graphs"
            if not os.path.exists(save_dir):
                os.makedirs(save_dir, exist_ok=True)
            
            # Calculate SHAP values
            shap_values = self.explainer(input_df)
            
            # Create waterfall plot
            fig = plt.figure(figsize=(10, 6))
            shap.plots.waterfall(shap_values[0], max_display=12, show=False)
            
            # Save
            safe_domain = "".join([c for c in domain_name if c.isalpha() or c.isdigit() or c in "_-"]).rstrip()
            filename = f"{save_dir}/shap_explanation_{safe_domain}.png"
            
            plt.tight_layout()
            plt.savefig(filename, bbox_inches='tight', dpi=100)
            
            # Clean up
            plt.close(fig)
            plt.close('all')
            
            print(f"      [XAI] Waterfall chart saved: {filename}")
            return filename
        
        except Exception as e:
            print(f"      [XAI ERROR] Waterfall chart failed: {e}")
            return None


# Backward compatibility: keep the old function
def generate_shap_explanation(model, input_df, domain_name):
    """
    Legacy function - kept for backward compatibility
    Use ModelExplainer class instead
    """
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer(input_df)
        
        save_dir = "static/graphs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)
        
        fig = plt.figure(figsize=(10, 6))
        shap.plots.waterfall(shap_values[0], max_display=12, show=False)
        
        safe_domain = "".join([c for c in domain_name if c.isalpha() or c.isdigit() or c in "_-"]).rstrip()
        filename = f"{save_dir}/shap_explanation_{safe_domain}.png"
        
        plt.tight_layout()
        plt.savefig(filename, bbox_inches='tight', dpi=100)
        plt.close(fig)
        plt.close('all')
        
        print(f"      [XAI] Grafik başarıyla oluşturuldu: {filename}")
        return filename
    
    except Exception as e:
        print(f"      ❌ [XAI HATASI] Grafik oluşturulamadı: {e}")
        return None