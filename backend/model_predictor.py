import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from url_feature_extractor import URLFeatureExtractor

class ModelPredictor:
    def __init__(self, model_path="xgb_model.json", scaler_path="scaler.pkl"):
        # Load the scaler and XGBoost model
        self.scaler = joblib.load(scaler_path)
        self.booster = xgb.Booster()
        self.booster.load_model(model_path)

        # Define the expected feature columns in correct order
        self.FEATURE_COLUMNS = [
            "URLLength", "DomainLength", "TLDLength", "NoOfImage", "NoOfJS", "NoOfCSS", 
            "NoOfSelfRef", "NoOfExternalRef", "IsHTTPS", "HasObfuscation", "HasTitle", 
            "HasDescription", "HasSubmitButton", "HasSocialNet", "HasFavicon", 
            "HasCopyrightInfo", "popUpWindow", "Iframe", "Abnormal_URL", 
            "LetterToDigitRatio", "Redirect_0", "Redirect_1"
        ]

    def predict_from_url(self, url):
        try:
            # Extract features using custom extractor
            extractor = URLFeatureExtractor(url)
            features = extractor.extract_model_features()

            if "error" in features:
                return {"error": features["error"]}

            # Convert to DataFrame to align with expected column names
            input_df = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)

            # Scale
            scaled_input = self.scaler.transform(input_df)

            # Predict with DMatrix
            dmatrix = xgb.DMatrix(scaled_input, feature_names=self.FEATURE_COLUMNS)
            pred = self.booster.predict(dmatrix)
            label = int(round(pred[0]))

            return {
                "features": features,
                "prediction": label,
                "result": "Legitimate" if label == 1 else "Phishing"
            }
        except Exception as e:
            return {"error": str(e)}

    def predict_from_features(self, features):
        try:
            # Convert to DataFrame with feature names
            input_df = pd.DataFrame([features], columns=self.FEATURE_COLUMNS)

            # Scale using the original scaler
            scaled_input = self.scaler.transform(input_df)

            # Create DMatrix with feature names
            dmatrix = xgb.DMatrix(scaled_input, feature_names=self.FEATURE_COLUMNS)

            # Predict
            pred = self.booster.predict(dmatrix)
            label = int(round(pred[0]))

            return {
                "prediction": label,
                "result": "Legitimate" if label == 1 else "Phishing"
            }
        except Exception as e:
            return {"error": str(e)} 