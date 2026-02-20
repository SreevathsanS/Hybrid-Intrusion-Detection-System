import xgboost as xgb
import numpy as np
import joblib


class MLEngine:
    FEATURE_NAMES = [
        "Flow Duration",
        "Total Packets",
        "Total Bytes",
        "Packet Length Mean",
        "Packet_Size_Var",
        "Packets_per_sec",
        "Bytes_per_sec",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "SYN Flag Count",
        "RST Flag Count",
        "ACK Flag Count",
        "PSH Flag Count",
        "Flow IAT Mean",
        "Flow IAT Std"
    ]

    def __init__(self, model_path, encoder_path, confidence_threshold=0.80):
        self.model = None
        self.encoder = None
        self.confidence_threshold = confidence_threshold

        self._load_model(model_path)
        self._load_encoder(encoder_path)

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------
    def _load_model(self, model_path):
        try:
            self.model = xgb.XGBClassifier()
            self.model.load_model(model_path)
        except Exception as e:
            print("ML Engine: Model load failed:", e)
            self.model = None

    # ---------------------------------------------------------
    # Load label encoder
    # ---------------------------------------------------------
    def _load_encoder(self, encoder_path):
        try:
            self.encoder = joblib.load(encoder_path)
        except Exception as e:
            print("ML Engine: Encoder load failed:", e)
            self.encoder = None

    # ---------------------------------------------------------
    # Predict
    # ---------------------------------------------------------
    def predict(self, feature_dict):
        # print(">>> ENTERED ML PREDICT")

        if self.model is None or self.encoder is None:
            return False, None, 0.0

        try:
            feature_vector = self._prepare_features(feature_dict)

            # Use classifier directly
            probs = self.model.predict_proba(feature_vector)[0]
            class_index = int(np.argmax(probs))
            confidence = float(probs[class_index])

            label = self.encoder.inverse_transform([class_index])[0]

            # print(f"ML RAW: {label} | Confidence: {confidence:.4f}")

            if label != "BENIGN" and confidence >= self.confidence_threshold:
                return True, label, confidence

            return False, label, confidence

        except Exception as e:
            print("ML ERROR:", e)
            return False, None, 0.0


    # ---------------------------------------------------------
    # Feature alignment
    # ---------------------------------------------------------
    def _prepare_features(self, feature_dict):
        ordered = [feature_dict.get(name, 0) for name in self.FEATURE_NAMES]
        return np.array([ordered], dtype=float)
