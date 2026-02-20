import pickle
import pandas as pd
import joblib
import os
import numpy as np

print("Loading model assets...")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============================
# Load multi-class model assets
# ============================
model = joblib.load(os.path.join(BASE_DIR, "models/xgb_multiclass_model.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "models/scaler.pkl"))

src_ip_encoder = joblib.load(os.path.join(BASE_DIR, "models/src_ip_encoder.pkl"))
dst_ip_encoder = joblib.load(os.path.join(BASE_DIR, "models/dst_ip_encoder.pkl"))

feature_columns = joblib.load(os.path.join(BASE_DIR, "models/feature_columns.pkl"))

# ============================
# Label Mapping (LOCKED)
# ============================
LABEL_MAP = {
    0: "Normal",
    1: "DoS",
    2: "SSH_BruteForce"
}

# ============================
# Core Prediction Function
# ============================
def predict_intrusion(raw_df: pd.DataFrame):
    """
    raw_df: DataFrame with raw input features (1 row)
    Returns: attack_type, confidence
    """

    df = raw_df.copy()

    # ============================
    # Encode IP addresses
    # ============================
    if "src_ip" in df.columns:
        df["src_ip"] = src_ip_encoder.transform(df["src_ip"])
    if "dst_ip" in df.columns:
        df["dst_ip"] = dst_ip_encoder.transform(df["dst_ip"])

    # ============================
    # Align feature space
    # ============================
    df = df.reindex(columns=feature_columns, fill_value=0)

    # ============================
    # Scale features
    # ============================
    scaled = scaler.transform(df)

    # ============================
    # Multi-class prediction
    # ============================
    probs = model.predict_proba(scaled)[0]
    print(probs)

    pred_class = int(np.argmax(probs))
    confidence = float(np.max(probs))

    label = LABEL_MAP.get(pred_class, "Unknown")

    return label, round(confidence, 3)


# ============================
# Wrapper for Real-Time IDS
# ============================
def predict_attack(feature_df: pd.DataFrame):
    """
    Wrapper for real-time IDS
    Returns: label, confidence
    """
    return predict_intrusion(feature_df)