# train_ips.py
import os
import joblib
import numpy as np
import pandas as pd
from glob import glob
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier
from feature_extractor import FEATURE_NAMES
import warnings
warnings.filterwarnings("ignore")

# -------------- CONFIG --------------
DATA_PATH = "/kaggle/input/datasets/chethuhn/network-intrusion-dataset"  # update
csv_files = glob(DATA_PATH + "/*.csv")
OUT_MODEL_JSON = "ips_multiclass_enhanced_model.json"
OUT_ENCODER = "ips_label_enhanced_encoder.pkl"
RANDOM_STATE = 42

# -------------- UTIL: transform raw dataset rows -> features --------------
def compute_features_from_row(row):
    # This function depends on how your CSV exposes forward/backward/flags.
    # For CICIDS style, there are separate columns (Total Fwd Packets, Total Bwd Packets, etc.)
    # adapt the column names if needed.
    duration = float(row.get("Flow Duration", 0)) / 1e6  # if microseconds -> seconds
    total_packets = float(row.get("Total Fwd Packets", 0) + row.get("Total Backward Packets", 0))
    total_bytes = float(row.get("Total Length of Fwd Packets", 0) + row.get("Total Length of Bwd Packets", 0))
    avg_packet_size = float(row.get("Packet Length Mean", 0))
    packet_length_var = float(row.get("Packet Length Std", 0))**2 if "Packet Length Std" in row else 0.0
    packets_per_sec = total_packets / max(duration, 1e-9)
    bytes_per_sec = total_bytes / max(duration, 1e-9)

    fwd_packet_count = float(row.get("Total Fwd Packets", 0))
    bwd_packet_count = float(row.get("Total Backward Packets", 0))
    fwd_byte_count = float(row.get("Total Length of Fwd Packets", 0))
    bwd_byte_count = float(row.get("Total Length of Bwd Packets", 0))

    syn_count = float(row.get("SYN Flag Count", 0))
    rst_count = float(row.get("RST Flag Count", 0))
    ack_count = float(row.get("ACK Flag Count", 0))
    psh_count = float(row.get("PSH Flag Count", 0))
    fin_count = float(row.get("FIN Flag Count", 0)) if "FIN Flag Count" in row else 0.0

    flow_iat_mean = float(row.get("Flow IAT Mean", 0))
    flow_iat_std = float(row.get("Flow IAT Std", 0)) if "Flow IAT Std" in row else 0.0

    feat = [
        duration,
        total_packets,
        total_bytes,
        avg_packet_size,
        packet_length_var,
        packets_per_sec,
        bytes_per_sec,
        fwd_packet_count,
        bwd_packet_count,
        fwd_byte_count,
        bwd_byte_count,
        syn_count,
        rst_count,
        ack_count,
        psh_count,
        fin_count,
        flow_iat_mean,
        flow_iat_std
    ]
    return feat

# -------------- LOAD + PREPARE --------------
print("Loading CSVs...")
df = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)
df.columns = df.columns.str.strip()
print("Original shape:", df.shape)

# Filter classes (same as you used earlier)
keep_classes = [
    "BENIGN",
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "SSH-Patator",
    "FTP-Patator"
]
df = df[df["Label"].isin(keep_classes)]
print("Filtered:", df["Label"].value_counts())

# Build feature matrix
features = []
labels = []
for _, row in df.iterrows():
    feats = compute_features_from_row(row)
    features.append(feats)
    labels.append(row["Label"])

X = np.array(features, dtype=float)
y = np.array(labels)

print("After Feature Engineering:", X.shape)

# Encode labels
encoder = LabelEncoder()
y_enc = encoder.fit_transform(y)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.25, random_state=RANDOM_STATE, stratify=y_enc
)

# -------------- MODEL --------------
print("Training model on GPU (if available)...")
model = XGBClassifier(
    objective="multi:softprob",
    num_class=len(encoder.classes_),
    n_estimators=500,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    tree_method="gpu_hist",   # GPU version
    predictor="gpu_predictor",
    eval_metric="mlogloss",
    random_state=RANDOM_STATE,
    use_label_encoder=False
)

model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=1)

# -------------- EVAL --------------
y_pred = model.predict(X_test)
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))
print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

# -------------- SAVE --------------
# Save booster JSON + encoder
booster = model.get_booster()
booster.save_model(OUT_MODEL_JSON)
joblib.dump(encoder, OUT_ENCODER)

print("\nSaved model JSON:", OUT_MODEL_JSON)
print("Saved label encoder:", OUT_ENCODER)
