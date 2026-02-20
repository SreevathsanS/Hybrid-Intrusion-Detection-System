# ==========================================
# RESEARCH-GRADE MULTI-CLASS EVALUATION
# ==========================================

import os
import json
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

# ==========================================
# EXACT TRAINING FEATURES (MATCH KAGGLE)
# ==========================================

FEATURES = [
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

MODEL_PATH = "../ips_multiclass_enhanced_model.json"
ENCODER_PATH = "../ips_label_enhanced_encoder.pkl"
DATASET_PATH = "evaluation_dataset.csv"

RESULT_DIR = "evaluation_results"
os.makedirs(RESULT_DIR, exist_ok=True)


def evaluate():

    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()

    # --------------------------------------
    # Validate Features
    # --------------------------------------
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    X = df[FEATURES]
    y_true_raw = df["Label"] if "Label" in df.columns else df["label"]

    print("[+] Loading encoder...")
    encoder = joblib.load(ENCODER_PATH)

    y_true = encoder.transform(y_true_raw)

    print("[+] Loading trained model...")
    model = xgb.Booster()
    model.load_model(MODEL_PATH)

    dmatrix = xgb.DMatrix(X, feature_names=FEATURES)

    print("[+] Running multi-class prediction...")
    y_scores = model.predict(dmatrix)

    y_pred = np.argmax(y_scores, axis=1)

    # ======================================
    # METRICS
    # ======================================

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average="weighted")
    recall = recall_score(y_true, y_pred, average="weighted")
    f1 = f1_score(y_true, y_pred, average="weighted")

    print("\n========== MODEL PERFORMANCE ==========")
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")

    # --------------------------------------
    # Classification Report
    # --------------------------------------

    report = classification_report(
        y_true,
        y_pred,
        target_names=encoder.classes_
    )

    print("\n=== Classification Report ===\n")
    print(report)

    with open(os.path.join(RESULT_DIR, "classification_report.txt"), "w") as f:
        f.write(report)

    # --------------------------------------
    # Confusion Matrix
    # --------------------------------------

    cm = confusion_matrix(y_true, y_pred)

    cm_df = pd.DataFrame(
        cm,
        index=encoder.classes_,
        columns=encoder.classes_
    )

    print("\n=== Confusion Matrix ===\n")
    print(cm_df)

    cm_df.to_csv(os.path.join(RESULT_DIR, "confusion_matrix.csv"))

    # --------------------------------------
    # Plot Confusion Matrix
    # --------------------------------------

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm_df, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix - Multi-Class XGBoost IPS")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()

    plt.savefig(os.path.join(RESULT_DIR, "confusion_matrix.png"))
    plt.close()

    # --------------------------------------
    # Save Metrics
    # --------------------------------------

    metrics = {
        "Accuracy": float(accuracy),
        "Precision_weighted": float(precision),
        "Recall_weighted": float(recall),
        "F1_weighted": float(f1)
    }

    with open(os.path.join(RESULT_DIR, "metrics_summary.json"), "w") as f:
        json.dump(metrics, f, indent=4)

    print("\n✅ Evaluation completed successfully.")
    print("📂 Results saved in:", RESULT_DIR)


if __name__ == "__main__":
    evaluate()
