import pandas as pd
import xgboost as xgb
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
import json


FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "packets_per_sec",
    "bytes_per_sec"
]

MODEL_PATH = "../ips_multiclass_enhanced_model.json"
DATASET_PATH = "evaluation_dataset.csv"  # prepared test dataset


def evaluate():
    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURES]
    y_true = df["label"]

    print("[+] Loading model...")
    model = xgb.Booster()
    model.load_model(MODEL_PATH)

    dmatrix = xgb.DMatrix(X, feature_names=FEATURES)

    print("[+] Running predictions...")
    y_scores = model.predict(dmatrix)
    y_pred = (y_scores > 0.5).astype(int)

    print("[+] Computing metrics...")
    cm = confusion_matrix(y_true, y_pred)
    report = classification_report(y_true, y_pred, output_dict=True)

    results = {
        "confusion_matrix": cm.tolist(),
        "classification_report": report
    }

    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred))


if __name__ == "__main__":
    evaluate()
