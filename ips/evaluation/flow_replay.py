import pandas as pd
import xgboost as xgb
import time
from sklearn.metrics import confusion_matrix

FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "packets_per_sec",
    "bytes_per_sec"
]

MODEL_PATH = "../cicids2017_ips_network_only.json"
DATASET_PATH = "evaluation_dataset.csv"

THRESHOLD = 0.5


def main():
    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURES]
    y_true = df["label"]

    print("[+] Loading model...")
    model = xgb.Booster()
    model.load_model(MODEL_PATH)

    dmatrix = xgb.DMatrix(X, feature_names=FEATURES)

    print("[+] Starting simulated live replay...")

    start_time = time.time()

    y_scores = model.predict(dmatrix)
    y_pred = (y_scores > THRESHOLD).astype(int)

    end_time = time.time()

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    total_flows = len(df)
    total_time = end_time - start_time
    avg_latency = total_time / total_flows

    print("\n==== FLOW REPLAY RESULTS ====")
    print("Total Flows:", total_flows)
    print("True Positives:", tp)
    print("False Positives:", fp)
    print("True Negatives:", tn)
    print("False Negatives:", fn)
    print("Detection Rate:", tp / (tp + fn))
    print("False Positive Rate:", fp / (fp + tn))
    print("Average Prediction Time per Flow (s):", avg_latency)
    print("===============================")


if __name__ == "__main__":
    main()
