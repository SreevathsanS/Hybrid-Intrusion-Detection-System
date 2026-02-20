import pandas as pd
import xgboost as xgb
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_score, recall_score, accuracy_score


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

THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7]


def main():
    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURES]
    y_true = df["label"]

    print("[+] Loading model...")
    model = xgb.Booster()
    model.load_model(MODEL_PATH)

    dmatrix = xgb.DMatrix(X, feature_names=FEATURES)

    print("[+] Getting probability scores...")
    y_scores = model.predict(dmatrix)

    results = []

    for threshold in THRESHOLDS:
        y_pred = (y_scores > threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        accuracy = accuracy_score(y_true, y_pred)

        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)

        results.append([
            threshold,
            accuracy,
            precision,
            recall,
            fpr,
            fnr
        ])

        print(f"\nThreshold: {threshold}")
        print(f"Accuracy : {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall   : {recall:.4f}")
        print(f"FPR      : {fpr:.4f}")
        print(f"FNR      : {fnr:.4f}")

    # Save results to CSV
    results_df = pd.DataFrame(
        results,
        columns=["Threshold", "Accuracy", "Precision", "Recall", "FPR", "FNR"]
    )

    results_df.to_csv("threshold_results.csv", index=False)
    print("\n✅ Threshold results saved to threshold_results.csv")

    # -------------------------
    # Plotting
    # -------------------------
    plt.figure()
    plt.plot(results_df["Threshold"], results_df["Precision"], label="Precision")
    plt.plot(results_df["Threshold"], results_df["Recall"], label="Recall")
    plt.plot(results_df["Threshold"], results_df["FPR"], label="FPR")
    plt.plot(results_df["Threshold"], results_df["FNR"], label="FNR")

    plt.xlabel("Threshold")
    plt.ylabel("Metric Value")
    plt.title("Threshold Sensitivity Analysis")
    plt.legend()
    plt.savefig("threshold_sensitivity.png")
    plt.close()

    print("✅ Threshold sensitivity graph saved as threshold_sensitivity.png")


if __name__ == "__main__":
    main()
