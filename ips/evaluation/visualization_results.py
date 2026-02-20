import pandas as pd
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve
)

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


def main():
    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURES]
    y_true = df["label"]

    print("[+] Loading model...")
    model = xgb.Booster()
    model.load_model(MODEL_PATH)

    dmatrix = xgb.DMatrix(X, feature_names=FEATURES)

    print("[+] Predicting probabilities...")
    y_scores = model.predict(dmatrix)
    y_pred = (y_scores > 0.5).astype(int)

    # ------------------------------
    # Confusion Matrix
    # ------------------------------
    cm = confusion_matrix(y_true, y_pred)

    plt.figure()
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        xticklabels=["Normal", "Attack"],
        yticklabels=["Normal", "Attack"]
    )
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.savefig("confusion_matrix.png")
    plt.close()

    # ------------------------------
    # ROC Curve
    # ------------------------------
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.savefig("roc_curve.png")
    plt.close()

    print("AUC Score:", roc_auc)

    # ------------------------------
    # Precision-Recall Curve
    # ------------------------------
    precision, recall, _ = precision_recall_curve(y_true, y_scores)

    plt.figure()
    plt.plot(recall, precision)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve")
    plt.savefig("precision_recall_curve.png")
    plt.close()

    print("✅ All evaluation graphs generated.")


if __name__ == "__main__":
    main()
