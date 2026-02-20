# train_and_save.py

from xgboost import XGBClassifier
import pandas as pd
import numpy as np

# Example loading (replace with your dataset logic)
df = pd.read_csv("your_processed_cicids.csv")

FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "packets_per_sec",
    "bytes_per_sec"
]

X = df[FEATURES].values
y = df["label"].values

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric='logloss'
)

model.fit(X, y)

# SAVE AS JSON (CRITICAL)
model.get_booster().save_model("cicids2017_ips_network_only.json")

print("Model saved successfully as JSON.")
