import threading
import time


class Metrics:

    def __init__(self):
        self.total_flows = 0
        self.total_predictions = 0
        self.total_attacks = 0
        self.total_blocks = 0
        self.prediction_times = []

        self.lock = threading.Lock()

    def increment_flows(self):
        with self.lock:
            self.total_flows += 1

    def record_prediction(self, prediction_time, is_attack):
        with self.lock:
            self.total_predictions += 1
            self.prediction_times.append(prediction_time)

            if is_attack:
                self.total_attacks += 1

    def increment_blocks(self):
        with self.lock:
            self.total_blocks += 1

    def report(self):
        with self.lock:
            avg_time = (
                sum(self.prediction_times) / len(self.prediction_times)
                if self.prediction_times
                else 0
            )

            print("\n==== IPS METRICS REPORT ====")
            print("Total Flows:", self.total_flows)
            print("Total Predictions:", self.total_predictions)
            print("Total Attacks:", self.total_attacks)
            print("Total Blocks:", self.total_blocks)
            print("Avg Prediction Time (s):", round(avg_time, 6))
            print("============================")
