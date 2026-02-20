import xgboost as xgb
import pickle

model = pickle.load(open("models/model.pkl", "rb"))
model.save_model("models/model.json")
