from pymongo import MongoClient
import pandas as pd
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)

db = client["cn_project"]
collection = db["metrics"]

def load_data():
    data = list(collection.find())

    if len(data) == 0:
        return pd.DataFrame()

    df = pd.DataFrame(data)

    if "timestamp" in df.columns:
         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    numeric_cols = [
        "latency_ms",
        "tcp_handshake_ms",
        "throughput_Mbps",
        "download_time_sec",
        "transfer_variance"
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=["latency_ms", "throughput_Mbps"])

    return df