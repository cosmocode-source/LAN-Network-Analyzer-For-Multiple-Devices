import socket
import threading
import json
from datetime import datetime
from pymongo import MongoClient
import logging
from config import *

# ── Logging ─────────────────────────────────────────────
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ── MongoDB ─────────────────────────────────────────────
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION]

connected_clients = set()
completed_clients = set()

def handle_client(conn, addr):
    ip = addr[0]
    connected_clients.add(ip)

    try:
        data = conn.recv(4096).decode()

        # ignore empty connections (handshake/duration steps)
        if not data:
            return

        payload = json.loads(data)

        record = {
            "device_ip": ip,
            "device_name": f"Device-{ip.replace('.', '_')}",

            "server_name": payload.get("server_name", "LocalServer"),

            "latency_ms": payload.get("latency_ms"),
            "tcp_handshake_ms": payload.get("tcp_handshake_ms"),
            "throughput_Mbps": payload.get("throughput_Mbps"),
            "download_time_sec": payload.get("download_time_sec"),
            "transfer_variance": payload.get("transfer_variance"),
            "connection_duration_sec": payload.get("connection_duration_sec"),

            # ✅ NEW FIELD
            "file_size_MB": payload.get("file_size_MB"),

            "timestamp": datetime.now()
        }

        collection.insert_one(record)
        completed_clients.add(ip)

        logging.info(f"{ip} stored successfully")

    except Exception as e:
        logging.error(f"{ip} error: {e}")

    finally:
        conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, TCP_PORT))
    server.listen(10)

    print(f"Server running on {HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    start_server()