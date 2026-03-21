import asyncio
import ssl
import json
import struct
from datetime import datetime
from pymongo import MongoClient
import logging
from concurrent.futures import ThreadPoolExecutor

from config import *

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- LOGGING SETUP ----------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
)

file_handler = logging.FileHandler("server.log")
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


# ---------------- DATABASE ----------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION]

# ✅ IMPROVEMENT: thread pool for non-blocking DB writes
executor = ThreadPoolExecutor(max_workers=10)

# ✅ IMPROVEMENT: limit concurrent clients (prevents overload)
semaphore = asyncio.Semaphore(50)

# ✅ IMPROVEMENT: payload size limit (DoS protection)
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# ✅ IMPROVEMENT: timeout for reads (prevents hanging connections)
READ_TIMEOUT = 5


# ---------------- LOAD KEYS ----------------
with open("server_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("server_cert.pem", "rb") as f:
    cert_data = f.read()


# ---------------- SAFE ASYNC READ ----------------
async def read_exact(reader, n):
    """
    Read exactly n bytes safely (handles TCP fragmentation).
    """
    data = b""
    while len(data) < n:
        chunk = await asyncio.wait_for(reader.read(n - len(data)), timeout=READ_TIMEOUT)
        if not chunk:
            raise ConnectionError("Connection closed early")
        data += chunk
    return data


# ---------------- ASYNC DB WRITE ----------------
async def insert_record(record):
    """
    Run MongoDB insert in thread pool (non-blocking for asyncio loop).
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(executor, collection.insert_one, record)


# ---------------- CLIENT HANDLER ----------------
async def handle_client(reader, writer):
    async with semaphore:
        addr = writer.get_extra_info('peername')

        try:
            logger.info(f"[CONNECTED] {addr}")

            # -------- PING HANDLER --------
            try:
                peek = await asyncio.wait_for(reader.read(4), timeout=1)

                if peek == b"PING":
                    writer.write(b"PONG")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    logger.info(f"[PING] Responded to {addr}")
                    return

                # If not PING → continue normal flow

            except asyncio.TimeoutError:
                pass  # No data → continue normal protocol

            # ---------- TLS INFO ----------
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                logger.info(f"[TLS] Version={ssl_obj.version()} Cipher={ssl_obj.cipher()}")

            # ---------- STEP 1: SEND CERT ----------
            writer.write(struct.pack("I", len(cert_data)))
            writer.write(cert_data)
            await writer.drain()

            # ---------- STEP 2: RECEIVE SESSION KEY ----------
            key_len = struct.unpack("I", await read_exact(reader, 4))[0]

            # ✅ VALIDATE SIZE
            if key_len > MAX_PAYLOAD_SIZE:
                raise ValueError("Session key too large")

            enc_session_key = await read_exact(reader, key_len)

            session_key = private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.info("Session key decrypted")

            # ---------- STEP 3: RECEIVE ENCRYPTED DATA ----------
            nonce_len = struct.unpack("I", await read_exact(reader, 4))[0]

            if nonce_len > 1024:
                raise ValueError("Nonce too large")

            nonce = await read_exact(reader, nonce_len)

            cipher_len = struct.unpack("I", await read_exact(reader, 4))[0]

            # ✅ VALIDATE PAYLOAD SIZE
            if cipher_len > MAX_PAYLOAD_SIZE:
                raise ValueError("Payload too large")

            ciphertext = await read_exact(reader, cipher_len)

            # ---------- STEP 4: DECRYPT ----------
            aesgcm = AESGCM(session_key)
            data = aesgcm.decrypt(nonce, ciphertext, None)

            # ---------- SAFE JSON PARSE ----------
            try:
                payload = json.loads(data.decode())
            except Exception:
                raise ValueError("Invalid JSON payload")

            # ---------- DEVICE IDENTIFICATION ----------
            device_ip = addr[0]
            client_name = payload.get("server_name", "Unknown")
            device_name = f"{client_name}_{device_ip}"

            # ---------- CREATE RECORD ----------
            record = {
                "device_name": device_name,
                "device_ip": device_ip,
                "server_name": client_name,

                "latency_ms": payload.get("latency_ms"),
                "tcp_handshake_ms": payload.get("tcp_handshake_ms"),
                "throughput_Mbps": payload.get("throughput_Mbps"),
                "download_time_sec": payload.get("download_time_sec"),
                "connection_duration_sec": payload.get("connection_duration_sec"),
                "file_size_MB": payload.get("file_size_MB"),

                "timestamp": datetime.now()
            }

            # ✅ NON-BLOCKING INSERT
            await insert_record(record)

            logger.info(f"Data stored for {device_name}")

        except asyncio.TimeoutError:
            logger.error(f"[TIMEOUT] {addr}")

        except Exception as e:
            logger.error(f"[ERROR] {addr} → {e}")

        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Connection closed: {addr}")


# ---------------- MAIN SERVER ----------------
async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("server_cert.pem", "server_key.pem")

    server = await asyncio.start_server(
        handle_client,
        HOST,
        TCP_PORT,
        ssl=ssl_context
    )

    logger.info(f"Server running on {HOST}:{TCP_PORT}")

    async with server:
        await server.serve_forever()


# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    asyncio.run(main())