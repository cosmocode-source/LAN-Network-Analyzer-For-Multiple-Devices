import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("HOST")
TCP_PORT = int(os.getenv("TCP_PORT"))
HTTP_PORT = int(os.getenv("HTTP_PORT"))
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION = os.getenv("COLLECTION")