# Network Telemetry Analyzer (LAN)

A lightweight client-server based network telemetry system that captures TCP traffic data from clients, sends it to a central server, stores it in MongoDB, and visualizes it using a dashboard.

---

## 📌 Overview

This project consists of three main components:

1. **Client** – Captures network packets and sends telemetry data
2. **Server** – Receives, processes, and stores data
3. **Analyzer/Dashboard** – Visualizes the collected data

The system works in a LAN environment and helps monitor TCP-level activity such as sequence numbers, flags, and packet flow.

---

## 🧠 How It Works (Architecture)

```
[ CLIENT ]  --->  [ SERVER ]  --->  [ DATABASE ]  --->  [ DASHBOARD ]
 Packet Capture     TCP Socket       MongoDB           Streamlit UI
```

### Step-by-step flow:

1. Client captures packets using raw sockets / packet sniffing
2. Extracts:

   * Source IP
   * Destination IP
   * Sequence number
   * Flags (SYN, ACK, FIN, etc.)
3. Sends this data to the server using TCP
4. Server receives and parses the data
5. Stores it in MongoDB
6. Dashboard fetches data from MongoDB
7. Displays graphs and logs

---

## 📁 Folder Structure

```
Network-Analyzer/
│
├── client/
│   ├── client.py              # Captures and sends packet data
│
├── server/
│   ├── tcp_server.py          # Receives client data
│   ├── db.py                  # MongoDB connection setup
│
├── local_analyzer/
│   ├── dashboard.py           # Streamlit dashboard
│
├── .env                       # Environment variables (Mongo URI)
├── requirements.txt           # Dependencies
└── README.md                  # This file
```

---

## ⚙️ Requirements

### Software:

* Python 3.10+
* MongoDB (local or Atlas)

### Python Libraries:

* pymongo
* socket
* streamlit
* python-dotenv

---

## 📦 Installation

### 1. Clone the repository

```
git clone <your-repo-url>
cd Network-Analyzer
```

### 2. Create virtual environment (recommended)

```
python -m venv venv
venv\Scripts\activate   # Windows
```

### 3. Install dependencies

```
pip install -r requirements.txt
```

---

## 🔐 Environment Setup

Create a `.env` file in the **root folder**:

```
MONGO_URI=mongodb://localhost:27017/
DB_NAME=network_data
COLLECTION_NAME=packets
```

> If using MongoDB Atlas, replace the URI accordingly.

---

## 🚀 Running the Project

### Step 1: Start MongoDB

Make sure MongoDB is running locally or accessible.

---

### Step 2: Run Server

```
cd server
python tcp_server.py
```

✔ Server will:

* Listen for incoming client connections
* Store incoming data in MongoDB

---

### Step 3: Run Client

```
cd client
python client.py
```

✔ Client will:

* Capture TCP packets
* Send structured data to server IP

⚠️ IMPORTANT:
Update server IP in `client.py`:

```
SERVER_IP = "YOUR_SERVER_IP"
```

Use:

```
ipconfig   # Windows
```

---

### Step 4: Run Dashboard

```
cd local_analyzer
streamlit run dashboard.py
```

✔ Opens browser:

```
http://localhost:8501
```

---

## 📊 Features

* Real-time packet monitoring
* TCP flag analysis (SYN, ACK, FIN)
* Sequence number tracking
* MongoDB-based storage
* Interactive dashboard using Streamlit

---

## 🧪 Example Data Format

```
{
  "src_ip": "192.168.1.5",
  "dst_ip": "192.168.1.10",
  "seq": 12345,
  "flags": "SYN"
}
```

---

## ⚠️ Common Issues

### 1. MongoDB Connection Error

* Check `.env` file
* Ensure MongoDB is running
* Verify URI format

---

### 2. Client Not Connecting

* Ensure server IP is correct
* Check firewall settings
* Both systems must be on same LAN

---

### 3. Dashboard Not Showing Data

* Verify database name and collection
* Check if server is inserting data
* Restart Streamlit

---

## 🛠️ Commands Summary

```
# Setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Run server
cd server
python tcp_server.py

# Run client
cd client
python client.py

# Run dashboard
cd local_analyzer
streamlit run dashboard.py
```

---

## 🔮 Future Improvements

* Add UDP packet analysis
* Real-time streaming using WebSockets
* Alert system for suspicious traffic
* Authentication layer

---

## 👨‍💻 Author

Developed as part of a Computer Networks mini project.

---

## 📜 License

This project is for educational purposes.
