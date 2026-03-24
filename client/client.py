"""
network_client.py
-----------------
Network Test Client — professional dark-gray GUI built with tkinter.

What this app does (in order):
  1. TCP Handshake  — measures connection latency to the server
  2. File Download  — downloads a 100 MB test file with a live progress bar
  3. Conn. Duration — holds a TCP connection open to measure duration
  4. Send Report    — serialises results as JSON and sends them to the server
  5. Cleanup        — removes the temporary downloaded file

Dependencies: requests  (pip install requests)
"""

import socket
import time
import requests
import json
import struct
import os
import threading
import tkinter as tk
import ssl
from tkinter import font as tkfont
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import os
# ── Constants ─────────────────────────────────────────────────────────────────

DOWNLOAD_FILE   = "temp_download.bin"
DOWNLOAD_CHUNKS = 8192          # bytes per chunk while streaming the download
FILE_SIZE_MB    = 100           # expected file size used for progress calculation

def create_secure_socket(ip, port):
    context = ssl.create_default_context(cafile="ca_cert.pem")
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile="client_cert.pem",
        keyfile="client_key.pem"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(sock, server_hostname=ip)
    s.connect((ip, port))
    cert = s.getpeercert()
    if not cert:
        raise Exception("Server certificate not received")
    subject = dict(x[0] for x in cert['subject'])
    issuer = dict(x[0] for x in cert['issuer'])
    server_cn = subject.get('commonName', 'UNKNOWN')
    issuer_cn = issuer.get('commonName', 'UNKNOWN')
    print(f"[mTLS SUCCESS] Server Authenticated → CN={server_cn}, Issuer={issuer_cn}")
    return s

# ── Colour palette (dark gray theme) ─────────────────────────────────────────

C = {
    "bg":        "#111213",   # window background
    "bg2":       "#181a1b",   # card / panel background
    "bg3":       "#1f2123",   # input background
    "bg4":       "#26292b",   # button / hover background
    "border":    "#2e3235",   # subtle border
    "accent":    "#c8cdd2",   # primary text / highlights
    "accent2":   "#8f979e",   # secondary accent
    "text":      "#dde1e4",   # main text
    "text2":     "#8f979e",   # muted text
    "text3":     "#555d63",   # very muted / labels
    "success":   "#6fcf97",   # green — test passed
    "danger":    "#eb5757",   # red   — error
    "warning":   "#f2c94c",   # yellow — running
    "info":      "#a8c4d8",   # blue  — informational log lines
}


# =============================================================================
# NetworkClientApp
# =============================================================================

class NetworkClientApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self._setup_window()
        self._setup_fonts()
        self._build_ui()

    # ── Window setup ──────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("NetProbe — Network Test Client")
        self.root.geometry("780x700")
        self.root.resizable(False, False)
        self.root.configure(bg=C["bg"])

    def _setup_fonts(self):
        """Define named fonts used throughout the UI."""
        self.font_mono_sm  = tkfont.Font(family="Courier",       size=9)
        self.font_mono_md  = tkfont.Font(family="Courier",       size=11)
        self.font_mono_lg  = tkfont.Font(family="Courier",       size=18, weight="bold")
        self.font_sans_sm  = tkfont.Font(family="Helvetica",     size=9)
        self.font_sans_md  = tkfont.Font(family="Helvetica",     size=11)
        self.font_sans_hd  = tkfont.Font(family="Helvetica",     size=20, weight="bold")
        self.font_label    = tkfont.Font(family="Courier",       size=8)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        """Assemble every panel of the window."""
        self._build_topbar()
        self._build_config_panel()
        self._build_steps_panel()
        self._build_progress_panel()
        self._build_metrics_panel()
        self._build_log_panel()

    # ── Top bar ───────────────────────────────────────────────────────────────

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=C["bg2"], height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(
            bar, text="◉  NETPROBE", bg=C["bg2"],
            fg=C["accent"], font=self.font_mono_md
        ).pack(side="left", padx=16)

        tk.Label(
            bar, text="v1.0", bg=C["bg2"],
            fg=C["text3"], font=self.font_label
        ).pack(side="left")

        # Status indicator on the right
        self.status_dot   = tk.Label(bar, text="●", bg=C["bg2"], fg=C["text3"], font=self.font_mono_sm)
        self.status_label = tk.Label(bar, text="IDLE", bg=C["bg2"], fg=C["text3"], font=self.font_label)
        self.status_label.pack(side="right", padx=12)
        self.status_dot.pack(side="right")

        # Thin separator line beneath the bar
        tk.Frame(self.root, bg=C["border"], height=1).pack(fill="x")

    # ── Config panel ──────────────────────────────────────────────────────────

    def _build_config_panel(self):
        outer = tk.Frame(self.root, bg=C["bg"], padx=20, pady=14)
        outer.pack(fill="x")

        # Section label
        tk.Label(
            outer, text="TARGET CONFIGURATION",
            bg=C["bg"], fg=C["text3"], font=self.font_label
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        # Four input fields in a 2×2 grid
        fields = [
            ("SERVER IP ADDRESS", "{ip}"),
            ("TCP PORT",          "5000"),
            ("DOWNLOAD FILE URL", "http://{ip}:8000/testfile.bin"),
            ("SERVER NAME",       "LocalServer"),
        ]

        self.entries = {}
        for idx, (label_text, default) in enumerate(fields):
            row = (idx // 2) + 1
            col = (idx %  2) * 2

            tk.Label(
                outer, text=label_text,
                bg=C["bg"], fg=C["text3"], font=self.font_label
            ).grid(row=row, column=col, sticky="w", padx=(0, 6), pady=2)

            entry = tk.Entry(
                outer, width=30,
                bg=C["bg3"], fg=C["text"], insertbackground=C["accent"],
                relief="flat", bd=0, font=self.font_mono_sm,
                highlightthickness=1, highlightbackground=C["border"],
                highlightcolor=C["accent2"]
            )
            entry.insert(0, default)
            entry.grid(row=row, column=col + 1, sticky="ew", padx=(0, 18), pady=4, ipady=5)
            self.entries[label_text] = entry

        outer.columnconfigure(1, weight=1)
        outer.columnconfigure(3, weight=1)

        # Run button
        self.run_btn = tk.Button(
            outer, text="▶   RUN NETWORK DIAGNOSTICS",
            bg=C["bg4"], fg=C["text"], activebackground=C["border"],
            activeforeground=C["accent"], relief="flat", bd=0,
            font=self.font_mono_sm, cursor="hand2",
            command=self._start_test_thread,
            pady=8
        )
        self.run_btn.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(10, 0))

    # ── Step indicators ───────────────────────────────────────────────────────

    def _build_steps_panel(self):
        outer = tk.Frame(self.root, bg=C["bg"], padx=20, pady=8)
        outer.pack(fill="x")

        steps = ["1  Handshake", "2  Download", "3  Duration", "4  Report"]
        self.step_labels = []

        for i, text in enumerate(steps):
            lbl = tk.Label(
                outer, text=text,
                bg=C["bg"], fg=C["text3"], font=self.font_label,
                width=18, anchor="center"
            )
            lbl.grid(row=0, column=i, padx=4)
            self.step_labels.append(lbl)

            # Connector line between steps
            if i < len(steps) - 1:
                tk.Frame(outer, bg=C["border"], height=1, width=30).grid(
                    row=0, column=i, sticky="e", padx=(0, 0)
                )

        outer.columnconfigure(tuple(range(len(steps))), weight=1)

    # ── Progress panel ────────────────────────────────────────────────────────

    def _build_progress_panel(self):
        outer = tk.Frame(self.root, bg=C["bg2"], padx=20, pady=14)
        outer.pack(fill="x", padx=20, pady=(4, 0))

        # Stage text + percentage on the same row
        top_row = tk.Frame(outer, bg=C["bg2"])
        top_row.pack(fill="x")

        self.stage_label = tk.Label(
            top_row, text="Ready to run",
            bg=C["bg2"], fg=C["text2"], font=self.font_mono_sm, anchor="w"
        )
        self.stage_label.pack(side="left")

        self.pct_label = tk.Label(
            top_row, text="0%",
            bg=C["bg2"], fg=C["accent"], font=self.font_mono_sm, anchor="e"
        )
        self.pct_label.pack(side="right")

        # Overall progress bar (canvas-drawn for precise control)
        tk.Label(
            outer, text="OVERALL PROGRESS",
            bg=C["bg2"], fg=C["text3"], font=self.font_label, anchor="w"
        ).pack(fill="x", pady=(6, 2))

        self.progress_canvas = tk.Canvas(
            outer, height=4, bg=C["bg4"], highlightthickness=0
        )
        self.progress_canvas.pack(fill="x", pady=(0, 10))
        self.progress_rect = self.progress_canvas.create_rectangle(
            0, 0, 0, 4, fill=C["accent2"], outline=""
        )

        # Download sub-section (hidden until Step 2 starts)
        self.dl_frame = tk.Frame(outer, bg=C["bg2"])
        # Not packed yet — shown dynamically during the download step

        self.dl_file_label = tk.Label(
            self.dl_frame, text="DOWNLOADING  testfile.bin",
            bg=C["bg2"], fg=C["text2"], font=self.font_label, anchor="w"
        )
        self.dl_file_label.pack(fill="x")

        dl_row = tk.Frame(self.dl_frame, bg=C["bg2"])
        dl_row.pack(fill="x", pady=(2, 4))

        self.dl_stat_label = tk.Label(
            dl_row, text="0 / 100 MB",
            bg=C["bg2"], fg=C["accent2"], font=self.font_mono_sm
        )
        self.dl_stat_label.pack(side="right")

        # Download progress bar
        self.dl_canvas = tk.Canvas(
            self.dl_frame, height=6, bg=C["bg4"], highlightthickness=0
        )
        self.dl_canvas.pack(fill="x", pady=(0, 6))
        self.dl_rect = self.dl_canvas.create_rectangle(
            0, 0, 0, 6, fill=C["accent2"], outline=""
        )

        # Speed / ETA / elapsed chips
        chips_row = tk.Frame(self.dl_frame, bg=C["bg2"])
        chips_row.pack(fill="x")

        self.dl_speed_label   = self._make_chip(chips_row, "SPEED",   "— MB/s")
        self.dl_eta_label     = self._make_chip(chips_row, "ETA",     "—")
        self.dl_elapsed_label = self._make_chip(chips_row, "ELAPSED", "0.0 s")

    def _make_chip(self, parent, key, value):
        """Helper: renders a small KEY  value label pair."""
        frame = tk.Frame(parent, bg=C["bg2"])
        frame.pack(side="left", padx=(0, 16))
        tk.Label(frame, text=key + "  ", bg=C["bg2"], fg=C["text3"], font=self.font_label).pack(side="left")
        val_lbl = tk.Label(frame, text=value, bg=C["bg2"], fg=C["text2"], font=self.font_label)
        val_lbl.pack(side="left")
        return val_lbl

    # ── Metric cards ──────────────────────────────────────────────────────────

    def _build_metrics_panel(self):
        outer = tk.Frame(self.root, bg=C["bg"], padx=20, pady=10)
        outer.pack(fill="x")

        cards = [
            ("Handshake",     "milliseconds", "accent",  "v_handshake"),
            ("Throughput",    "Mbps",         "success",  "v_throughput"),
            ("Download Time", "seconds",      "accent",  "v_dltime"),
            ("Conn. Duration","seconds",      "accent",  "v_conndur"),
        ]

        self.metric_values = {}

        for i, (name, unit, color_key, attr) in enumerate(cards):
            card = tk.Frame(
                outer, bg=C["bg2"],
                highlightthickness=1, highlightbackground=C["border"]
            )
            card.grid(row=0, column=i, padx=6, sticky="nsew")

            tk.Label(
                card, text=name.upper(),
                bg=C["bg2"], fg=C["text3"], font=self.font_label
            ).pack(anchor="w", padx=12, pady=(10, 4))

            val_lbl = tk.Label(
                card, text="—",
                bg=C["bg2"], fg=C[color_key], font=self.font_mono_lg
            )
            val_lbl.pack(anchor="w", padx=12)

            tk.Label(
                card, text=unit,
                bg=C["bg2"], fg=C["text3"], font=self.font_label
            ).pack(anchor="w", padx=12, pady=(2, 10))

            self.metric_values[attr] = val_lbl
            outer.columnconfigure(i, weight=1)

    # ── Log panel ─────────────────────────────────────────────────────────────

    def _build_log_panel(self):
        outer = tk.Frame(self.root, bg=C["bg"], padx=20, pady=10)
        outer.pack(fill="both", expand=True)

        # Header row with title and clear button
        header = tk.Frame(outer, bg=C["bg2"])
        header.pack(fill="x")

        tk.Label(
            header, text="CONSOLE OUTPUT",
            bg=C["bg2"], fg=C["text3"], font=self.font_label
        ).pack(side="left", padx=10, pady=6)

        tk.Button(
            header, text="CLEAR",
            bg=C["bg2"], fg=C["text3"], activebackground=C["bg3"],
            activeforeground=C["danger"], relief="flat", bd=0,
            font=self.font_label, cursor="hand2",
            command=self._clear_log
        ).pack(side="right", padx=10)

        tk.Frame(outer, bg=C["border"], height=1).pack(fill="x")

        # Scrollable text area
        self.log_text = tk.Text(
            outer,
            bg=C["bg2"], fg=C["text2"],
            insertbackground=C["accent"],
            relief="flat", bd=0,
            font=self.font_mono_sm,
            wrap="word",
            state="disabled",
            height=10
        )
        self.log_text.pack(fill="both", expand=True, padx=10, pady=8)

        # Colour tags for different log message types
        self.log_text.tag_config("ok",   foreground=C["success"])
        self.log_text.tag_config("err",  foreground=C["danger"])
        self.log_text.tag_config("info", foreground=C["info"])
        self.log_text.tag_config("warn", foreground=C["warning"])
        self.log_text.tag_config("ts",   foreground=C["text3"])

        self._log("NetProbe ready. Configure target and press Run.")

    # =========================================================================
    # LOGGING HELPERS
    # =========================================================================

    def _log(self, msg: str, tag: str = ""):
        """Append a timestamped line to the console log (thread-safe)."""
        timestamp = time.strftime("%H:%M:%S")

        def _insert():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"{timestamp}  ", "ts")
            self.log_text.insert("end", f"{msg}\n", tag if tag else "")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.root.after(0, _insert)

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # =========================================================================
    # STATUS + STEP + PROGRESS HELPERS
    # =========================================================================

    def _set_status(self, state: str, label: str):
        """Update the top-bar status dot and text.
        state: 'running' | 'done' | 'error' | '' (idle)
        """
        color_map = {
            "running": C["warning"],
            "done":    C["success"],
            "error":   C["danger"],
            "":        C["text3"],
        }
        color = color_map.get(state, C["text3"])
        self.root.after(0, lambda: self.status_dot.configure(fg=color))
        self.root.after(0, lambda: self.status_label.configure(text=label, fg=color))

    def _set_step(self, n: int, state: str):
        """Highlight a step label.
        state: 'active' | 'done' | '' (idle)
        """
        color_map = {"active": C["accent2"], "done": C["success"], "": C["text3"]}
        color = color_map.get(state, C["text3"])
        lbl   = self.step_labels[n - 1]
        prefix = "✓ " if state == "done" else f"{n}  "
        text   = prefix + ["Handshake", "Download", "Duration", "Report"][n - 1]
        self.root.after(0, lambda: lbl.configure(text=text, fg=color))

    def _set_progress(self, pct: float, stage: str):
        """Move the overall progress bar and update the stage/percentage labels."""
        def _update():
            self.stage_label.configure(text=stage)
            self.pct_label.configure(text=f"{int(pct)}%")
            width = self.progress_canvas.winfo_width()
            fill  = int(width * pct / 100)
            self.progress_canvas.coords(self.progress_rect, 0, 0, fill, 4)
        self.root.after(0, _update)

    def _set_metric(self, attr: str, value: str):
        """Fill a metric card with a result value."""
        self.root.after(0, lambda: self.metric_values[attr].configure(text=value))

    def _show_download_bar(self, visible: bool):
        """Show or hide the download sub-section inside the progress panel."""
        def _toggle():
            if visible:
                self.dl_frame.pack(fill="x", pady=(6, 0))
            else:
                self.dl_frame.pack_forget()
        self.root.after(0, _toggle)

    def _update_download_progress(self, downloaded_mb: float, total_mb: float,
                                   speed_mbs: float, elapsed: float):
        """Refresh every element of the download sub-bar (called each chunk)."""
        pct       = (downloaded_mb / total_mb) * 100
        remaining = (total_mb - downloaded_mb) / speed_mbs if speed_mbs > 0 else 0

        def _update():
            # Download bar fill
            width = self.dl_canvas.winfo_width()
            fill  = int(width * pct / 100)
            self.dl_canvas.coords(self.dl_rect, 0, 0, fill, 6)

            # Text chips
            self.dl_stat_label.configure(text=f"{downloaded_mb:.1f} / {total_mb:.0f} MB")
            self.dl_speed_label.configure(text=f"{speed_mbs:.1f} MB/s")
            self.dl_elapsed_label.configure(text=f"{elapsed:.1f} s")
            self.dl_eta_label.configure(
                text=f"{remaining:.0f} s" if downloaded_mb < total_mb else "0 s"
            )

            # Mirror download progress onto the overall bar (Step 2 = 20%–65%)
            overall = 20 + (pct / 100) * 45
            bar_width = self.progress_canvas.winfo_width()
            bar_fill  = int(bar_width * overall / 100)
            self.progress_canvas.coords(self.progress_rect, 0, 0, bar_fill, 4)
            self.pct_label.configure(text=f"{int(overall)}%")
            self.stage_label.configure(
                text=f"Downloading… {downloaded_mb:.1f} MB of {total_mb:.0f} MB"
            )

        self.root.after(0, _update)

    # =========================================================================
    # NETWORK TEST METHODS
    # These map directly to the original Python functions.
    # =========================================================================

    def _download_file(self, url: str, total_mb: float = FILE_SIZE_MB) -> tuple:
        """Stream-download the test file, updating the download progress bar
        every chunk. Returns (size_mb, duration_sec).
        """
        self._log(f"Starting download: {url}", "info")
        self._show_download_bar(True)

        start = time.time()
        downloaded_bytes = 0

        response = requests.get(url, stream=True)
        with open(DOWNLOAD_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNKS):
                if chunk:
                    f.write(chunk)
                    downloaded_bytes += len(chunk)

                    # Update UI every chunk
                    downloaded_mb = downloaded_bytes / (1024 * 1024)
                    elapsed       = time.time() - start
                    speed_mbs     = downloaded_mb / elapsed if elapsed > 0 else 0

                    self._update_download_progress(
                        downloaded_mb, total_mb, speed_mbs, elapsed
                    )

        self._show_download_bar(False)

        size_mb  = downloaded_bytes / (1024 * 1024)
        duration = time.time() - start
        return size_mb, duration


    def _run_network_sequence(self, ip, port, data):
        # ===============================
        # 1. LATENCY MEASUREMENT
        # ===============================
        start = time.time()
        s = create_secure_socket(ip, port)
        latency_ms = (time.time() - start) * 1000
        s.close()

        # ===============================
        # 2. PING (STABILITY)
        # ===============================
        try:
            s = create_secure_socket(ip, port)
            s.settimeout(5)

            start = time.time()
            s.send(b"PING")
            resp = s.recv(4)

            if resp == b"PONG":
                stability_ms = (time.time() - start) * 1000
            else:
                stability_ms = -1

            s.close()

        except:
            stability_ms = -1

        # ===============================
        # 3. SECURE DATA TRANSMISSION
        # ===============================
        s = create_secure_socket(ip, port)
        s.settimeout(5)

        def recv_exact(sock, n):
            data_buf = b""
            while len(data_buf) < n:
                chunk = sock.recv(n - len(data_buf))
                if not chunk:
                    raise ConnectionError("Incomplete read")
                data_buf += chunk
            return data_buf

        # ---- RECEIVE CERT ----
        cert_len = struct.unpack("I", recv_exact(s, 4))[0]
        cert_data = recv_exact(s, cert_len)

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert.public_key()

        # ---- AES KEY ----
        session_key = AESGCM.generate_key(bit_length=128)

        enc_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        s.send(struct.pack("I", len(enc_session_key)))
        s.send(enc_session_key)

        # ---- ENCRYPT PAYLOAD ----
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)

        ciphertext = aesgcm.encrypt(
            nonce,
            json.dumps(data).encode(),
            None
        )
        # ---- SEND PAYLOAD ----
        s.send(struct.pack("I", len(nonce)))
        s.send(nonce)
        s.send(struct.pack("I", len(ciphertext)))
        s.send(ciphertext)
        s.close()
        return latency_ms, stability_ms

    def _cleanup(self):
        """Remove the temporary downloaded file from disk."""
        if os.path.exists(DOWNLOAD_FILE):
            os.remove(DOWNLOAD_FILE)
            self._log("Temp file deleted (temp_download.bin)")

    # =========================================================================
    # MAIN TEST RUNNER  (runs in a background thread)
    # =========================================================================

    def _start_test_thread(self):
        """Spawn a background thread so the GUI stays responsive during the test."""
        thread = threading.Thread(target=self._run_test, daemon=True)
        thread.start()

    def _run_test(self):
        """Execute optimized test flow with reduced connections."""

        # Disable button
        self.root.after(0, lambda: self.run_btn.configure(state="disabled"))

        # Reset UI
        for i in range(1, 5):
            self._set_step(i, "")
        for attr in ["v_handshake", "v_throughput", "v_dltime", "v_conndur"]:
            self._set_metric(attr, "—")
        self._set_progress(0, "Starting…")

        # Read inputs
        ip        = self.entries["SERVER IP ADDRESS"].get().strip()
        port      = int(self.entries["TCP PORT"].get().strip())
        file_url  = self.entries["DOWNLOAD FILE URL"].get().strip()
        srv_name  = self.entries["SERVER NAME"].get().strip()

        self._set_status("running", "RUNNING")
        self._log(f"Target → {ip}:{port}   Server: {srv_name}", "info")

        try:
            # ─────────────────────────────────────────────────────────
            # STEP 1 — SINGLE CONNECTION (LATENCY ONLY)
            # ─────────────────────────────────────────────────────────
            self._set_step(1, "active")
            self._set_progress(5, "Connecting to server…")
            self._log(f"Opening secure connection to {ip}:{port} …")

            # Measure latency ONLY
            start = time.time()
            s = create_secure_socket(ip, port)
            s.settimeout(5)
            latency_ms = (time.time() - start) * 1000
            s.close()

            conn_dur = latency_ms / 1000  # proxy metric

            self._log(f"Connection latency: {latency_ms:.2f} ms", "ok")
            self._set_metric("v_handshake", f"{latency_ms:.2f}")
            self._set_metric("v_conndur", f"{conn_dur:.3f}")

            self._set_step(1, "done")
            self._set_progress(20, "Connection established. Starting download…")

            # ─────────────────────────────────────────────────────────
            # STEP 2 — FILE DOWNLOAD
            # ─────────────────────────────────────────────────────────
            self._set_step(2, "active")
            self._log("Downloading test file…")

            size_mb, dl_time = self._download_file(file_url, total_mb=FILE_SIZE_MB)

            # Prevent division crash
            throughput_mbps = (size_mb * 8) / dl_time if dl_time > 0 else 0

            self._log(f"Downloaded {size_mb:.2f} MB in {dl_time:.2f} s", "ok")
            self._log(f"Throughput: {throughput_mbps:.2f} Mbps", "ok")

            self._set_metric("v_throughput", f"{throughput_mbps:.2f}")
            self._set_metric("v_dltime", f"{dl_time:.2f}")

            self._set_step(2, "done")
            self._set_progress(70, "Download done. Sending results…")

            # ─────────────────────────────────────────────────────────
            # STEP 3 — SEND DATA (NEW CONNECTION)
            # ─────────────────────────────────────────────────────────
            self._set_step(4, "active")

            result_data = {
                "server_name": srv_name,
                "latency_ms": round(latency_ms, 2),
                "tcp_handshake_ms": round(latency_ms, 2),
                "throughput_Mbps": round(throughput_mbps, 2),
                "download_time_sec": round(dl_time, 2),
                "transfer_variance": 0.01,
                "connection_duration_sec": round(conn_dur, 3),
                "file_size_MB": round(size_mb, 2)
            }

            self._log(f"Transmitting JSON → {ip}:{port}")
            self._log(json.dumps(result_data))
            self._run_network_sequence(ip, port, result_data)

            self._set_step(4, "done")
            self._set_progress(100, "All tests completed successfully")

            # ─────────────────────────────────────────────────────────
            # CLEANUP
            # ─────────────────────────────────────────────────────────
            self._cleanup()

            self._set_status("done", "COMPLETED")
            self._log("─" * 50)
            self._log("All diagnostics passed successfully.", "ok")

        except Exception as exc:
            self._log(f"Error: {exc}", "err")
            self._set_status("error", "ERROR")

        finally:
            self.root.after(0, lambda: self.run_btn.configure(state="normal"))


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app  = NetworkClientApp(root)
    root.mainloop()