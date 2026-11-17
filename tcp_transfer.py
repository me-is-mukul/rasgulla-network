"""
tcp_transfer.py — File transfer over raw TCP sockets (SafeCipher 2.0)

Transfers files that SafeCipher has ALREADY encrypted (AES-256-CBC or stego PNG),
so only ciphertext ever travels over the network. Integrity is checked with
SHA-256 on both ends.

------------------------------------------------------------------------------
Application-layer protocol ("SCFT" = SafeCipher File Transfer), over TCP:

    CLIENT (sender)                                   SERVER (receiver)
    ---------------                                   -----------------
    connect()  ----------- TCP 3-way handshake ----------->  accept()
    [4B magic "SCFT"]
    [4B header length N, big-endian]
    [N bytes JSON header]  ------------------------------->  validate header
        {filename, size, sha256, meta}
                           <-------------------------------  [4B len][JSON] READY
    [size bytes of file data, sent in 4 KB chunks] ------->  recv() loop,
                                                             write to disk,
                                                             hash on the fly
                           <-------------------------------  [4B len][JSON] OK/ERROR
                                                             {status, sha256, message}
    close()    ----------- TCP connection teardown -------->  close()

Length-prefixing is required because TCP is a byte STREAM, not a message
protocol — recv() can return any number of bytes, so we must frame messages
ourselves and loop until exactly the expected number of bytes has arrived.
------------------------------------------------------------------------------

Usage as a standalone CLI (for terminal demos, no web app needed):

    python tcp_transfer.py receive --port 5001 --out received_files
    python tcp_transfer.py send <file> <host> --port 5001
"""

import os
import json
import socket
import struct
import hashlib
import threading
from datetime import datetime

MAGIC = b"SCFT"
CHUNK_SIZE = 4096
DEFAULT_PORT = 5001
MAX_HEADER_SIZE = 64 * 1024            # 64 KB is plenty for the JSON header
MAX_FILE_SIZE = 100 * 1024 * 1024      # 100 MB safety limit
SOCKET_TIMEOUT = 30                    # seconds (data phase)
CONNECT_TIMEOUT = 5                    # seconds (fail fast if receiver unreachable)


# ============================================================
# LOW-LEVEL FRAMING HELPERS
# ============================================================
def recv_exact(sock, n):
    """Receive exactly n bytes from a TCP socket (TCP may split data arbitrarily)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before all data was received")
        buf.extend(chunk)
    return bytes(buf)


def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_json(sock, max_size=MAX_HEADER_SIZE):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > max_size:
        raise ValueError("Message too large")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def get_local_ip():
    """Best-effort LAN IP of this machine (UDP connect sends no packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_local_ips():
    """All usable IPv4 addresses of this machine (primary first, no loopback/link-local)."""
    ips = [get_local_ip()]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
    seen, result = set(), []
    for ip in ips:
        if ip not in seen and not ip.startswith(("127.", "169.254.")):
            seen.add(ip)
            result.append(ip)
    return result or ["127.0.0.1"]


def parse_host_port(host, port=DEFAULT_PORT):
    """Accept '192.168.1.5', '192.168.1.5:5001', 'http://192.168.1.5:5001/', 'localhost'."""
    host = (host or "").strip()
    for prefix in ("http://", "https://", "tcp://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.strip("/ ")
    if host.count(":") == 1:
        h, _, p = host.partition(":")
        if p.strip().isdigit():
            host, port = h.strip(), int(p)
    if host in ("0.0.0.0", "localhost", ""):
        host = "127.0.0.1" if host else ""
    return host, int(port)


def _safe_name(name):
    """Strip any directory components to prevent path traversal (../../etc)."""
    name = os.path.basename(name.replace("\\", "/")).strip()
    return name or "unnamed_file"


# ============================================================
# SENDER (TCP CLIENT)
# ============================================================
def send_file(file_path, host, port=DEFAULT_PORT, meta=None, progress=None):
    """
    Send a file to a SafeCipher TCP receiver.
    Returns the receiver's final response dict: {status, sha256, message}.
    Raises on network / protocol errors.
    """
    size = os.path.getsize(file_path)
    file_hash = sha256_of_file(file_path)

    header = {
        "filename": os.path.basename(file_path),
        "size": size,
        "sha256": file_hash,
        "meta": meta or {},
    }

    host, port = parse_host_port(host, port)
    if not host:
        raise ConnectionError("Receiver IP / host is empty.")

    # Connect with a short timeout and turn raw socket errors into clear messages
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except ConnectionRefusedError:
        raise ConnectionError(
            f"Connection refused by {host}:{port}. Nothing is listening there: "
            f"click 'Start Receiver' on that machine and check the port number.")
    except socket.gaierror:
        raise ConnectionError(
            f"Unknown host '{host}'. Enter the receiver's IP address (e.g. 192.168.1.20).")
    except (socket.timeout, TimeoutError):
        raise ConnectionError(
            f"Timed out connecting to {host}:{port}. The receiver is unreachable: make sure the "
            f"receiver is started, both machines are on the SAME Wi-Fi/hotspot, the IP is the one "
            f"shown on the receiver's page, and the receiver's Windows Firewall allows Python.")
    except OSError as e:
        raise ConnectionError(
            f"Cannot reach {host}:{port} ({e.strerror or e}). Check both machines are on the "
            f"same network and the IP address is correct.")

    sock.settimeout(SOCKET_TIMEOUT)
    with sock:
        # 1) Send magic + header
        sock.sendall(MAGIC)
        send_json(sock, header)

        # 2) Wait for receiver to accept the header
        reply = recv_json(sock)
        if reply.get("status") != "READY":
            raise ConnectionError(f"Receiver rejected transfer: {reply.get('message')}")

        # 3) Stream the file body in chunks
        sent = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                sock.sendall(chunk)
                sent += len(chunk)
                if progress:
                    progress(sent, size)

        # 4) Read final integrity verdict
        result = recv_json(sock)
        result.setdefault("sender_sha256", file_hash)
        result.setdefault("bytes_sent", sent)
        return result


# ============================================================
# RECEIVER (TCP SERVER)
# ============================================================
class TCPFileReceiver:
    """
    Multi-client TCP server. Each incoming connection is handled in its own
    thread; received files are written to `save_dir` along with a small
    .meta.json sidecar describing the transfer.
    """

    def __init__(self, host="0.0.0.0", port=DEFAULT_PORT, save_dir="received_files",
                 on_event=None):
        self.host = host
        self.port = int(port)
        self.save_dir = os.path.abspath(save_dir)
        self.on_event = on_event or (lambda msg: print(msg))
        self._sock = None
        self._thread = None
        self._running = threading.Event()

    @property
    def running(self):
        return self._running.is_set()

    def start(self):
        if self.running:
            return
        os.makedirs(self.save_dir, exist_ok=True)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: SO_REUSEADDR would let TWO programs silently share the port
            # (and steal each other's connections), so demand exclusive use instead.
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(1.0)  # lets the accept loop notice stop()

        self._running.set()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self.on_event(f"Receiver listening on {self.host}:{self.port}")

    def stop(self):
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        self.on_event("Receiver stopped")

    def serve_forever(self):
        """Blocking variant for CLI use."""
        self.start()
        try:
            while self.running:
                self._thread.join(timeout=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # --------------------------------------------------------
    def _accept_loop(self):
        while self._running.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn, addr),
                             daemon=True).start()

    def _handle_client(self, conn, addr):
        peer = f"{addr[0]}:{addr[1]}"
        self.on_event(f"Connection accepted from {peer}")
        save_path = None
        try:
            conn.settimeout(SOCKET_TIMEOUT)

            # 1) Validate magic + header
            if recv_exact(conn, 4) != MAGIC:
                raise ValueError("Bad protocol magic (not a SafeCipher client)")
            header = recv_json(conn)

            filename = _safe_name(str(header.get("filename", "")))
            size = int(header.get("size", -1))
            expected_hash = str(header.get("sha256", ""))
            meta = header.get("meta") or {}

            if size < 0 or size > MAX_FILE_SIZE:
                send_json(conn, {"status": "ERROR", "message": "Invalid or too-large file size"})
                raise ValueError(f"Rejected size {size}")

            stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
            stored_name = f"recv_{stamp}_{filename}"
            save_path = os.path.join(self.save_dir, stored_name)

            send_json(conn, {"status": "READY"})
            self.on_event(f"Receiving '{filename}' ({size} bytes) from {peer}")

            # 2) Receive exactly `size` bytes, hashing as we go
            h = hashlib.sha256()
            remaining = size
            with open(save_path, "wb") as f:
                while remaining > 0:
                    chunk = conn.recv(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("Sender disconnected mid-transfer")
                    f.write(chunk)
                    h.update(chunk)
                    remaining -= len(chunk)

            actual_hash = h.hexdigest()
            verified = actual_hash == expected_hash

            # 3) Persist transfer metadata
            info = {
                "stored_name": stored_name,
                "filename": filename,
                "size": size,
                "sha256": actual_hash,
                "verified": verified,
                "sender": peer,
                "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "meta": meta,
            }
            with open(save_path + ".meta.json", "w", encoding="utf-8") as mf:
                json.dump(info, mf, indent=2)

            # 4) Send integrity verdict
            if verified:
                send_json(conn, {"status": "OK", "sha256": actual_hash,
                                 "message": "File received and SHA-256 verified"})
                self.on_event(f"'{filename}' received from {peer} - SHA-256 OK")
            else:
                send_json(conn, {"status": "ERROR", "sha256": actual_hash,
                                 "message": "SHA-256 mismatch - file corrupted in transit"})
                self.on_event(f"'{filename}' from {peer} - SHA-256 MISMATCH")

        except Exception as e:
            self.on_event(f"Transfer from {peer} failed: {e}")
            # Remove partial file (only if no metadata was written for it)
            if save_path and os.path.exists(save_path) and not os.path.exists(save_path + ".meta.json"):
                try:
                    os.remove(save_path)
                except OSError:
                    pass
        finally:
            conn.close()


def list_received(save_dir):
    """Return metadata dicts for all received files, newest first."""
    items = []
    if not os.path.isdir(save_dir):
        return items
    for name in os.listdir(save_dir):
        if name.endswith(".meta.json"):
            try:
                with open(os.path.join(save_dir, name), encoding="utf-8") as f:
                    info = json.load(f)
                if os.path.exists(os.path.join(save_dir, info["stored_name"])):
                    items.append(info)
            except Exception:
                continue
    items.sort(key=lambda i: i.get("stored_name", ""), reverse=True)
    return items


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SafeCipher TCP file transfer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("receive", help="Run a TCP receiver (server)")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=DEFAULT_PORT)
    r.add_argument("--out", default="received_files")

    s = sub.add_parser("send", help="Send a file to a receiver (client)")
    s.add_argument("file")
    s.add_argument("host")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)

    args = parser.parse_args()

    if args.cmd == "receive":
        print(f"[*] This machine's LAN IP: {get_local_ip()}")
        print("[*] Press Ctrl+C to stop.")
        TCPFileReceiver(args.host, args.port, args.out,
                        on_event=lambda m: print(f"[{datetime.now():%H:%M:%S}] {m}")).serve_forever()
    else:
        def show(sent, total):
            pct = 100 * sent / total if total else 100
            print(f"\r[*] Sent {sent}/{total} bytes ({pct:.0f}%)", end="", flush=True)

        print(f"[*] Connecting to {args.host}:{args.port} ...")
        res = send_file(args.file, args.host, args.port, progress=show)
        print()
        print(f"[*] Receiver status : {res.get('status')}")
        print(f"[*] Message         : {res.get('message')}")
        print(f"[*] Sender SHA-256  : {res.get('sender_sha256')}")
        print(f"[*] Receiver SHA-256: {res.get('sha256')}")
