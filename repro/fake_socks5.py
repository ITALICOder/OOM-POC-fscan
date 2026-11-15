"""Fake SOCKS5 proxy emulating the honeypot, handshake-aware (mode 'pg').

Handshake logic (mode=pg):
  - payload is an 8-byte SSLRequest (00 00 00 08 ...) -> reply b'N'
    (PostgreSQL "SSL not supported"; what a plaintext-only server answers),
    so lib/pq falls back to the plaintext startup packet on the same socket.
  - any other payload (the PG startup packet) -> reply with an HTTP/ error
    page: pq parses first 5 bytes b"HTTP/" as type='H', length=0x5454502f
    -> make([]byte, 0x5454502b) = 1,414,590,507 bytes, uncapped
    -> Go runtime fatal "out of memory" (the incident crash).

Every payload's hex is appended to fake_socks5.payloads for diagnosis.

Modes (argv[1]): pg | http | canned | none
argv[2] = listen port (default 1080), argv[3] = hold seconds (default 300)
"""
import socket
import sys
import threading
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "pg"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
HOLD = float(sys.argv[3]) if len(sys.argv) > 3 else 300.0

HTTP_REPLY = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Server: honeypot\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 19\r\n"
    b"\r\n"
    b"access denied!!!!\n"
)
CANNED_REPLY = b"R\x00\x00\x00\x08\x00\x00\x00\x03"  # PG AuthenticationCleartextPassword
SSLREFUSE = b"N"  # PG SSLResponse: no SSL

LOG = "/home/rasp/fake_socks5.payloads"


def log_payload(data: bytes) -> None:
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} len={len(data)} hex={data[:24].hex()}\n")
    except OSError:
        pass


def handle(c: socket.socket) -> None:
    try:
        c.settimeout(60)
        hdr = c.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            return
        c.recv(hdr[1])
        c.sendall(b"\x05\x00")
        req = c.recv(4)
        if len(req) < 4:
            return
        atyp = req[3]
        if atyp == 1:
            c.recv(4)
        elif atyp == 3:
            n = c.recv(1)
            c.recv(n[0])
        elif atyp == 4:
            c.recv(16)
        c.recv(2)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        while True:
            try:
                payload = c.recv(4096)
            except socket.timeout:
                return
            if not payload:
                return
            log_payload(payload)
            if MODE == "pg":
                if len(payload) == 8 and payload[:4] == b"\x00\x00\x00\x08":
                    c.sendall(SSLREFUSE)  # SSLRequest -> "no SSL"
                    continue
                c.sendall(HTTP_REPLY)     # startup packet -> the crash trigger
            elif MODE == "http":
                c.sendall(HTTP_REPLY)
            elif MODE == "canned":
                c.sendall(CANNED_REPLY)
            else:
                return
            time.sleep(HOLD)
            return
    except Exception:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(64)
print(f"fake socks5 on 127.0.0.1:{PORT} mode={MODE} hold={HOLD}s", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
