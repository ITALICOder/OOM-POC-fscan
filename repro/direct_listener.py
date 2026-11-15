"""Direct TCP listener on 127.0.0.1:5432 that replies HTTP to any payload.

Purpose: fscan's postgresql plugin (database/sql + lib/pq) dials the target
DIRECTLY, ignoring -socks5. With nothing on real 127.0.0.1:5432 pq got
connection-refused (why the proxy repro never crashed). This listener answers
the pq startup packet with b"HTTP/..." -> pq recvMessage parses type='H',
length=0x5454502f -> make([]byte, 0x5454502b) = 1,414,590,507 bytes, uncapped
-> under a tight RLIMIT_AS the mmap fails -> Go fatal "out of memory"
(identical to the incident).

Every payload's hex is appended to /home/rasp/direct.payloads as proof that
the connection arrived WITHOUT the proxy.
"""
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5432
HOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
LOG = "/home/rasp/direct.payloads"

HTTP_REPLY = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Server: honeypot\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 19\r\n"
    b"\r\n"
    b"access denied!!!!\n"
)


def handle(c: socket.socket) -> None:
    try:
        c.settimeout(60)
        try:
            data = c.recv(4096)
        except socket.timeout:
            data = b""
        if data:
            with open(LOG, "a") as f:
                f.write(f"{time.strftime('%H:%M:%S')} len={len(data)} hex={data[:32].hex()}\n")
            c.sendall(HTTP_REPLY)
            time.sleep(HOLD)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("", PORT))
srv.listen(16)
print(f"direct http-pg listener on 127.0.0.1:{PORT} hold={HOLD}s", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
