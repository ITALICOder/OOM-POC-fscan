#!/bin/bash
# Crash repro: fscan's postgresql plugin dials DIRECT (bypasses -socks5),
# hits the local HTTP-pg listener on 127.0.0.1:5432, lib/pq parses b"HTTP/"
# as a 0x5454502f length -> make(0x5454502b)=1.41GB -> RLIMIT_AS below that
# makes the mmap fail -> Go fatal "out of memory" (identical to the incident).
cd /home/rasp
: > /home/rasp/direct.payloads

sudo -n cp -f /root/pass.txt /home/rasp/pass.txt 2>/dev/null
sudo -n chmod 644 /home/rasp/pass.txt 2>/dev/null

BASE="-lang en -pwdf /home/rasp/pass.txt -np -h 127.0.0.1,127.0.0.2,127.0.0.3 -t 64 -time 4 -nocolor -nopg -gt 30 -socks5 127.0.0.1:1080 -nsp -m postgresql -p 5433"

for L in 1600000 1200000; do
  echo "--- ulimit -v $L KB ---"
  (
    ulimit -v $L || exit 99
    exec /home/rasp/fscan $BASE > /home/rasp/repro_d$L.log 2>&1
  )
  rc=$?
  echo "exit=$rc"
  if grep -q "recvMessage" /home/rasp/repro_d$L.log 2>/dev/null; then
    echo "*** CRASH REPRODUCED: direct dial + RLIMIT_AS=$L ***"
    grep -n -m 12 -E "fatal error|out of memory|recvMessage|makeslice|lib/pq" /home/rasp/repro_d$L.log
    echo "--- direct listener payload log (proof pq bypassed the proxy) ---"
    head -8 /home/rasp/direct.payloads
    exit 0
  fi
  echo "(no crash; log tail:)"
  tail -5 /home/rasp/repro_d$L.log 2>/dev/null
done

echo "--- direct listener payload log ---"
cat /home/rasp/direct.payloads 2>/dev/null | head -10
echo "NO_CRASH"
