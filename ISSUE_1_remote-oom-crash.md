# Remote DoS: peer-controlled message length in lib/pq `recvMessage` crashes fscan with `fatal error: out of memory` (exit 2)

**Version:** fscan 2.2.2 (`2ede41d`, official release binary)
**Environment:** Debian armhf (32-bit ARM), Raspberry Pi 4, 4 GB RAM — also reproduced with no limits on an idle system
**Classification:** remote memory-exhaustion DoS (not a buffer overflow, not RCE)

## Summary

Any host that answers a PostgreSQL startup packet with a non-PostgreSQL response can crash fscan. `lib/pq@v1.10.9/conn.go:1030` (`recvMessage`) reads a 4-byte message length from the socket and allocates that many bytes **with no upper bound**. The most common trigger in the wild is an **HTTP response**: its first five bytes `HTTP/` are parsed as type `'H'` + length `uint32("TTP/") = 0x5454502f` → `make([]byte, 0x5454502b)` = **1,414,590,507 bytes**.

No authentication is needed: the `postgresql` plugin connects to every host where the port scan found 5432/5433/5434 open and immediately performs an unauthorized-access ping (`testUnauthorizedAccess`) plus credential tests — each of which goes through the vulnerable read.

## Wild incident

A full `/24` scan (all traffic through a SOCKS5 proxy) died mid-scan:

```
runtime: out of memory: cannot allocate 1417674752-byte block (3023765504 in use)
fatal error: out of memory
...
runtime.makeslice(0xa22c50, 0x5454502b, 0x5454502b)
github.com/lib/pq.(*conn).recvMessage(...)  github.com/lib/pq@v1.10.9/conn.go:1030
github.com/lib/pq.(*conn).recv(...)         conn.go:1048
github.com/lib/pq.(*conn).startup(...)      conn.go:1189
github.com/lib/pq.(*Connector).open(...)    conn.go:390
...
fscan/plugins/services.(*PostgreSQLPlugin).doPostgreSQLAuth(...) postgresql.go:95
```

Five goroutines were inside `recvMessage → makeslice` concurrently (`ModuleThread=5`); two 1.41 GB allocations had already committed ~3.02 GB when the third triggered the fatal error → **exit code 2, entire scan lost**.

## Root cause

```go
// lib/pq@v1.10.9/conn.go:1030
_, err = io.ReadFull(r, buf[:5])               // type + uint32 length
t := buf[0]
n := int(binary.BigEndian.Uint32(buf[1:])) - 4  // ← attacker-controlled, no cap
y = make([]byte, n)                             // ← allocate whatever the peer claims
```

## Attacker controls the size (up to 100 GB+ in aggregate)

| Reply (first 5 bytes) | Declared `n` | Notes |
|---|---|---|
| `HTTP/...` (seen in the wild) | 1,414,590,507 (1.41 GB) | the incident |
| `H` + `0x7FFFFFFF` | 2,147,483,643 (2.15 GB) | max positive on 32-bit builds — PoC below |
| `H` + `0xFFFFFFFF` | 32-bit: wraps negative, rejected; 64-bit: 4,294,967,291 (4.29 GB) | uint32 ceiling |

A **5-byte reply** therefore demands up to 2.15 GB (32-bit) / 4.29 GB (64-bit) *per connection*. fscan's credential tests run concurrently (`ModuleThread`, observed = 5, adaptive): in the PoC below the first worker committed **2.25 GB** and the second immediately crashed the process. Aggregate demand scales with thread and target count — 25 concurrent connections on a 64-bit build = **>100 GB** requested. Even when allocations succeed, zeroing gigabytes stalls the scanner and thrashes the host.

## Reproduction (deterministic, localhost-only)

```bash
# 1. fake "PostgreSQL" that replies 48 7f ff ff ff (H + 0x7FFFFFFF) to the startup packet
python3 bigalloc_listener.py 5433 &     # script in the accompanying repro/ folder

# 2. exact plugin invocation
./fscan -lang en -np -h 127.0.0.1,127.0.0.2,127.0.0.3 -t 64 -time 4 \
        -nocolor -nopg -gt 30 -nsp -m postgresql -p 5433
```

Result on a **default, idle 4 GB system — no ulimit, no tuning**:

```
runtime: out of memory: cannot allocate 2147483648-byte block (2247294976 in use)
fatal error: out of memory
runtime.makeslice(0xa22c50, 0x7ffffffb, 0x7ffffffb)
github.com/lib/pq.(*conn).recvMessage(...) conn.go:1030
exit code 2
```

A second variant replies a full `HTTP/1.1 403 Forbidden` page and reproduces the exact wild bytes: `makeslice(0x5454502b)` → `cannot allocate 1417674752-byte block`. Full logs accompany this report.

## Suggested fix

- Cap `n` in `recvMessage`: reject lengths above a sane ceiling (PostgreSQL messages are bounded in practice — tens of MB at most) with a protocol error instead of allocating; audit the other length-prefixed reads in pq for the same pattern.
- Checked arithmetic (`length ≥ 4`, no wraparound).
- Read deadlines on protocol reads so a silent peer cannot pin goroutines either.

(Same class of bug as historical unbounded-length issues in other wire-protocol parsers; the fix belongs upstream in `lib/pq` and/or as a vendored patch here.)
