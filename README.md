# OOM-POC-fscan
## fscan v2.2.2 — Security Report: Remote OOM Crash (lib/pq) & `-socks5` Proxy Bypass

**Reported:** 2026-11-15
**Affected version:** fscan 2.2.2 (`2ede41d`, 2026-10-01) — official release binaries
**Discovered on:** Raspberry Pi 4, Debian armhf (32-bit ARM), 4 GB RAM
**Status:** both issues reproduced locally with deterministic PoCs (see `repro/`, `evidence/`)

---

## TL;DR

1. **Remote denial of service (process crash)** — `lib/pq`'s `recvMessage` reads a 4-byte message length from the socket with **no upper bound** and allocates that many bytes. Any target (or on-path device) that answers a PostgreSQL startup packet with a non-PostgreSQL response — most commonly an HTTP error page — makes fscan allocate gigabytes and die with `fatal error: out of memory` (exit code 2). A **5-byte response** is enough to demand **2.15 GB** (32-bit build) or **4.29 GB** (64-bit build) *per connection*; fscan's concurrent credential workers multiply this (25 concurrent connections ⇒ **>100 GB** demanded).
2. **`-socks5` is not applied to `database/sql` plugins** — with `-socks5` set, port scanning and banner grabbing go through the proxy, but the `postgresql` plugin (and presumably `mysql`, `mssql`, `oracle` — same `database/sql` pattern) connects **directly** from the scanner's real IP. This leaks the real source IP, reaches targets outside the configured proxy, and is what allowed issue #1 to be triggered by a LAN host *during an otherwise fully proxied scan*.

---

## Issue 1 — Remote OOM crash via attacker-controlled allocation in `lib/pq`

### What happened (wild incident)

A full `192.168.1.0/24` scan (all traffic through a SOCKS5 proxy) aborted mid-scan:

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
github.com/shadow1ng/fscan/plugins/services.(*PostgreSQLPlugin).doPostgreSQLAuth(...) postgresql.go:95
```

Five goroutines were in `recvMessage → makeslice` simultaneously (adaptive `ModuleThread=5`); two 1.41 GB allocations had already committed ~3.02 GB when the third triggered the fatal error. fscan exited with code 2 and the scan was lost. Excerpt of the real log: `evidence/incident_crash_snippet.txt`.

### Root cause

`lib/pq@v1.10.9/conn.go:1030` (`recvMessage`):

```go
_, err = io.ReadFull(r, buf[:5])               // type byte + uint32 length
t := buf[0]
n := int(binary.BigEndian.Uint32(buf[1:])) - 4  // ← attacker-controlled, NO upper bound
y = make([]byte, n)                             // ← allocate whatever the peer claims
```

The peer fully controls `n`. fscan opens these connections in the `postgresql` plugin (`testUnauthorizedAccess` and the credential tests) against **every host where the port scan found 5432/5433/5434 open** — no authentication required to trigger.

### Why an HTTP response triggers it

PostgreSQL's wire format starts every message with `type(1) + length(4)`. An HTTP response's first five bytes are `HTTP/`, which pq parses as:

- type = `'H'`
- length = `uint32("TTP/")` = `0x5454502f`
- `n = 0x5454502f − 4 = 0x5454502b = 1,414,590,507 bytes`

→ `make([]byte, 1414590507)` → `fatal error: out of memory` on any host without ~1.4 GB to spare (the wild incident had ~1 GB free ⇒ crash). HTTP error pages are the most common non-PG response in the wild: misconfigured services, HTTP-only devices listening on 5432, load balancers, captive portals, proxies answering `403/502`.

### Arbitrary size — scaling past 100 GB

The length is a raw `uint32`; the attacker picks it:

| Reply (first 5 bytes) | Declared `n` | Notes |
|---|---|---|
| `HTTP/...` (observed in the wild) | 1,414,590,507 (1.41 GB) | the incident |
| `H` + `0x7FFFFFFF` | 2,147,483,643 (2.15 GB) | max positive value on 32-bit builds — **our PoC** |
| `H` + `0xFFFFFFFF` | 32-bit: wraps to −5, rejected cleanly; 64-bit: 4,294,967,291 (4.29 GB) | uint32 ceiling |

One connection can demand up to **2.15 GB** (32-bit) / **4.29 GB** (64-bit). fscan runs credential tests concurrently (`ModuleThread`, observed = 5, adaptive): in our default-system PoC the first worker committed **2.25 GB** and the second worker's allocation immediately crashed the process (`cannot allocate 2147483648-byte block (2247294976 in use)`). Aggregate demand scales with thread count and target count — 25 concurrent connections on a 64-bit build = **>100 GB** requested from a 5-byte reply. Even where the allocation succeeds, zeroing gigabytes stalls the scanner and thrashes the host.

### Reproduction (deterministic, localhost-only)

`repro/` contains a complete PoC (Python 3 stdlib only):

```bash
python3 bigalloc_listener.py 5433 &          # replies 48 7f ff ff ff (H + 0x7FFFFFFF)
./fscan -lang en -np -h 127.0.0.1,127.0.0.2,127.0.0.3 -t 64 -time 4 \
        -nocolor -nopg -gt 30 -nsp -m postgresql -p 5433
```

Result — on a **default, idle 4 GB system with no limits or tuning**:

```
runtime: out of memory: cannot allocate 2147483648-byte block (2247294976 in use)
fatal error: out of memory
runtime.makeslice(0xa22c50, 0x7ffffffb, 0x7ffffffb)
github.com/lib/pq.(*conn).recvMessage(...) conn.go:1030
exit code 2
```

Variants:

- `direct_listener.py` replies a full `HTTP/1.1 403 Forbidden` page → reproduces the **exact wild bytes** (`makeslice(0x5454502b)`) — `evidence/repro_http_1.41GB_ulimit.log`.
- `fake_socks5.py` wraps either responder in SOCKS5 to model proxied operation.

Evidence: `evidence/maxlen_nolimit.log` (default system), `evidence/maxlen_ulimit.log` (deterministic via `RLIMIT_AS`), `evidence/incident_crash_snippet.txt` (wild crash).

### Suggested fix

- Cap the message length in `recvMessage`: PostgreSQL messages are bounded in practice — reject `n` above a sane ceiling (a few tens of MB) with a protocol error instead of allocating. Audit the other length-prefixed reads in pq for the same pattern.
- Use checked arithmetic (`length ≥ 4`, no wraparound).
- Consider read deadlines on protocol reads so a silent peer cannot pin goroutines either.

---

## Environment & methodology

- fscan **2.2.2** (`2ede41d 2026-10-01T05:55:05Z`), official `linux_arm` release binary, ordinary user, no namespaces or pre-existing limits.
- Debian armhf (32-bit userland), Raspberry Pi 4, 4 GB RAM + 1.3 GB swap, `vm.overcommit_memory=0`.
- All PoCs are deterministic and localhost-only; no third-party systems were contacted.
- Classification: **memory-exhaustion DoS — not a buffer overflow, not RCE.** Go's bounds-checked `make` either allocates or the runtime aborts the process; there is no memory corruption. For a scanning tool the availability impact is nonetheless critical: one hostile/misconfigured target kills the entire scan.

## Files

```
README.md                             this document
ISSUE_1_remote-oom-crash.md           ready-to-file issue text
repro/bigalloc_listener.py            max-length (2.15 GB) crash PoC
repro/direct_listener.py              HTTP/-reply (wild variant) PoC
repro/fake_socks5.py                  SOCKS5-wrapped variant
repro/repro_direct.sh                 automated run (HTTP variant)
repro/repro_maxlen.sh                 automated run (max-length variant)
evidence/incident_crash_snippet.txt   wild crash excerpt (from the real scan)
evidence/maxlen_nolimit.log           2.15 GB crash on a default system
evidence/maxlen_ulimit.log            2.15 GB crash under RLIMIT_AS
evidence/repro_http_1.41GB_ulimit.log exact wild bytes (0x5454502b) crash
evidence/payloads_via_proxy.txt       what actually goes through -socks5
evidence/payloads_http_direct.txt     pq startup arriving direct (bypass proof)
evidence/payloads_bigalloc_direct.txt same, max-length run
```
