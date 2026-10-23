# Go DNS Server

A small DNS server written in Go using **only the standard library**. There's no DNS library: the binary wire format is encoded and decoded by hand, following RFC 1035.

It can do four things:

- **Answer your own names** from a simple zone file, for example `nas.home → 192.168.1.20`
- **Block ads and trackers**, Pi-hole style, from a blocklist
- **Forward everything else** to an upstream resolver such as `1.1.1.1`
- **Cache upstream answers** for as long as their TTL allows

It serves both **UDP and TCP**, so it works with `dig`, `nslookup`, browsers and operating-system resolvers.

```
$ dig @127.0.0.1 -p 1053 media.home +noall +answer
media.home.     300  IN  CNAME  files.home.
files.home.     300  IN  CNAME  nas.home.
nas.home.       300  IN  A      192.168.1.20
```

The project is meant for learning. It shows how to:

- read and write a **binary protocol** (big-endian integers, length-prefixed labels, bit flags)
- decode **name compression pointers** safely, including protection against malicious pointer loops
- run a **UDP and a TCP server** on the same port, each with its own message framing
- write a **TTL-aware cache** that serves raw bytes and rewrites TTLs in place
- defend against **cache poisoning** with random query IDs and random source ports
- handle **truncation**: when an answer is too big for UDP, set the TC flag so the client retries over TCP

---

## How DNS works, briefly

When you open `example.com`, your computer asks a DNS server "what is the A record (IPv4 address) of `example.com.`?" The question and the answer are each a small binary message, normally sent as **one UDP packet each way** to port 53.

```
                                  ┌── blocked?   → NXDOMAIN
client ── "A? nas.home." ──► this │── local zone? → answer from zones.txt
          (UDP or TCP)     server │── cached?    → answer from memory
                                  └── otherwise  → ask 1.1.1.1, cache, answer
```

| Term | Meaning |
|------|---------|
| **Record type** | `A` (IPv4), `AAAA` (IPv6), `CNAME` (alias), `MX` (mail server), `TXT` (text), and others |
| **TTL** | How many seconds an answer may be cached |
| **Authoritative** | The server owns the zone and *knows* the answer. dig shows this as the `aa` flag. |
| **NXDOMAIN** | The name does not exist |
| **NODATA** | The name exists, but has no records of the requested type |
| **Recursive/forwarding** | The server asks other servers on the client's behalf |

---

## Requirements

- Go **1.24 or newer**
- `dig` (from bind9-dnsutils) or `nslookup`, for testing

## Quick start

```bash
cd dns_server
make run      # listens on :1053 (UDP + TCP) with the example zone and blocklist
```

In another terminal:

```bash
dig @127.0.0.1 -p 1053 nas.home                  # local A record   (flags: aa)
dig @127.0.0.1 -p 1053 nas.home AAAA +short      # local IPv6
dig @127.0.0.1 -p 1053 media.home                # CNAME chain followed
dig @127.0.0.1 -p 1053 home MX +short            # mail server
dig @127.0.0.1 -p 1053 nope.home                 # NXDOMAIN (local)
dig @127.0.0.1 -p 1053 www.doubleclick.net       # NXDOMAIN (blocked)
dig @127.0.0.1 -p 1053 example.com               # forwarded to 1.1.1.1
dig @127.0.0.1 -p 1053 example.com               # again: served from the cache, lower TTL
dig @127.0.0.1 -p 1053 +tcp web.lab.internal     # over TCP
nslookup -port=1053 router.home 127.0.0.1
```

The server logs one line per query, saying where the answer came from:

```
msg=query client=127.0.0.1:57692 net=udp name=example.com. type=A source=upstream rcode=NOERROR duration=21.6ms
msg=query client=127.0.0.1:53157 net=udp name=example.com. type=A source=cache    rcode=NOERROR duration=21µs
```

### Options

| Flag         | Default      | Meaning |
|--------------|--------------|---------|
| `-addr`      | `:1053`      | Address for both UDP and TCP. Port 53 needs root, or `CAP_NET_BIND_SERVICE`. |
| `-upstream`  | `1.1.1.1:53` | Upstream resolver. Set it to `""` to answer only local names; everything else is then `REFUSED`. |
| `-zone`      | none         | Zone file with local records |
| `-blocklist` | none         | File of domains to block |
| `-cache`     | `10000`      | Maximum cached responses. `0` turns the cache off. |
| `-timeout`   | `2s`         | How long to wait for the upstream |
| `-debug`     | `false`      | Also log malformed queries |

### Using it as your real DNS server

```bash
sudo go run ./cmd/dnsserver -addr :53 -zone examples/zones.txt -blocklist examples/blocklist.txt
```

Then point a device's DNS setting at this machine's IP address. On Linux, port 53 may already be taken by `systemd-resolved`.

### Make targets

| Command      | What it does |
|--------------|--------------|
| `make run`   | Run on `:1053` with the example files |
| `make build` | Build `bin/dnsserver` |
| `make test`  | Run tests with the race detector |
| `make vet`   | Run `go vet` static analysis |
| `make fmt`   | Format the code |

---

## Zone file format

`examples/zones.txt`:

```
$DOMAIN home.                                  # we are authoritative for home. and below

home.          300  TXT    "my home network"
home.          300  MX     10 mail.home.
nas.home.      300  A      192.168.1.20
nas.home.      300  AAAA   fd00::20
files.home.    300  CNAME  nas.home.
```

- Each line is: **name, TTL in seconds, type, value.** Lines starting with `#` are comments.
- **Supported types:** `A`, `AAAA`, `CNAME`, `MX` (`<preference> <host>`), `TXT`.
- **`$DOMAIN`** declares a zone the server is authoritative for. Every record must sit under one. Names inside a `$DOMAIN` that have no records get **NXDOMAIN**; they are never forwarded upstream.
- **Names** are case-insensitive, and the trailing dot is optional.
- **Errors are caught at startup, with the line number:**
  - an invalid IP address
  - an IPv6 address in an `A` record, or an IPv4 address in an `AAAA` record
  - a record outside every `$DOMAIN`
  - a `CNAME` sharing its name with another record (RFC 1034 forbids that)

## Blocklist format

`examples/blocklist.txt`:

```
doubleclick.net
0.0.0.0 ads.example.com        # hosts-file format also works
```

Blocking a domain blocks **all of its subdomains**, so `doubleclick.net` also blocks `ad.doubleclick.net`. Matching works on whole labels, so blocking `ads.com` does *not* block `badads.com`. Because hosts-file lines are accepted, you can use public ad lists directly. Blocked names get `NXDOMAIN`.

---

## The wire format

Every DNS message, query or response, has this layout:

```
+---------------------+
|       Header        |  12 bytes
+---------------------+
|      Question       |  name + type + class
+---------------------+
|       Answer        |  resource records
+---------------------+
|      Authority      |  resource records
+---------------------+
|     Additional      |  resource records (EDNS OPT lives here)
+---------------------+
```

**Header (12 bytes):**

```
 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |   matches responses to queries
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |   flags
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|      QDCOUNT  /  ANCOUNT  /  NSCOUNT  /  ARCOUNT   (2 bytes each)
```

**Names** are sequences of labels, each one prefixed by its length:

```
www.example.com.  →  03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
```

**Compression.** To avoid repeating names, a name can end with a 2-byte **pointer**: its top two bits are `11`, and the remaining 14 bits give the offset of an earlier name in the message. For example, `C0 0C` means "the rest of the name is at offset 12". Upstream servers use pointers all the time.

**Pointer safety.** A malicious packet could contain a pointer to itself and trap a careless parser in an endless loop. This parser only accepts pointers that jump **backwards**, which guarantees that decoding ends. `TestParseRejectsBadMessages` checks this, along with other malformed input.

---

## Project structure

```
dns_server/
├── cmd/dnsserver/main.go        # flags, loads files, starts UDP + TCP servers
├── internal/
│   ├── dns/                     # the wire format (no networking)
│   │   ├── message.go           # Header, Question, Record, Parse, Pack, name compression
│   │   ├── rdata.go             # A/AAAA/CNAME/MX/TXT data builders, TCP framing
│   │   └── message_test.go
│   ├── zone/                    # local records from a zone file
│   ├── blocklist/               # Pi-hole style domain blocking
│   ├── resolver/                # decides how to answer each query
│   │   ├── resolver.go          # blocked → local → cache → upstream; truncation
│   │   ├── cache.go             # TTL-aware cache of raw responses
│   │   └── resolver_test.go     # uses a fake upstream DNS server
│   └── server/                  # UDP and TCP listeners
├── examples/zones.txt
├── examples/blocklist.txt
├── Makefile
└── README.md
```

The packages are layered. `dns` knows nothing about networking. `resolver` doesn't know whether a query arrived over UDP or TCP, apart from a size limit. `server` doesn't know anything about DNS logic. That layering is why each layer can be tested on its own.

## Design notes

**Answering locally**
- **CNAME chasing.** For `media.home → files.home → nas.home`, the answer contains the whole chain plus the final A record, exactly as `dig` shows. The chain is capped at 8 steps, so a loop such as `a → b → a` can't run forever. A CNAME that points outside the zone is returned as it is, and the client resolves the rest.
- **NXDOMAIN vs NODATA.** These are different answers. If `a.deep.home` exists, then `deep.home` exists too, even though it has no records of its own; that's called an *empty non-terminal*. A query for it gets NODATA, not NXDOMAIN.

**Forwarding and caching**
- **Cache poisoning defence.** Each query to the upstream gets a **new random ID** and goes out from a **new socket with a random source port**. Replies with the wrong ID are ignored, and the question in the reply must match. A forged answer would have to guess about 32 bits of randomness. Without these measures, the 2008 Kaminsky attack could poison caches.
- **The cache stores raw bytes.** The parser records the byte offset of every TTL field, so a cache hit is just: copy the bytes, set the client's ID, and lower each TTL by the time spent in the cache. Nothing has to be re-encoded. That's why `dig` shows the TTL counting down.
- **Negative caching.** NXDOMAIN and NODATA answers are cached too. The time comes from the upstream's SOA record: the smaller of its TTL and its MINIMUM field (RFC 2308). Without an SOA the default is 60 seconds.
- **Not cached:** truncated responses and failures (SERVFAIL and similar). Every TTL is capped at 24 hours.

**UDP and TCP**
- **UDP size limit.** Classic DNS over UDP allows 512 bytes. Clients can advertise a bigger limit with EDNS(0); `dig` sends 1232. If an answer is too big, the server replies with an **empty response that has TC=1**, and the client retries over TCP. `TestTruncation` covers this.
- **TCP framing.** Each message is preceded by its length in 2 bytes. A single connection can carry several queries, and idle connections close after 10 seconds.

**Robustness**
- **UDP concurrency.** Each query is resolved in its own goroutine, so one slow upstream lookup doesn't hold up others. At most 512 run at once; any more are dropped instead of exhausting memory. TCP allows at most 128 connections.
- **The server never answers a response packet** (QR=1). Doing so is a classic way to create reflection loops between two servers. Garbage shorter than a header is ignored, and other malformed queries get `FORMERR`.

## Security notes

- **Open resolver risk.** If you run this on a public IP address with forwarding turned on, anyone can use it. That includes DNS amplification attacks, where a small spoofed query triggers a large reply aimed at a victim. Bind it to `127.0.0.1` or your LAN only, or block port 53 from the internet with a firewall.
- **No DNSSEC validation.** Answers from the upstream are trusted. To protect the hop to the upstream, use a resolver you trust, or extend this project with DNS-over-TLS or DNS-over-HTTPS.
- **No rate limiting** per client. That would be a good extension.

## Testing

```bash
go test -race ./...
```

| Package     | What the tests cover |
|-------------|---------------------|
| `dns`       | Pack/parse round trip, compressed names, bad input (pointer loops, forward pointers, reserved labels, overlong names), TXT splitting, TCP framing |
| `zone`      | Loading, case-insensitivity, empty non-terminals, whole-label matching, ten kinds of invalid zone line |
| `blocklist` | Subdomain blocking, hosts-file format, whole-label matching |
| `resolver`  | Local answers, CNAME chains and loops, NXDOMAIN vs NODATA, blocking, `REFUSED` with no upstream, forwarding through a **fake upstream server**, cache hits with lowered TTLs, cache expiry (using a fake clock), SERVFAIL when the upstream is down, UDP truncation vs a full TCP answer, FORMERR, NOTIMP, ignoring responses, SOA-based negative TTL |
| `server`    | Real UDP and TCP round trips, several queries on one TCP connection, clean shutdown |

## Limitations

These are left out to keep the code small:

- Only A, AAAA, CNAME, MX and TXT can be defined locally. Upstream answers of any type pass through unchanged.
- No zone transfers (AXFR), DNSSEC or dynamic updates.
- No `SOA`/`NS` records for local zones, so negative answers from local zones carry no SOA.
- If several clients ask the same uncached question at the same moment, each query goes upstream. There's no "singleflight" merging of identical requests.
- Changes to the zone file or blocklist need a restart.

## Ideas to extend

- Reload the zone and blocklist on `SIGHUP`, without a restart
- Rate limiting per client IP
- DNS-over-HTTPS upstream (`net/http` + `application/dns-message`)
- `PTR` records for reverse lookups (`dig -x 192.168.1.20`)
- A metrics page: queries per second, cache hit rate, top blocked domains
- Merge identical in-flight upstream queries (singleflight)
