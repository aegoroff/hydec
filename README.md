# hydec

Non-interactive CLI that downloads a base64-encoded proxy subscription, probes working nodes, and prints the preferred working one (protocol preference, then latency).

Requires **Zig 0.16.0** ([mise](https://mise.jdx.dev/) pin in `mise.toml`, or install manually).

## Features

- Fetches an **HTTPS-only** subscription URL and base64-decodes URI lines
- Probes **Shadowsocks** (AEAD), **Trojan** (TLS / WebSocket), **VLESS REALITY** (TCP vision and gRPC gun)
- Skips VMess (counted in stats)
- Groups by host/IP: different IPs in parallel, same IP sequentially
- Ranks by **protocol preference** (VLESS gRPC → VLESS TCP → SS → Trojan), demoting a preferred tier only when a lower tier is much faster (3× / 5× rules)
- Optional `--interface` / `-I` binds probe sockets to a source IP or Linux device name
- Logs progress to **stderr**; prints the winning URI to **stdout**

## Build

```bash
# via mise + just (recommended)
just build
just test

# or plain zig
zig build
zig build test
```

Binary: `zig-out/bin/hydec`.

Cross-compile / release archives:

```bash
just arch=x86_64 os=linux abi=musl ver=0.1.0 cpu=core2 release
just ver=0.1.0 build-all   # linux / macos / windows targets
```

## Usage

```bash
hydec best <SUBSCRIPTION_URL>
hydec best -v -t 5 https://example.com/sub
hydec best -I 192.168.1.10 https://example.com/sub
hydec best -I eth0 https://example.com/sub          # Linux; needs CAP_NET_RAW / root
hydec ping 'ss://...#remark'
hydec ping -t 10 -I wlan0 'vless://...'
```

| Command | Description |
|---------|-------------|
| `best <URI>` | Download HTTPS subscription, probe nodes, print preferred URI |
| `ping <PROXY>` | Probe a single proxy URI; exit `1` on failure |

| Flag | Description |
|------|-------------|
| `-t`, `--timeout` | Per-operation timeout in seconds (default: `5`) |
| `-I`, `--interface` | Bind probe sockets to a source IP or interface name (default: kernel chooses). Device names use `SO_BINDTODEVICE` on Linux (`CAP_NET_RAW`). Not supported on Windows (warns and ignores). Affects probes only — subscription fetch is unchanged |
| `-v`, `--verbose` | `best` only: log each probe (Testing / OK / FAIL) |
| `-V`, `--version` | Print version |
| `-h`, `--help` | Help |

### Ranking (`best`)

Each candidate is probed **3 times** (fail-fast); the average latency is kept per preference class. Winner selection:

1. Prefer **VLESS²** (REALITY gRPC)
2. Prefer **VLESS³** (REALITY TCP vision) over VLESS² when VLESS² is **>3×** slower
3. Prefer **Shadowsocks** over VLESS² when VLESS² is **≥5×** slower (and vs demoted VLESS³, the **>3×** rule)
4. With VLESS³ but no VLESS²: prefer VLESS³ unless it is **>3×** slower than SS
5. **Trojan** only if no VLESS² / VLESS³ / SS succeeded

### Output (`best`)

- **stderr:** download progress, optional verbose probe lines, summary stats, winner line  
  `Best: 59ms 192.168.11.1 — 🇸🇪 SHADOWSOCKS - Швеция`
- **stdout:** raw winning proxy URI (one line)

### Output (`ping`)

- **stderr:** `OK: …ms host — name` or `FAIL: name (host): hint (error)`
- exit `0` on success, `1` on probe failure

Example:

```bash
fastest=$(hydec best -v "$SUB_URL")
# use $fastest with your proxy client
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
