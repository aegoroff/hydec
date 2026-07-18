# hydec

Non-interactive CLI that downloads a base64-encoded proxy subscription, probes working nodes, and prints the fastest one.

Requires **Zig 0.16.0** ([mise](https://mise.jdx.dev/) pin in `mise.toml`, or install manually).

## Features

- Fetches an HTTPS subscription URL and base64-decodes URI lines
- Probes **Shadowsocks** (AEAD), **Trojan** (TLS / WebSocket), **VLESS REALITY** (TCP vision and gRPC gun)
- Skips VMess (counted in stats)
- Groups by host/IP: different IPs in parallel, same IP sequentially
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
hydec ping 'ss://...#remark'
hydec ping -t 10 'vless://...'
```

| Command | Description |
|---------|-------------|
| `best <URI>` | Download subscription, probe nodes, print fastest URI |
| `ping <PROXY>` | Probe a single proxy URI; exit `1` on failure |

| Flag | Description |
|------|-------------|
| `-t`, `--timeout` | Per-operation timeout in seconds (default: `5`) |
| `-v`, `--verbose` | `best` only: log each probe (Testing / OK / FAIL) |
| `-V`, `--version` | Print version |
| `-h`, `--help` | Help |

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
