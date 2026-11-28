# hydec

Non-interactive CLI that downloads a base64-encoded proxy subscription, probes working nodes, and prints the preferred working one (protocol preference, then latency).

Requires **Zig 0.17.1** ([mise](https://mise.jdx.dev/) pin in `mise.toml`, or install manually).

## Features

- Fetches an **HTTPS-only** subscription URL (HTTP redirects rejected) and base64-decodes URI lines
- Probes **Shadowsocks** (AEAD), **Trojan** (TLS / WebSocket), **VLESS REALITY** (TCP Vision, gRPC gun, XHTTP `stream-one` over HTTP/2), and **Hysteria 2** (QUIC, `hysteria2://` and `hy2://`)
- Skips VMess (counted in stats)
- Groups by host/IP: different IPs in parallel, same IP sequentially
- Ranks by **protocol preference** (VLESS gRPC / Trojan / Hysteria 2 → VLESS TCP Vision / XHTTP → SS), with 2× / 3× demotion thresholds and a minimum latency gap. Override with `--strategy fastest` or `strict`
- Optional `--prefer-stable` ranks by the worst probe and puts candidates that needed a retry last
- Optional `--check-volume` downloads 40 KB through each tunnel to catch nodes that DPI freezes after the first ~16 KB
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
hydec best --strategy fastest https://example.com/sub
hydec best --raw https://example.com/sub
hydec best --prefer-stable --check-volume -t 3 https://example.com/sub
hydec ping 'ss://...#remark'
hydec ping -t 10 -I wlan0 'vless://...'
hydec ping --check-volume 'trojan://...'
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
| `--strategy` | `best` only: ranking policy (`hydec`, `fastest`, `strict`). Default: `hydec` |
| `--prefer-stable` | `best` only: rank by the worst of the 3 probes instead of the median; a candidate that needed a retry loses to every candidate that did not (see below) |
| `--check-volume` | `best` and `ping`: after the latency probes, download 40 KB through the tunnel once; a stall fails the proxy (`volume/stalled`) |
| `--raw` | `best` only. Print the original winning URI with its hostname and query intact |
| `-V`, `--version` | Print version |
| `-h`, `--help` | Help |

Hysteria 2 probes support plain QUIC. The `obfs` parameter may be omitted, empty, or set to `plain`. A `pinSHA256` fingerprint may use uppercase or lowercase hexadecimal, with optional `:` or `-` separators.

### Ranking (`best`)

Each candidate is probed **3 times**; one timeout or dropped connection is retried once, any other failure drops the candidate. The median latency is kept per preference class. Every entry is probed on its own: failures on one IP never skip the other entries on it. Latency is the full attempt time: connect, TLS / REALITY handshake (and WebSocket upgrade) and the test requests through the tunnel. For WebSocket, ALPN is negotiated in that same TLS handshake; a server selecting h2 fails because the following HTTP/1.1 upgrade would be invalid. A link without `alpn=` offers `http/1.1` only, as Xray and sing-box (podkop) do for ws. `--strategy` picks the winner:

| Strategy | Behavior |
|----------|----------|
| `hydec` (default) | VLESS², Trojan, and Hysteria 2 share the top tier, followed by VLESS³ and SS, with 2× / 3× demotion |
| `fastest` | Compare nodes across all protocol classes using the 10% median window |
| `strict` | Use the first successful class in VLESS² → Trojan → Hysteria 2 → VLESS³ → SS |

By default, candidates with median latency at most **10%** above the lowest eligible median are compared by the arithmetic mean of their three successful probes. Ties go to the lower median, then to VLESS² → Trojan → VLESS³ → SS → Hysteria 2. The window covers all classes with `fastest`, the winning tier with `hydec`, or the winning class with `strict`.

`hydec` winner selection:

1. Start with the **VLESS²** (REALITY gRPC), **Trojan**, and **Hysteria 2** tier. Use its lowest median for the demotion rules below.
2. Prefer **VLESS³** (REALITY TCP Vision and XHTTP) when the top tier's median is **>2×** its median.
3. **Shadowsocks** becomes eligible when the top tier's median is **≥3×** the SS median. If VLESS³ is also available, keep VLESS³ unless it is **>3×** slower than SS.
4. If the top tier has no successful probes, prefer VLESS³ unless it is **>2×** slower than SS.
5. If only SS succeeds, choose SS.

Every demotion in 2–4 also requires the slower class to be more than **15 ms** behind, so jitter between nearby nodes (e.g. 21 ms vs 7 ms) does not change the winner.

#### `--prefer-stable`

The strategy compares each class by its **worst** probe, so a node at 40 / 42 / 300 ms loses to one at 45 / 46 / 47 ms within the same class. Candidates that passed without a retry rank first. A class whose best needed a retry takes part only when every class needed a retry.

Among eligible candidates tied on the winning retry status and worst probe, those within **10%** of the lowest median among them are compared by mean latency (then lower median, then protocol preference). The `Best:` line shows the median, and `-v` marks retried probes (for example, `OK: 42ms (min 40, max 300, retry 1) …`).

#### `--check-volume`

The latency probes move only a few hundred bytes, so a node whose sessions DPI freezes after the first ~16–20 KB still passes them. With this flag, each candidate that passed gets one more attempt: the tunnel is opened to `speed.cloudflare.com` (`cp.cloudflare.com` cannot serve the download), the usual `/cdn-cgi/trace` warmup runs, and `/__down?bytes=40000` follows on the same connection. The proxy passes only on a `200` with exactly 40000 body bytes. This attempt is not part of the latency, has its own `-t`, and is never retried; a timeout after the connection is established is reported as `volume/stalled` (`error.VolumeStalled`), while a connect timeout remains `slow/timeout` (`error.ConnectTimeout`). If Cloudflare answers the download with another status (e.g. `429` or `403`), the check is skipped for that proxy with a warning instead of failing it only when the warmup already crossed the tunnel. VLESS TCP has no warmup, so a non-200 download response fails its check. On healthy nodes the check adds about one probe per candidate; each stalled node costs a full `-t`.

### Output (`best`)

- **stderr:** download progress, optional verbose probe lines, summary stats, winner line  
  `Best: 59ms 192.168.11.1 — 🇸🇪 SHADOWSOCKS - Швеция`
- **stdout** contains one winning proxy URI. When possible, `best` replaces the hostname with the IP address reached by the probe. It preserves the fragment and query parameters. For Trojan, VLESS REALITY and Hysteria 2, it adds `sni=<original hostname>` if `sni` was missing or empty. With `--raw`, or when IP substitution is unavailable, it prints the original URI.

### Output (`ping`)

- **stderr:** `OK: …ms host — name` or `FAIL: name (host): hint (error)` (`volume/stalled` with `--check-volume`)
- exit `0` on success, `1` on probe failure

Example:

```bash
fastest=$(hydec best -v "$SUB_URL")
# use $fastest with your proxy client
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
