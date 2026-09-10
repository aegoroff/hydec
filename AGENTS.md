# AGENTS.md

Instructions for AI coding agents working in the **hydec** repository.

## Project overview

Non-interactive CLI with subcommands: `best` (subscription → preferred proxy) and `ping` (single proxy probe).

| Item | Value |
|------|-------|
| Language | Zig **0.16.0** (see `mise.toml`) |
| CLI parsing | [zig-cli](https://github.com/zig-utils/zig-cli) |
| License | MIT |
| Default version | `0.1.0-dev` (`-Dversion=...` / `build_options.version`) |

**Supported probes**

| Protocol | Notes |
|----------|--------|
| Shadowsocks | AEAD methods |
| Trojan | TLS; WebSocket transport |
| VLESS | REALITY only; TCP vision (`xtls-rprx-vision`, inner HTTPS) and gRPC gun |
| VMess | Skipped (counted in stats) |

**Behavior (`best`)**

1. Fetch subscription URL (**HTTPS only**; plaintext schemes → `InsecureSubscriptionUrl`). Redirects are followed only while the resolved target stays HTTPS; `http://` hops are rejected. Scheme is normalized to lowercase for `std.http.Client`.
2. Base64-decode body; iterate URI lines.
3. Group proxies by `host` (IP); probe **different hosts in parallel**, **same host sequentially**.
4. Each candidate: **3 probes**, fail-fast on first error; keep **average** latency per preference class.
5. Rank with `selectBestClass` according to `--strategy` (`hydec` default, `fastest`, `strict`). `hydec`: prefer VLESS² (gRPC) → VLESS³ (TCP) → SS → Trojan. Demote VLESS²→VLESS³ when VLESS² is **>2×** slower; VLESS²→SS when **≥3×** (then keep VLESS³ unless it is **>3×** slower than SS); with no VLESS², demote VLESS³→SS when **>2×** slower. Trojan only if no VLESS² / VLESS³ / SS succeeded. `fastest`: lowest latency (tie → higher class). `strict`: never demote.
6. Log winner to **stderr** (`Best: …ms host — name`), then print the raw winning URI to **stdout**. Progress / verbose / errors also go to **stderr** via `std.log`.

**Behavior (`ping`)**

1. Parse one proxy URI from the CLI.
2. Probe it **3 times** (stop on first failure); log `OK: …` or `FAIL: …` to **stderr**.
3. Exit `0` on success, `1` on probe failure.

**`--interface` / `-I`**

Optional bind spec for **probe** sockets only (subscription fetch unchanged):

| Spec | Behavior |
|------|----------|
| IP literal | `bind(src_ip, port 0)` before connect (unprivileged) |
| Interface name | Linux `SO_BINDTODEVICE` (needs `CAP_NET_RAW` / root) |
| Empty string | Rejected (`EmptyInterfaceName`) |
| Windows | Timed connect bind path is TODO; non-null `-I` logs a warning and is ignored |

## Layout

| Path | Role |
|------|------|
| `src/main.zig` | Entry, orchestration |
| `src/cli.zig` | Commands: `best <URI>`, `ping <PROXY>`; `-t/--timeout`, `-I/--interface`, `-v/--verbose` (`best`), `--strategy` (`best`; default `hydec`), `-V/--version` |
| `src/fetch.zig` | Download subscription (HTTPS-only gate) |
| `src/subscription.zig` | Base64 decode, line iteration |
| `src/proxy_uri.zig` | URI parse (kind, host/port, query, `#name`) |
| `src/probe.zig` | Group-by-host parallel `findBest`, preference ranking, `probeOne` / `probeAverage` |
| `src/ss.zig` / `trojan.zig` / `reality.zig` | Protocol probes |
| `src/vless.zig` / `grpc_gun.zig` / `ws.zig` | Framing helpers |
| `src/netutil.zig` | Timed connect, optional source bind, poll deadlines, TLS watchdog |
| `src/util.zig` | Shared helpers (URL decode, query params, …) |

## Build and run

Use **mise** for Zig 0.16.0, or install it manually.

```bash
zig build
zig build test

# Probe a subscription (best) or a single proxy (ping)
zig build run -- best "https://example.com/sub"
zig build run -- ping 'ss://...'

# Cross-compile example
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
```

Via **just** (mise-wrapped Zig):

```bash
just build                                                      # ReleaseFast, x86_64-linux-musl, core2
just test
just arch=x86_64 os=linux abi=musl ver=0.1.0 cpu=core2 release
just ver=0.1.0 build-all                                        # all release targets + archives
```

Binary: `zig-out/bin/hydec` (or `--prefix-exe-dir`).

**Linux-gnu note:** `build.zig` pins glibc to **2.38** so Zig links its bundled CRT. Do not drop that pin without understanding the `.sframe` / system `crt1.o` issue documented in `build.zig`.

## Zig conventions for this repo

- **Minimize scope.** Small, focused diffs. No drive-by refactors.
- **Match existing style.** Follow patterns in `src/*.zig` for naming, errors, and allocators.
- **Use std library first.** Avoid new dependencies without discussion.
- **I/O.** Zig 0.16 `std.Io` (`init.io`, `std.Io.File`, `std.Io.Clock`, `std.Io.Writer`, `Io.Mutex`). Do not revert to pre-0.16 APIs.
- **Networking.** Prefer `netutil` helpers for connect/timeouts/bind. IP connects use non-blocking + `poll` (Zig `IpAddress.connect` timeout is still TODO on Linux). Thread optional `-I` bind through `connectHostPort` → `connectIpUntil` / `applyBind`. Blocking `std.crypto.tls` needs `DeadlineShutdown`, not only poll.
- **Concurrency.** Parallelism is **by host** in `probe.zig` (`std.Thread` + `Io.Mutex`). Do not probe the same IP concurrently.
- **Comments.** Only for non-obvious logic.
- **Tests.** `test` blocks in the same file as the code. Run `zig build test` before finishing.
- **Format.** `zig fmt` on changed Zig files before finishing.

## Code style

- Zig stdlib conventions: `snake_case` functions/vars; `PascalCase` types; `SCREAMING_SNAKE_CASE` constants
- Explicit `!` error returns; keep functions focused
- Allocator parameter name: `gpa`
- In `main`, use `init.gpa` / `init.io` from `std.process.Init`

## Development rules

### Before making changes

1. Read existing code for patterns
2. Check tests near the code you touch
3. Keep CLI compatible unless the task changes it

### When writing code

1. Idiomatic Zig / std patterns
2. Handle errors explicitly — no silent failures
3. Add tests for new logic (AAA)
4. Keep backward compatibility when possible

### When fixing bugs

1. Find root cause before fixing
2. Add a regression test if missing
3. Check similar code paths (SS / Trojan / VLESS / gRPC)
4. Confirm `zig build test` still passes

## Testing

```bash
zig build test
```

Prefer focused unit tests (URI parse, framing, grouping). Live subscription probes are manual smoke checks, not default CI.

`just release` runs tests only for **x86_64-linux** targets. Ensure tests pass there.

## Releases

- Version via `-Dversion=...` (default `0.1.0-dev`).
- Multi-target archives: `just ver=0.1.0 build-all` (see `justfile`).
- CI / tagged releases: `.forgejo/workflows/ci.yaml` (Forgejo; `just build-all` + OpenWrt apk on push/PR/tag). No GitHub Actions workflow or git-cliff config in-repo.

## Commit and PR guidelines

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: probe distinct IPs in parallel
fix: respect Trojan TLS timeout via socket shutdown
chore: correct project overview in AGENTS.md
build: zig 0.16
```

- Do **not** commit unless explicitly asked.
- Do **not** push or force-push without explicit request.
- Keep PRs focused; verify with `zig build test` and a manual `hydec best -v <subscription-url>` smoke run when networking changed.

## Security

- Never commit secrets, tokens, or credentials.
- Subscription URIs and proxy lines often embed passwords/UUIDs — avoid logging full URIs; prefer host/port and decoded `#fragment` name (as in `probe.zig` verbose output).
- Treat user-supplied URLs carefully when fetching; never allow non-HTTPS subscription downloads or redirects to plaintext HTTP.
- Interface-name binds require elevated privileges on Linux; do not weaken that requirement in docs or code comments.

## What agents should avoid

- Large frameworks or abstractions for one-off logic.
- Copying entire files into rules/docs — reference paths instead.
- Changing `build.zig.zon` dependency hashes without fetching and verifying the package.
- Breaking cross-compile targets listed in `justfile` `build-all` without updating that recipe.
- Editing `README.md` or this file unless the task asks for documentation updates.
- Probing multiple protocols on the **same host** in parallel (overloads one endpoint; current design is sequential per IP).
- Reintroducing untimed blocking connects/reads where `netutil` deadlines already apply.

## Verification checklist

1. `zig build` succeeds.
2. `zig build test` passes.
3. Changed Zig sources are `zig fmt`'d.
4. No new compiler warnings in ReleaseFast (just/CI default).
