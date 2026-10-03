const std = @import("std");
const proxy_uri = @import("proxy_uri.zig");
const util = @import("util.zig");
const ss = @import("ss.zig");
const trojan = @import("trojan.zig");
const alpn = @import("alpn.zig");
const reality = @import("reality.zig");
const Io = std.Io;

const Result = struct {
    latency_ms: u64,
    raw: []const u8,
    /// Owned copy of the host; free with `deinit`.
    host: []u8,

    pub fn deinit(self: *Result, gpa: std.mem.Allocator) void {
        gpa.free(self.host);
        self.* = undefined;
    }
};

/// Ranking strategy for `best` (CLI `--strategy`). Default `hydec` is the current tree.
pub const Strategy = enum {
    hydec,
    fastest,
    strict,

    pub fn parse(s: []const u8) ?Strategy {
        return std.meta.stringToEnum(Strategy, s);
    }
};

/// Preference class for `best` ranking (higher = preferred when latencies are comparable).
/// VLESS² = REALITY gRPC; VLESS³ = REALITY TCP vision — matching HyNet subscription labels.
pub const PrefClass = enum {
    trojan,
    shadowsocks,
    vless3,
    vless2,

    pub fn fromProxy(proxy: proxy_uri.Proxy) ?PrefClass {
        return switch (proxy.kind) {
            .vless => switch (proxy.transport) {
                .grpc => .vless2,
                .tcp => .vless3,
                else => null,
            },
            .shadowsocks => .shadowsocks,
            .trojan => .trojan,
            else => null,
        };
    }
};

pub const Stats = struct {
    tested: usize = 0,
    passed: usize = 0,
    skipped_vmess: usize = 0,
    skipped_other: usize = 0,
    parse_failed: usize = 0,
    /// Entries not probed because an earlier entry on the same host could not even connect.
    skipped_dead_host: usize = 0,
};

const WorkItem = struct {
    raw: []const u8,
    proxy: proxy_uri.Proxy,
};

/// Cap concurrent host workers so a large subscription cannot exhaust OS threads.
const MAX_PARALLEL_HOSTS: usize = 64;

const Shared = struct {
    gpa: std.mem.Allocator,
    io: Io,
    verbose: bool,
    timeout_secs: u32,
    /// Optional interface/source-IP spec forwarded to `connectHostPort` (`null` = default).
    bind: ?[]const u8,
    mutex: Io.Mutex = .init,
    /// Fastest successful probe per preference class.
    best: std.EnumArray(PrefClass, ?Result) = .initFill(null),
    /// Set when a successful probe could not be recorded as best (host dupe OOM).
    best_oom: bool = false,
    stats: *Stats,

    fn lock(self: *Shared) void {
        self.mutex.lockUncancelable(self.io);
    }

    fn unlock(self: *Shared) void {
        self.mutex.unlock(self.io);
    }

    fn deinitBests(self: *Shared) void {
        for (std.enums.values(PrefClass)) |class| {
            if (self.best.getPtr(class).*) |*r| r.deinit(self.gpa);
            self.best.set(class, null);
        }
    }
};

/// How many successful probes are required for `ping` / `best` (see `TRANSIENT_RETRIES`).
pub const PROBE_ATTEMPTS: usize = 3;

pub fn probeOne(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    timeout_secs: u32,
    bind: ?[]const u8,
) !u64 {
    return switch (proxy.kind) {
        .shadowsocks => blk: {
            const method = proxy.method orelse return error.InvalidProxyUri;
            const password = proxy.password orelse return error.InvalidProxyUri;
            break :blk try ss.probe(gpa, io, proxy.host, proxy.port, method, password, timeout_secs, bind);
        },
        .trojan => blk: {
            const sni_owned = try proxy.getParamDecoded(gpa, "sni");
            defer if (sni_owned) |s| gpa.free(s);
            const sni = sni_owned orelse proxy.host;
            const path_owned = try proxy.getParamDecoded(gpa, "path");
            defer if (path_owned) |p| gpa.free(p);
            const path = path_owned orelse "/";
            const host_owned = try proxy.getParamDecoded(gpa, "host");
            defer if (host_owned) |h| gpa.free(h);
            const host_hdr = host_owned orelse sni;
            const alpn_owned = try proxy.getParamDecoded(gpa, "alpn");
            defer if (alpn_owned) |a| gpa.free(a);
            var alpn_storage: [alpn.MAX_PROTOCOLS][]const u8 = undefined;
            const alpn_list = try alpn.parseList(alpn_owned, &alpn_storage, proxy.transport == .ws);
            const allow_insecure = util.queryParamTruthy(proxy.query, "allowInsecure") or
                util.queryParamTruthy(proxy.query, "allow_insecure") or
                util.queryParamTruthy(proxy.query, "insecure");
            break :blk try trojan.probe(gpa, io, proxy.host, proxy.port, .{
                .password = proxy.userinfo,
                .sni = sni,
                .transport_ws = proxy.transport == .ws,
                .ws_path = path,
                .ws_host = host_hdr,
                .alpn = alpn_list,
                .allow_insecure = allow_insecure,
            }, timeout_secs, bind);
        },
        .vless => blk: {
            if (proxy.security != .reality) return error.UnsupportedSecurity;
            if (proxy.transport == .other) return error.UnsupportedTransport;
            if (proxy.transport == .ws) return error.UnsupportedTransport;

            const enc_owned = try proxy.getParamDecoded(gpa, "encryption");
            defer if (enc_owned) |e| gpa.free(e);
            const enc = enc_owned orelse "none";
            if (enc.len != 0 and !std.mem.eql(u8, enc, "none")) return error.UnsupportedVlessEncryption;

            const sni_owned = try proxy.getParamDecoded(gpa, "sni");
            defer if (sni_owned) |s| gpa.free(s);
            const sni = sni_owned orelse proxy.host;
            const pbk = (try proxy.getParamDecoded(gpa, "pbk")) orelse return error.MissingRealityPublicKey;
            defer gpa.free(pbk);
            const sid_owned = try proxy.getParamDecoded(gpa, "sid");
            defer if (sid_owned) |s| gpa.free(s);
            const sid = sid_owned orelse "";
            const flow_owned = try proxy.getParamDecoded(gpa, "flow");
            defer if (flow_owned) |f| gpa.free(f);
            const flow = flow_owned orelse "";
            const service_owned = try proxy.getParamDecoded(gpa, "serviceName");
            defer if (service_owned) |s| gpa.free(s);
            const service = service_owned orelse "";
            const use_grpc = proxy.transport == .grpc;
            if (use_grpc) {
                const mode_owned = try proxy.getParamDecoded(gpa, "mode");
                defer if (mode_owned) |m| gpa.free(m);
                const mode = mode_owned orelse "gun";
                if (!std.mem.eql(u8, mode, "gun") and mode.len != 0) return error.UnsupportedGrpcMode;
            }
            const authority_owned = try proxy.getParamDecoded(gpa, "authority");
            defer if (authority_owned) |a| gpa.free(a);
            const authority = authority_owned orelse "";
            break :blk try reality.probeVless(
                io,
                proxy.host,
                proxy.port,
                proxy.userinfo,
                sni,
                pbk,
                sid,
                flow,
                use_grpc,
                service,
                authority,
                timeout_secs,
                bind,
            );
        },
        .vmess => error.SkippedVmess,
        .unsupported => error.UnsupportedProtocol,
    };
}

/// How many failed attempts per candidate may be retried, and only when `isTransient`.
pub const TRANSIENT_RETRIES: usize = 1;

/// Summary of one candidate's samples. `median_ms` ranks; min/max are for `-v` output.
pub const Latency = struct {
    median_ms: u64,
    min_ms: u64,
    max_ms: u64,

    /// `samples` must be non-empty; sorts it in place. Upper median for an even count,
    /// so a single latency spike among three samples does not move the result.
    pub fn fromSamples(samples: []u64) Latency {
        std.debug.assert(samples.len > 0);
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        return .{
            .median_ms = samples[samples.len / 2],
            .min_ms = samples[0],
            .max_ms = samples[samples.len - 1],
        };
    }
};

/// Failures a repeat attempt may plausibly not hit again (packet loss, a dropped
/// connection). Handshake, auth, response-mismatch and DNS errors are deterministic
/// for a given URI, so they still fail the candidate on the first occurrence.
pub fn isTransient(err: anyerror) bool {
    return switch (err) {
        error.Timeout,
        error.ConnectTimeout,
        error.ConnectionTimedOut,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.UnexpectedEndOfStream,
        error.BrokenPipe,
        error.TlsConnectionTruncated,
        => true,
        else => false,
    };
}

/// Fill `samples` from `prober.probe()`; fail on the first non-transient error or once
/// `TRANSIENT_RETRIES` is used up.
fn collectSamples(prober: anytype, samples: []u64) !void {
    var retries_left = TRANSIENT_RETRIES;
    for (samples) |*slot| {
        slot.* = while (true) {
            break prober.probe() catch |err| {
                if (retries_left == 0 or !isTransient(err)) return err;
                retries_left -= 1;
                std.log.debug("retrying after transient error: {t}", .{err});
                continue;
            };
        };
    }
}

/// Run `PROBE_ATTEMPTS` full probes (one retry on a transient error).
/// On success returns the median latency and the sample spread.
pub fn probeLatency(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    timeout_secs: u32,
    bind: ?[]const u8,
) !Latency {
    const Prober = struct {
        gpa: std.mem.Allocator,
        io: Io,
        proxy: proxy_uri.Proxy,
        timeout_secs: u32,
        bind: ?[]const u8,

        fn probe(self: @This()) !u64 {
            return probeOne(self.gpa, self.io, self.proxy, self.timeout_secs, self.bind);
        }
    };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;
    try collectSamples(Prober{ .gpa = gpa, .io = io, .proxy = proxy, .timeout_secs = timeout_secs, .bind = bind }, &samples);
    return Latency.fromSamples(&samples);
}

/// Pick the winning preference class from per-class fastest latencies.
pub fn selectBestClass(
    strategy: Strategy,
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
) ?PrefClass {
    return switch (strategy) {
        .hydec => selectHydecClass(vless2_ms, vless3_ms, ss_ms, trojan_ms),
        .fastest => selectFastestClass(vless2_ms, vless3_ms, ss_ms, trojan_ms),
        .strict => selectStrictClass(vless2_ms, vless3_ms, ss_ms, trojan_ms),
    };
}

/// Absolute latency gap (ms) a `hydec` demotion requires on top of its ratio:
/// 21 ms vs 7 ms is 3× but only noise.
pub const MIN_DEMOTE_GAP_MS: u64 = 15;

/// `slow` loses to `fast` by more than `MIN_DEMOTE_GAP_MS`.
fn clearlySlower(slow: u64, fast: u64) bool {
    return slow -| fast > MIN_DEMOTE_GAP_MS;
}

/// Default `hydec` policy. SS and Trojan form one tier ("SS/Trojan" below): the faster
/// of the two stands for it, SS on a tie.
/// 1. Prefer fastest VLESS² (gRPC).
/// 2. Prefer VLESS³ over VLESS² when VLESS² is strictly more than 2× slower.
/// 3. Prefer SS/Trojan over VLESS² only when there is no VLESS², or VLESS² is ≥3× slower.
///    When SS/Trojan is eligible and VLESS³ exists, prefer VLESS³ unless it is >3× slower
///    than SS/Trojan (even if VLESS² was not demoted to VLESS³).
/// 4. With VLESS³ but no VLESS²: prefer VLESS³ unless it is strictly more than 2× slower
///    than SS/Trojan.
/// Every demotion in 2–4 also needs the slower class to lose by more than
/// `MIN_DEMOTE_GAP_MS`, so jitter between near-local nodes cannot flip the pick.
fn selectHydecClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
) ?PrefClass {
    const tier: ?struct { class: PrefClass, ms: u64 } = blk: {
        const ss_lat = ss_ms orelse break :blk if (trojan_ms) |t| .{ .class = .trojan, .ms = t } else null;
        const t = trojan_ms orelse break :blk .{ .class = .shadowsocks, .ms = ss_lat };
        break :blk if (t < ss_lat) .{ .class = .trojan, .ms = t } else .{ .class = .shadowsocks, .ms = ss_lat };
    };

    if (vless2_ms) |v2| {
        var class: PrefClass = .vless2;
        if (vless3_ms) |v3| {
            if (v2 > v3 *| 2 and clearlySlower(v2, v3)) {
                class = .vless3;
            }
        }
        if (tier) |low| {
            if (v2 >= low.ms *| 3 and clearlySlower(v2, low.ms)) {
                // SS/Trojan eligible vs VLESS²: prefer VLESS³ unless it is >3× slower.
                if (vless3_ms) |v3| {
                    if (v3 > low.ms *| 3 and clearlySlower(v3, low.ms)) return low.class;
                    return .vless3;
                }
                return low.class;
            }
        }
        return class;
    }

    if (vless3_ms) |v3| {
        if (tier) |low| {
            if (v3 > low.ms *| 2 and clearlySlower(v3, low.ms)) return low.class;
        }
        return .vless3;
    }

    return if (tier) |low| low.class else null;
}

/// Minimum latency; on a tie keep the higher preference class (VLESS² → … → Trojan).
fn selectFastestClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
) ?PrefClass {
    const candidates = [_]struct { class: PrefClass, ms: ?u64 }{
        .{ .class = .vless2, .ms = vless2_ms },
        .{ .class = .vless3, .ms = vless3_ms },
        .{ .class = .shadowsocks, .ms = ss_ms },
        .{ .class = .trojan, .ms = trojan_ms },
    };
    var best_class: ?PrefClass = null;
    var best_ms: u64 = undefined;
    for (candidates) |c| {
        const ms = c.ms orelse continue;
        if (best_class == null or ms < best_ms) {
            best_class = c.class;
            best_ms = ms;
        }
    }
    return best_class;
}

/// Never demote: first class that succeeded in preference order.
fn selectStrictClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
) ?PrefClass {
    if (vless2_ms != null) return .vless2;
    if (vless3_ms != null) return .vless3;
    if (ss_ms != null) return .shadowsocks;
    if (trojan_ms != null) return .trojan;
    return null;
}

fn considerBest(shared: *Shared, class: PrefClass, latency: u64, raw: []const u8, host: []const u8) void {
    // Dupe outside the lock so host workers do not serialize on allocation.
    const host_copy = shared.gpa.dupe(u8, host) catch {
        shared.lock();
        defer shared.unlock();
        shared.best_oom = true;
        return;
    };

    shared.lock();
    const slot = shared.best.getPtr(class);
    if (slot.*) |cur| {
        if (latency >= cur.latency_ms) {
            shared.unlock();
            shared.gpa.free(host_copy);
            return;
        }
    }
    // Own a copy: proxy.deinit may free legacy-SS hosts before the caller reads Result.
    const prev_host: ?[]u8 = if (slot.*) |old| old.host else null;
    slot.* = .{
        .latency_ms = latency,
        .raw = raw,
        .host = host_copy,
    };
    shared.unlock();
    if (prev_host) |h| shared.gpa.free(h);
}

/// `" — name"` when the proxy is named, otherwise nothing.
pub const NameSuffix = struct {
    name: ?[]const u8,

    pub fn format(self: NameSuffix, w: *Io.Writer) Io.Writer.Error!void {
        if (self.name) |n| try w.print(" — {s}", .{n});
    }
};

/// `name (host)` when the proxy is named, otherwise bare `host`.
pub const HostIdent = struct {
    name: ?[]const u8,
    host: []const u8,

    pub fn format(self: HostIdent, w: *Io.Writer) Io.Writer.Error!void {
        if (self.name) |n| {
            try w.print("{s} ({s})", .{ n, self.host });
        } else {
            try w.print("{s}", .{self.host});
        }
    }
};

/// Short hint for FAIL logs (why the probe likely failed).
pub fn failHint(err: anyerror) []const u8 {
    return switch (err) {
        error.Timeout, error.ConnectTimeout, error.ConnectionTimedOut => "slow/timeout",
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.UnexpectedEndOfStream,
        error.BrokenPipe,
        error.TlsConnectionTruncated,
        error.SocketUnconnected,
        => "rejected/closed",
        // REALITY/TLS alert — rejected ClientHello (wrong pbk/sid/sni/client ver) or dest fallback.
        error.TlsAlert, error.TlsUnexpectedMessage, error.TlsFinishedVerifyFailed => "handshake/alert",
        error.CertificateBundleLoadFailure => "tls/cert",
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.NetworkDown,
        => "unreachable",
        error.GrpcEmptyResponse => "empty/no-data",
        // Server picked h2 for a ws transport: the HTTP/1.1 upgrade gets HTTP/2 frames.
        error.WsAlpnHttp2 => "alpn/h2-breaks-ws",
        // The URI listed more ALPN protocols than a probe will carry.
        error.TooManyAlpnProtocols => "alpn/too-many",
        error.ProbeResponseMismatch => "bad/response",
        error.ExpectedVisionPadding => "vision/framing",
        error.InvalidSsChunk => "ss/chunk",
        error.UnsupportedVlessEncryption => "unsupported-encryption",
        error.BufferTooSmall, error.RecordTooLarge => "buffer/overflow",
        error.SystemResources => "sys/resources",
        // Socket creation / bind failures: netutil.openSocket for our own probe
        // sockets, std's Io.net.IpAddress.BindError for the resolver's. Split from
        // sys/resources because the operator fix differs — raise the fd limit, or cut
        // MAX_PARALLEL_HOSTS, rather than free memory.
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => "sys/fd-limit",
        // Ephemeral source ports exhausted (bind with port 0 finding none free).
        error.AddressInUse => "addr/in-use",
        // The platform or Io implementation cannot do what the probe asked for; a
        // build/target problem, not a network one.
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        error.SocketModeUnsupported,
        error.OptionUnsupported,
        => "sys/unsupported",
        // Hostname resolution (netutil.connectHostnameTimed). Split three ways because
        // the fixes differ: a dead subscription entry, a broken local resolver, and a
        // hostname the URI got wrong.
        error.UnknownHostName, error.NoAddressReturned => "dns/no-address",
        error.NameServerFailure,
        error.ResolvConfParseFailed,
        error.DetectingNetworkConfigurationFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        => "dns/failure",
        error.InvalidHostName, error.NameTooLong => "dns/bad-name",
        // --interface binding failures (interface name / source IP).
        error.NoSuchInterface => "iface/missing",
        error.EmptyInterfaceName => "iface/empty",
        error.InterfaceBindingUnsupported => "iface/unsupported",
        error.InterfaceNameTooLong => "iface/toolong",
        // Two spellings of "not a local address / nonexistent interface": our own
        // bindSrcIp maps ADDRNOTAVAIL to the first, std's Io.net.IpAddress.BindError
        // uses the second (reached via the resolver's own socket, and the Windows
        // connect paths in netutil).
        error.AddressNotAvailable, error.AddressUnavailable => "iface/addr",
        error.AccessDenied => "denied",
        error.AddressFamilyUnsupported => "family",
        // Opaque Io wrappers — Reality/Vision should unwrap socket causes first.
        error.WriteFailed => "write/failed",
        error.ReadFailed => "read/failed",
        else => "error",
    };
}

/// Decides when a host's remaining entries are not worth probing.
///
/// Only a timed-out TCP connect counts: a timeout after connecting can be specific to
/// one port or protocol (a REALITY dest fallback that hangs while SS on the same IP
/// works). Even a connect timeout can be one throttled port on a live host, so the
/// host is dead only after it on two different ports, with no entry having connected.
const DeadHost = struct {
    timed_out_port: ?u16 = null,
    /// Some entry got past the TCP connect (passed, or failed later).
    alive: bool = false,

    /// Record one candidate's outcome (`null` = passed); true once the host is dead.
    fn record(self: *DeadHost, port: u16, err: ?anyerror) bool {
        const e = err orelse {
            self.alive = true;
            return false;
        };
        if (e != error.ConnectTimeout) {
            self.alive = true;
            return false;
        }
        if (self.alive) return false;
        if (self.timed_out_port) |p| return p != port;
        self.timed_out_port = port;
        return false;
    }
};

fn probeGroup(shared: *Shared, items: []WorkItem) void {
    var dead_host: DeadHost = .{};
    for (items, 0..) |*item, i| {
        const proxy = item.proxy;

        {
            shared.lock();
            shared.stats.tested += 1;
            shared.unlock();
        }

        if (shared.verbose) {
            if (proxy.name) |n| {
                std.log.debug("Testing: {s} ({s}:{d})", .{ n, proxy.host, proxy.port });
            } else {
                std.log.debug("Testing: {s}:{d}", .{ proxy.host, proxy.port });
            }
        }

        // Three probes (one transient retry); ranking uses their median.
        const latency = probeLatency(shared.gpa, shared.io, proxy, shared.timeout_secs, shared.bind) catch |err| {
            if (shared.verbose) {
                std.log.warn("FAIL: {f}: {s} ({})", .{ HostIdent{ .name = proxy.name, .host = proxy.host }, failHint(err), err });
            }
            if (dead_host.record(proxy.port, err)) {
                skipDeadHost(shared, items[i + 1 ..]);
                return;
            }
            continue;
        };
        _ = dead_host.record(proxy.port, null);

        {
            shared.lock();
            shared.stats.passed += 1;
            shared.unlock();
        }

        if (shared.verbose) {
            std.log.info("OK: {d}ms (min {d}, max {d}) {s}{f}", .{ latency.median_ms, latency.min_ms, latency.max_ms, proxy.host, NameSuffix{ .name = proxy.name } });
        }

        const class = PrefClass.fromProxy(proxy) orelse continue;
        considerBest(shared, class, latency.median_ms, item.raw, proxy.host);
    }
}

fn skipDeadHost(shared: *Shared, rest: []const WorkItem) void {
    if (rest.len == 0) return;
    {
        shared.lock();
        shared.stats.skipped_dead_host += rest.len;
        shared.unlock();
    }
    if (shared.verbose) {
        for (rest) |item| {
            std.log.warn("SKIP: {f}: host did not accept a connection", .{HostIdent{ .name = item.proxy.name, .host = item.proxy.host }});
        }
    }
}

fn freeGroups(gpa: std.mem.Allocator, groups: *std.array_hash_map.String(std.ArrayList(WorkItem))) void {
    for (groups.keys()) |key| {
        gpa.free(key);
    }
    for (groups.values()) |*list| {
        for (list.items) |*item| {
            item.proxy.deinit(gpa);
        }
        list.deinit(gpa);
    }
    groups.deinit(gpa);
}

/// Build host→proxies map. Same host (IP) shares one sequential queue.
fn collectGroups(
    gpa: std.mem.Allocator,
    lines: []const []const u8,
    stats: *Stats,
    verbose: bool,
) !std.array_hash_map.String(std.ArrayList(WorkItem)) {
    var groups: std.array_hash_map.String(std.ArrayList(WorkItem)) = .empty;
    errdefer freeGroups(gpa, &groups);

    for (lines) |line| {
        const kind = proxy_uri.classify(line);
        switch (kind) {
            .vmess => {
                stats.skipped_vmess += 1;
                continue;
            },
            .unsupported => {
                stats.skipped_other += 1;
                continue;
            },
            else => {},
        }

        var proxy = proxy_uri.parse(gpa, line) catch |err| {
            stats.parse_failed += 1;
            if (verbose) std.log.warn("parse fail: {s}: {}", .{ line, err });
            continue;
        };
        errdefer proxy.deinit(gpa);

        // Own map keys: legacy SS hosts are freed in proxy.deinit.
        var host_key: ?[]u8 = try gpa.dupe(u8, proxy.host);
        errdefer if (host_key) |k| gpa.free(k);

        const gop = try groups.getOrPut(gpa, host_key.?);
        if (gop.found_existing) {
            gpa.free(host_key.?);
            host_key = null;
        } else {
            host_key = null; // owned by map
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(gpa, .{
            .raw = line,
            .proxy = proxy,
        });
    }

    return groups;
}

pub fn findBest(
    gpa: std.mem.Allocator,
    io: Io,
    lines: []const []const u8,
    verbose: bool,
    timeout_secs: u32,
    bind: ?[]const u8,
    strategy: Strategy,
    stats: *Stats,
) !?Result {
    var groups = try collectGroups(gpa, lines, stats, verbose);
    defer freeGroups(gpa, &groups);

    if (groups.count() == 0) return null;

    var shared: Shared = .{
        .gpa = gpa,
        .io = io,
        .verbose = verbose,
        .timeout_secs = timeout_secs,
        .bind = bind,
        .stats = stats,
    };
    errdefer shared.deinitBests();

    const lists = groups.values();
    const n = lists.len;
    const threads = try gpa.alloc(std.Thread, @min(n, MAX_PARALLEL_HOSTS));
    defer gpa.free(threads);

    var next: usize = 0;
    while (next < n) {
        const batch = @min(MAX_PARALLEL_HOSTS, n - next);
        var spawned: usize = 0;
        errdefer for (threads[0..spawned]) |t| t.join();

        for (lists[next..][0..batch]) |*list| {
            threads[spawned] = try std.Thread.spawn(.{}, probeGroup, .{ &shared, list.items });
            spawned += 1;
        }

        for (threads[0..spawned]) |t| t.join();
        next += batch;
    }

    const chosen = selectBestClass(
        strategy,
        if (shared.best.get(.vless2)) |r| r.latency_ms else null,
        if (shared.best.get(.vless3)) |r| r.latency_ms else null,
        if (shared.best.get(.shadowsocks)) |r| r.latency_ms else null,
        if (shared.best.get(.trojan)) |r| r.latency_ms else null,
    );

    if (chosen == null) {
        shared.deinitBests();
        if (shared.best_oom) return error.OutOfMemory;
        return null;
    }

    // Take ownership of the winner; free the other class bests.
    const winner = shared.best.get(chosen.?).?;
    shared.best.set(chosen.?, null);
    for (std.enums.values(PrefClass)) |class| {
        if (shared.best.getPtr(class).*) |*r| r.deinit(gpa);
        shared.best.set(class, null);
    }
    return winner;
}

test "OK/FAIL log formatters render both named and unnamed proxies" {
    var buf: [128]u8 = undefined;

    // OK: `best -v` (probe.zig) adds the sample spread; `ping` (main.zig) does not.
    try std.testing.expectEqualStrings(
        "OK: 42ms (min 40, max 300) 1.2.3.4 \u{2014} NL",
        try std.mem.print(&buf, "OK: {d}ms (min {d}, max {d}) {s}{f}", .{ 42, 40, 300, "1.2.3.4", NameSuffix{ .name = "NL" } }),
    );
    try std.testing.expectEqualStrings(
        "OK: 42ms 1.2.3.4 \u{2014} \u{1f1f3}\u{1f1f1} NL",
        try std.mem.print(&buf, "OK: {d}ms {s}{f}", .{ 42, "1.2.3.4", NameSuffix{ .name = "\u{1f1f3}\u{1f1f1} NL" } }),
    );
    try std.testing.expectEqualStrings(
        "OK: 42ms 1.2.3.4",
        try std.mem.print(&buf, "OK: {d}ms {s}{f}", .{ 42, "1.2.3.4", NameSuffix{ .name = null } }),
    );

    // FAIL: same two call sites.
    try std.testing.expectEqualStrings(
        "FAIL: \u{1f1f3}\u{1f1f1} NL (1.2.3.4): slow/timeout",
        try std.mem.print(&buf, "FAIL: {f}: {s}", .{ HostIdent{ .name = "\u{1f1f3}\u{1f1f1} NL", .host = "1.2.3.4" }, failHint(error.Timeout) }),
    );
    try std.testing.expectEqualStrings(
        "FAIL: 1.2.3.4: slow/timeout",
        try std.mem.print(&buf, "FAIL: {f}: {s}", .{ HostIdent{ .name = null, .host = "1.2.3.4" }, failHint(error.Timeout) }),
    );
}

test "Latency.fromSamples: median ignores a single spike, min/max keep it" {
    var spike = [_]u64{ 40, 300, 42 };
    try std.testing.expectEqual(Latency{ .median_ms = 42, .min_ms = 40, .max_ms = 300 }, Latency.fromSamples(&spike));
    var even = [_]u64{ 30, 10, 20, 40 };
    try std.testing.expectEqual(Latency{ .median_ms = 30, .min_ms = 10, .max_ms = 40 }, Latency.fromSamples(&even));
    var one = [_]u64{7};
    try std.testing.expectEqual(Latency{ .median_ms = 7, .min_ms = 7, .max_ms = 7 }, Latency.fromSamples(&one));
}

const FakeProber = struct {
    script: []const anyerror!u64,
    calls: *usize,

    fn probe(self: FakeProber) !u64 {
        const r = self.script[self.calls.*];
        self.calls.* += 1;
        return r;
    }
};

test "collectSamples retries one transient error" {
    // Arrange
    var calls: usize = 0;
    const script = [_]anyerror!u64{ 10, error.Timeout, 20, 30 };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;

    // Act
    try collectSamples(FakeProber{ .script = &script, .calls = &calls }, &samples);

    // Assert
    try std.testing.expectEqual(@as(usize, 4), calls);
    try std.testing.expectEqualSlices(u64, &.{ 10, 20, 30 }, &samples);
}

test "collectSamples fails on a second transient error" {
    var calls: usize = 0;
    const script = [_]anyerror!u64{ error.ConnectionResetByPeer, 10, error.Timeout };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;

    try std.testing.expectError(error.Timeout, collectSamples(FakeProber{ .script = &script, .calls = &calls }, &samples));
    try std.testing.expectEqual(@as(usize, 3), calls);
}

test "collectSamples does not retry deterministic errors" {
    var calls: usize = 0;
    const script = [_]anyerror!u64{ error.TlsAlert, 10, 10, 10 };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;

    try std.testing.expectError(error.TlsAlert, collectSamples(FakeProber{ .script = &script, .calls = &calls }, &samples));
    try std.testing.expectEqual(@as(usize, 1), calls);
}

test "DeadHost needs connect timeouts on two different ports" {
    // Arrange
    var host: DeadHost = .{};

    // Act / Assert: one throttled port (live 84.32.177.169:2058) is not enough.
    try std.testing.expect(!host.record(2058, error.ConnectTimeout));
    try std.testing.expect(!host.record(2058, error.ConnectTimeout));
    try std.testing.expect(host.record(8443, error.ConnectTimeout));
}

test "DeadHost never skips a host that connected once" {
    var passed: DeadHost = .{};
    _ = passed.record(443, null);
    try std.testing.expect(!passed.record(2058, error.ConnectTimeout));
    try std.testing.expect(!passed.record(8443, error.ConnectTimeout));

    // Connected, then stalled: may be one port/protocol only — the host is alive.
    var stalled: DeadHost = .{};
    try std.testing.expect(!stalled.record(443, error.Timeout));
    try std.testing.expect(!stalled.record(2058, error.ConnectTimeout));
    try std.testing.expect(!stalled.record(8443, error.ConnectTimeout));

    try std.testing.expectEqualStrings("slow/timeout", failHint(error.ConnectTimeout));
}

test "isTransient splits network blips from deterministic failures" {
    try std.testing.expect(isTransient(error.Timeout));
    try std.testing.expect(isTransient(error.ConnectTimeout));
    try std.testing.expect(isTransient(error.ConnectionResetByPeer));
    try std.testing.expect(isTransient(error.EndOfStream));
    try std.testing.expect(!isTransient(error.TlsAlert));
    try std.testing.expect(!isTransient(error.ProbeResponseMismatch));
    try std.testing.expect(!isTransient(error.UnknownHostName));
    try std.testing.expect(!isTransient(error.ConnectionRefused));
}

test "collectGroups buckets by host" {
    const gpa = std.testing.allocator;
    // userinfo = base64(chacha20-ietf-poly1305:test-password)
    const lines = [_][]const u8{
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.1:8388#a",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@198.51.100.1:8388#b",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.1:443#c",
    };
    var stats: Stats = .{};
    var groups = try collectGroups(gpa, &lines, &stats, false);
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), groups.count());
    try std.testing.expectEqual(@as(usize, 2), groups.get("192.0.2.1").?.items.len);
    try std.testing.expectEqual(@as(usize, 1), groups.get("198.51.100.1").?.items.len);
}

test "collectGroups owns keys for legacy SS hosts" {
    const gpa = std.testing.allocator;
    // method:password@host:port base64url
    const lines = [_][]const u8{
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3JkQDE5Mi4wLjIuMTo4Mzg4#legacy-a",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3JkQDE5Mi4wLjIuMTo0NDM#legacy-b",
    };
    var stats: Stats = .{};
    var groups = try collectGroups(gpa, &lines, &stats, false);
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 1), groups.count());
    try std.testing.expectEqual(@as(usize, 2), groups.get("192.0.2.1").?.items.len);
    for (groups.get("192.0.2.1").?.items) |item| {
        try std.testing.expect(item.proxy.owns_host);
    }
}

test "failHint classifies write and buffer errors" {
    try std.testing.expectEqualStrings("write/failed", failHint(error.WriteFailed));
    try std.testing.expectEqualStrings("read/failed", failHint(error.ReadFailed));
    try std.testing.expectEqualStrings("buffer/overflow", failHint(error.BufferTooSmall));
    try std.testing.expectEqualStrings("rejected/closed", failHint(error.ConnectionResetByPeer));
    try std.testing.expectEqualStrings("unreachable", failHint(error.NetworkDown));
    try std.testing.expectEqualStrings("iface/addr", failHint(error.AddressNotAvailable));
    // std spells the same condition AddressUnavailable in Io.net.IpAddress.BindError.
    try std.testing.expectEqualStrings("iface/addr", failHint(error.AddressUnavailable));
    try std.testing.expectEqualStrings("iface/empty", failHint(error.EmptyInterfaceName));
}

test "PrefClass.fromProxy maps vless transport and protocols" {
    const gpa = std.testing.allocator;
    const v2_line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:2053?security=reality&type=grpc&mode=gun&serviceName=xyz&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#VLESS2
    ;
    const v3_line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:8444?security=reality&type=tcp&flow=xtls-rprx-vision&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#VLESS3
    ;
    const ss_line = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.1:8388#ss";
    const tj_line = "trojan://password@192.0.2.1:443?security=tls&type=ws&sni=example.com&path=%2F#tj";

    var v2 = try proxy_uri.parse(gpa, v2_line);
    defer v2.deinit(gpa);
    var v3 = try proxy_uri.parse(gpa, v3_line);
    defer v3.deinit(gpa);
    var ss_p = try proxy_uri.parse(gpa, ss_line);
    defer ss_p.deinit(gpa);
    var tj = try proxy_uri.parse(gpa, tj_line);
    defer tj.deinit(gpa);

    try std.testing.expect(PrefClass.fromProxy(v2) == .vless2);
    try std.testing.expect(PrefClass.fromProxy(v3) == .vless3);
    try std.testing.expect(PrefClass.fromProxy(ss_p) == .shadowsocks);
    try std.testing.expect(PrefClass.fromProxy(tj) == .trojan);
}

test "selectBestClass hydec prefers VLESS2 then demotes on 2x / SS on 3x" {
    // Fastest VLESS² wins when close to others.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 100, 90, 80, 50));
    // Exactly 2×: keep VLESS² ("больше чем в два раза").
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 200, 100, null, null));
    // Strictly more than 2× → VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 201, 100, null, null));
    // SS needs ≥3× vs VLESS².
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 299, null, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 300, null, 100, null));
    // Demoted to VLESS³; SS eligible via VLESS²≥3×SS, then 3× vs VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 600, 100, 40, null)); // 100 ≯ 3×40
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 600, 100, 30, null)); // 100 > 3×30
    // VLESS² kept vs VLESS³, but SS eligible (≥3×); still apply 3× to VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 100, 40, 20, null)); // 40 ≯ 3×20
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 100, 70, 20, null)); // 70 > 3×20
    // No VLESS²: VLESS³ vs SS at 2×.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 200, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, 201, 100, null));
    // No VLESS: SS and Trojan share a tier, the faster one wins, SS on a tie.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, null, 40, 10));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, null, 40, 40));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, null, null, 10));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.hydec, null, null, null, null));
}

test "selectBestClass hydec demotes VLESS to Trojan like to SS" {
    // Trojan alone in the tier: same thresholds SS would get.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 299, null, null, 100));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, 300, null, null, 100));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 200, null, 100));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, 201, null, 100));
    // Both present: the faster of the two is compared and returned.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, 600, null, 300, 150));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 600, null, 150, 300));
    // Live HyNet NL: VLESS² 333, Trojan 307, SS 161 — still VLESS² (333 < 3×161).
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 333, 330, 161, 307));
}

test "selectBestClass hydec ignores ratio wins below the absolute gap" {
    // 3× but only 14 ms apart: no VLESS²→SS demotion.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 21, null, 7, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 23, null, 7, null));
    // >2× but 15 ms apart (not more): no VLESS²→VLESS³ demotion.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 29, 14, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 30, 14, null, null));
    // No VLESS²: VLESS³ 20 ms vs SS 5 ms stays VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 20, 5, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, 21, 5, null));
    // SS eligible vs VLESS², VLESS³ >3× SS yet within the gap: keep VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 100, 20, 5, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 100, 21, 5, null));
}

test "selectBestClass fastest picks minimum latency" {
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.fastest, 100, 90, 80, 50));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.fastest, 300, 100, 40, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.fastest, 201, 100, null, null));
    // Tie: keep the higher preference class.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.fastest, 100, 100, 100, 100));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.fastest, null, null, null, null));
}

test "selectBestClass strict never demotes" {
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.strict, 500, 10, 5, 1));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.strict, null, 200, 10, 1));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.strict, null, null, 40, 10));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.strict, null, null, null, 10));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.strict, null, null, null, null));
}

test "Strategy.parse accepts known names" {
    try std.testing.expectEqual(@as(?Strategy, .hydec), Strategy.parse("hydec"));
    try std.testing.expectEqual(@as(?Strategy, .fastest), Strategy.parse("fastest"));
    try std.testing.expectEqual(@as(?Strategy, .strict), Strategy.parse("strict"));
    try std.testing.expectEqual(@as(?Strategy, null), Strategy.parse("unknown"));
    try std.testing.expectEqual(@as(?Strategy, null), Strategy.parse(""));
}

test "failHint names DNS failures instead of falling through to error" {
    // Io.net.HostName.LookupError plus the ValidateError from HostName.init, both
    // reachable through netutil.connectHostnameTimed for a hostname-based proxy.
    try std.testing.expectEqualStrings("dns/no-address", failHint(error.NoAddressReturned));
    try std.testing.expectEqualStrings("dns/no-address", failHint(error.UnknownHostName));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.NameServerFailure));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.ResolvConfParseFailed));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.DetectingNetworkConfigurationFailed));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.InvalidDnsARecord));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.InvalidDnsAAAARecord));
    try std.testing.expectEqualStrings("dns/failure", failHint(error.InvalidDnsCnameRecord));
    try std.testing.expectEqualStrings("dns/bad-name", failHint(error.InvalidHostName));
    try std.testing.expectEqualStrings("dns/bad-name", failHint(error.NameTooLong));
    // A resolver timeout stays a timeout: netutil maps the deadline race to Timeout.
    try std.testing.expectEqualStrings("slow/timeout", failHint(error.Timeout));
}

test "failHint covers every Io.net.IpAddress.BindError member" {
    // Reflected rather than listed, so a future std release adding a member breaks
    // this test instead of silently regressing that member to the bare `error` hint.
    // Two stay deliberately generic: `Unexpected` is an errno netutil could not map,
    // and `Canceled` cannot reach a probe (connectHostnameTimed turns cancellation
    // into Timeout) — for both, "error" is the honest answer.
    const names = @typeInfo(Io.net.IpAddress.BindError).error_set.error_names.?;
    inline for (names) |name| {
        if (comptime std.mem.eql(u8, name, "Unexpected")) continue;
        if (comptime std.mem.eql(u8, name, "Canceled")) continue;
        const hint = failHint(@field(anyerror, name));
        std.testing.expect(!std.mem.eql(u8, hint, "error")) catch |err| {
            std.debug.print("BindError.{s} has no failHint\n", .{name});
            return err;
        };
    }
}

test "failHint names the ALPN failures" {
    try std.testing.expectEqualStrings("alpn/h2-breaks-ws", failHint(error.WsAlpnHttp2));
    try std.testing.expectEqualStrings("alpn/too-many", failHint(error.TooManyAlpnProtocols));
}
