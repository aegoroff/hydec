const std = @import("std");
const builtin = @import("builtin");
const proxy_uri = @import("proxy_uri.zig");
const util = @import("util.zig");
const ss = @import("ss.zig");
const trojan = @import("trojan.zig");
const alpn = @import("alpn.zig");
const reality = @import("reality.zig");
const hy2 = @import("hy2.zig");
const netutil = @import("netutil.zig");
const Io = std.Io;

const Result = struct {
    /// Median latency, for the `Best:` line.
    latency_ms: u64,
    raw: []const u8,
    /// Owned when `raw` was rewritten to a dialed IP. Free with `deinit`.
    owns_raw: bool = false,
    /// Owned copy of the host; free with `deinit`.
    host: []u8,

    pub fn deinit(self: *Result, gpa: std.mem.Allocator) void {
        gpa.free(self.host);
        if (self.owns_raw) gpa.free(self.raw);
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
/// VLESS² = REALITY gRPC; VLESS³ = REALITY TCP Vision and XHTTP.
/// Enum order breaks exact latency ties. Strict uses its own class order.
pub const PrefClass = enum {
    hysteria2,
    shadowsocks,
    vless3,
    trojan,
    vless2,

    pub fn fromProxy(proxy: proxy_uri.Proxy) ?PrefClass {
        return switch (proxy.kind) {
            .vless => switch (proxy.transport) {
                .grpc => .vless2,
                .tcp, .xhttp => .vless3,
                else => null,
            },
            .shadowsocks => .shadowsocks,
            .trojan => .trojan,
            .hysteria2 => .hysteria2,
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
};

const WorkItem = struct {
    raw: []const u8,
    proxy: proxy_uri.Proxy,
    /// Owned addresses from grouping. An empty slice without an error needs fresh DNS.
    addresses: []Io.net.IpAddress,
    resolution_error: ?anyerror = null,
    /// Address the successful probe connected to. Empty until that probe returns.
    dialed: ?Io.net.IpAddress = null,
    latency: ?Latency = null,
};

/// Cap concurrent host workers so a large subscription cannot exhaust OS threads.
const MAX_PARALLEL_HOSTS: usize = 64;
// The threaded DNS pool can still be alive when the probe workers start.
const WORKER_STACK_SIZE = if (@bitSizeOf(usize) == 32) 2 * 1024 * 1024 else std.Thread.SpawnConfig.default_stack_size;

const Shared = struct {
    gpa: std.mem.Allocator,
    io: Io,
    verbose: bool,
    check_volume: bool,
    timeout_secs: u32,
    /// Optional interface/source-IP spec forwarded to `connectHostPortWithAddresses` (`null` = default).
    bind: ?[]const u8,
    mutex: Io.Mutex = .init,
    stats: *Stats,

    fn lock(self: *Shared) void {
        self.mutex.lockUncancelable(self.io);
    }

    fn unlock(self: *Shared) void {
        self.mutex.unlock(self.io);
    }
};

/// How many successful probes are required for `ping` / `best` (see `TRANSIENT_RETRIES`).
pub const PROBE_ATTEMPTS: usize = 3;

pub fn probeOne(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    target: util.Target,
    timeout_secs: u32,
    bind: ?[]const u8,
    addresses: ?[]Io.net.IpAddress,
    stage: *util.Stage,
    dialed: ?*Io.net.IpAddress,
) !u64 {
    stage.* = .setup;
    return switch (proxy.kind) {
        .shadowsocks => blk: {
            var query_params = std.mem.splitScalar(u8, proxy.query, '&');
            while (query_params.next()) |pair| {
                const eq = std.mem.findScalar(u8, pair, '=');
                const name = if (eq) |i| pair[0..i] else pair;
                if (!std.mem.eql(u8, name, "plugin")) continue;
                const raw = if (eq) |i| pair[i + 1 ..] else "";
                const plugin = try util.urlDecodeStrict(gpa, raw);
                defer gpa.free(plugin);
                // An empty first value must not hide a plugin in a later parameter.
                if (plugin.len > 0) return error.UnsupportedPlugin;
            }
            const method = proxy.method orelse return error.InvalidProxyUri;
            const password = proxy.password orelse return error.InvalidProxyUri;
            break :blk try ss.probe(gpa, io, proxy.host, proxy.port, method, password, target, timeout_secs, bind, addresses, stage, dialed);
        },
        .trojan => blk: {
            if (proxy.transport != .tcp and proxy.transport != .ws) return error.UnsupportedTransport;
            if (proxy.security != .tls) return error.UnsupportedSecurity;
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
            }, target, timeout_secs, bind, addresses, stage, dialed);
        },
        .vless => blk: {
            if (proxy.security != .reality) return error.UnsupportedSecurity;
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
            var params_arena = std.heap.ArenaAllocator.init(gpa);
            defer params_arena.deinit();
            const params = params_arena.allocator();
            const transport: reality.Transport = switch (proxy.transport) {
                .tcp => .{ .tcp = flow },
                .grpc => grpc: {
                    const mode = (try proxy.getParamDecoded(params, "mode")) orelse "";
                    if (mode.len != 0 and !std.mem.eql(u8, mode, "gun")) return error.UnsupportedGrpcMode;
                    break :grpc .{ .grpc = .{
                        .service = (try proxy.getParamDecoded(params, "serviceName")) orelse "",
                        .authority = (try proxy.getParamDecoded(params, "authority")) orelse "",
                    } };
                },
                .xhttp => xhttp: {
                    if (flow.len != 0) return error.UnsupportedXhttpFlow;
                    break :xhttp .{ .xhttp = try parseXhttp(params, proxy) };
                },
                else => return error.UnsupportedTransport,
            };
            break :blk try reality.probeVless(
                gpa,
                io,
                proxy.host,
                proxy.port,
                proxy.userinfo,
                sni,
                pbk,
                sid,
                transport,
                target,
                timeout_secs,
                bind,
                addresses,
                stage,
                dialed,
            );
        },
        .hysteria2 => try hy2.probe(gpa, io, proxy, target, timeout_secs, bind, addresses, stage, dialed),
        .vmess => error.SkippedVmess,
        .unsupported => error.UnsupportedProtocol,
    };
}

fn parseXhttp(arena: std.mem.Allocator, proxy: proxy_uri.Proxy) !@FieldType(reality.Transport, "xhttp") {
    try validateXhttpMode(try proxy.getParamDecoded(arena, "mode"));
    var options: @FieldType(reality.Transport, "xhttp") = .{
        .path = (try proxy.getParamDecoded(arena, "path")) orelse "",
        .authority = (try proxy.getParamDecoded(arena, "host")) orelse "",
    };
    const Extra = struct {
        mode: ?[]const u8 = null,
        xPaddingObfsMode: ?bool = null,
        noGRPCHeader: ?bool = null,
        downloadSettings: ?std.json.Value = null,
        headers: ?std.json.ArrayHashMap([]const u8) = null,
        xPaddingBytes: ?std.json.Value = null,
    };
    if (util.getQueryParam(proxy.query, "extra")) |raw| {
        const form = try arena.dupe(u8, raw);
        std.mem.replaceScalar(u8, form, '+', ' ');
        var decoded = try util.urlDecodeStrict(arena, form);
        if (decoded.len >= 3 and std.ascii.eqlIgnoreCase(decoded[0..3], "%7B")) {
            std.mem.replaceScalar(u8, decoded, '+', ' ');
            decoded = try util.urlDecodeStrict(arena, decoded);
        }
        const json = std.mem.trim(u8, decoded, " \t\r\n");
        if (json.len != 0) {
            const extra = std.json.parseFromSliceLeaky(Extra, arena, json, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.InvalidXhttpExtra,
            };
            try validateXhttpMode(extra.mode);
            if ((extra.xPaddingObfsMode orelse false) or (extra.noGRPCHeader orelse false) or extra.downloadSettings != null or
                (if (extra.headers) |headers| headers.map.count() != 0 else false))
                return error.UnsupportedXhttpExtra;
            if (extra.xPaddingBytes) |padding| {
                options.padding = switch (padding) {
                    .string => |value| try parseXhttpPadding(value),
                    .integer => |value| if (value == 0) .{} else blk: {
                        const bytes = std.math.cast(u32, value) orelse return error.InvalidXhttpPadding;
                        break :blk .{ .min = bytes, .max = bytes };
                    },
                    else => return error.InvalidXhttpPadding,
                };
                return options;
            }
        }
    }
    if (try proxy.getParamDecoded(arena, "x_padding_bytes")) |padding|
        options.padding = try parseXhttpPadding(padding);
    if (try proxy.getParamDecoded(arena, "xPaddingBytes")) |padding|
        options.padding = try parseXhttpPadding(padding);
    return options;
}

fn validateXhttpMode(mode: ?[]const u8) error{UnsupportedXhttpMode}!void {
    const value = mode orelse return;
    if (value.len != 0 and !std.mem.eql(u8, value, "auto") and !std.mem.eql(u8, value, "stream-one"))
        return error.UnsupportedXhttpMode;
}

fn parseXhttpPadding(value: []const u8) error{InvalidXhttpPadding}!reality.XhttpPadding {
    if (value.len == 0) return .{};
    const sep = std.mem.findScalar(u8, value, '-') orelse value.len;
    const min = std.fmt.parseUnsigned(u32, value[0..sep], 10) catch return error.InvalidXhttpPadding;
    if (sep == value.len) return if (min == 0) .{} else .{ .min = min, .max = min };
    const max = std.fmt.parseUnsigned(u32, value[sep + 1 ..], 10) catch return error.InvalidXhttpPadding;
    if (min == 0 or min > max) return error.InvalidXhttpPadding;
    return .{ .min = min, .max = max };
}

/// How many failed attempts per candidate may be retried, and only when `isTransient`.
pub const TRANSIENT_RETRIES: usize = 1;

/// Summary of one candidate's successful latency probes.
pub const Latency = struct {
    median_ms: u64,
    mean_ms: f64,
    min_ms: u64,
    max_ms: u64,
    /// Transient failures retried while collecting the samples.
    retries: usize = 0,

    /// `samples` must be non-empty; sorts it in place. Upper median for an even count,
    /// so a single latency spike among three samples does not move the result.
    pub fn fromSamples(samples: []u64) Latency {
        std.debug.assert(samples.len > 0);
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        var sum: u128 = 0;
        for (samples) |sample| sum += sample;
        return .{
            .median_ms = samples[samples.len / 2],
            .mean_ms = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(samples.len)),
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
        error.Timeout, error.ConnectTimeout, error.ConnectionTimedOut => true,
        else => util.isPeerClosed(err),
    };
}

/// Fill `samples` from `prober.probe()`; fail on the first non-transient error or once
/// `TRANSIENT_RETRIES` is used up. Returns how many retries were spent.
fn collectSamples(prober: anytype, samples: []u64) !usize {
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
    return TRANSIENT_RETRIES - retries_left;
}

/// Run `PROBE_ATTEMPTS` full probes (one retry on a transient error).
/// With `check_volume`, then one unretried `util.VOLUME_TARGET` download under the full
/// timeout; its duration is not counted toward latency (a post-connect timeout becomes
/// `VolumeStalled`, see `volumeError`).
/// On success returns the median latency and the sample spread; on failure `stage`
/// holds how far the failing attempt got.
pub fn probeLatency(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    timeout_secs: u32,
    bind: ?[]const u8,
    addresses: ?[]Io.net.IpAddress,
    resolution_error: ?anyerror,
    check_volume: bool,
    stage: *util.Stage,
    dialed: *?Io.net.IpAddress,
) !Latency {
    if (resolution_error) |err| return err;

    const Prober = struct {
        gpa: std.mem.Allocator,
        io: Io,
        proxy: proxy_uri.Proxy,
        timeout_secs: u32,
        bind: ?[]const u8,
        addresses: ?[]Io.net.IpAddress,
        stage: *util.Stage,
        dialed: *?Io.net.IpAddress,

        fn probe(self: @This()) !u64 {
            var one: Io.net.IpAddress = undefined;
            const ms = try probeOne(self.gpa, self.io, self.proxy, util.LATENCY_TARGET, self.timeout_secs, self.bind, self.addresses, self.stage, &one);
            self.dialed.* = one;
            return ms;
        }
    };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;
    const retries = try collectSamples(Prober{ .gpa = gpa, .io = io, .proxy = proxy, .timeout_secs = timeout_secs, .bind = bind, .addresses = addresses, .stage = stage, .dialed = dialed }, &samples);
    var latency = Latency.fromSamples(&samples);
    latency.retries = retries;
    if (check_volume) {
        var one: Io.net.IpAddress = undefined;
        _ = probeOne(gpa, io, proxy, util.VOLUME_TARGET, timeout_secs, bind, addresses, stage, &one) catch |err| switch (err) {
            error.VolumeRefused => {
                if (!volumeRefusalIgnored(proxy)) return err;
                std.log.warn("volume check skipped for {s}:{d}: download refused", .{ proxy.host, proxy.port });
            },
            else => return volumeError(err, stage.*),
        };
        dialed.* = one;
    }
    return latency;
}

fn volumeRefusalIgnored(proxy: proxy_uri.Proxy) bool {
    // VLESS TCP has no warmup request, so a refusal proves nothing about the download.
    return proxy.kind != .vless or proxy.transport != .tcp;
}

/// The volume download runs once and is never retried: a DPI freeze past the first
/// ~16–20 KB repeats on every attempt, and a retry would only double its cost.
/// A read timeout there is that freeze, so it gets its own name; other errors pass through.
/// Lookup and connect timeouts stay connect failures: no download has started yet.
fn volumeError(err: anyerror, stage: util.Stage) anyerror {
    return switch (err) {
        error.Timeout, error.ConnectionTimedOut => switch (stage) {
            .setup, .connect => err,
            .handshake, .tunnel, .reply => error.VolumeStalled,
        },
        else => err,
    };
}

/// Ranking key for one candidate: lower is better, `retried` first, then `ms`.
pub const Rank = struct {
    /// Only set with `--prefer-stable`: a candidate that needed a retry loses to
    /// every candidate that did not, in any class.
    retried: bool,
    ms: u64,

    /// Default: median latency. `--prefer-stable`: the worst sample, so a single
    /// spike counts against the candidate instead of being hidden by the median.
    pub fn of(latency: Latency, prefer_stable: bool) Rank {
        if (!prefer_stable) return .{ .retried = false, .ms = latency.median_ms };
        return .{ .retried = latency.retries > 0, .ms = latency.max_ms };
    }

    pub fn lessThan(a: Rank, b: Rank) bool {
        if (a.retried != b.retried) return !a.retried;
        return a.ms < b.ms;
    }
};

/// `selectBestClass` over per-class bests. Classes whose best needed a retry only
/// compete when no class has a clean best.
fn selectBestRanked(strategy: Strategy, best: std.EnumArray(PrefClass, ?Rank)) ?PrefClass {
    for ([_]bool{ false, true }) |allow_retried| {
        var ms: std.EnumArray(PrefClass, ?u64) = .initFill(null);
        for (std.enums.values(PrefClass)) |class| {
            const r = best.get(class) orelse continue;
            if (r.retried and !allow_retried) continue;
            ms.set(class, r.ms);
        }
        if (selectBestClass(strategy, ms.get(.vless2), ms.get(.vless3), ms.get(.shadowsocks), ms.get(.trojan), ms.get(.hysteria2))) |class|
            return class;
    }
    return null;
}

/// Pick the winning preference class from per-class fastest latencies.
pub fn selectBestClass(
    strategy: Strategy,
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
    hysteria2_ms: ?u64,
) ?PrefClass {
    return switch (strategy) {
        .hydec => selectHydecClass(vless2_ms, vless3_ms, ss_ms, trojan_ms, hysteria2_ms),
        .fastest => selectFastestClass(vless2_ms, vless3_ms, ss_ms, trojan_ms, hysteria2_ms),
        .strict => selectStrictClass(vless2_ms, vless3_ms, ss_ms, trojan_ms, hysteria2_ms),
    };
}

/// Absolute latency gap (ms) a `hydec` demotion requires on top of its ratio:
/// 21 ms vs 7 ms is 3× but only noise.
pub const MIN_DEMOTE_GAP_MS: u64 = 15;

/// `slow` loses to `fast` by more than `MIN_DEMOTE_GAP_MS`.
fn clearlySlower(slow: u64, fast: u64) bool {
    return slow -| fast > MIN_DEMOTE_GAP_MS;
}

/// Default `hydec` policy. VLESS², Trojan, and Hysteria 2 share the top tier.
/// 1. Use the fastest class in that tier, breaking ties in the listed order.
/// 2. Prefer VLESS³ when the top tier is strictly more than 2× slower.
/// 3. Prefer SS over the top tier if it is absent or at least 3× slower.
///    When SS is eligible and VLESS³ exists, prefer VLESS³ unless it is >3× slower
///    than SS (even if VLESS²/Trojan was not demoted to VLESS³).
/// 4. With VLESS³ but no top-tier class: prefer VLESS³ unless it is strictly more than 2× slower
///    than SS.
/// Every demotion in 2–4 also needs the slower class to lose by more than
/// `MIN_DEMOTE_GAP_MS`, so jitter between near-local nodes cannot flip the pick.
fn selectHydecClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
    hysteria2_ms: ?u64,
) ?PrefClass {
    if (selectFastestClass(vless2_ms, null, null, trojan_ms, hysteria2_ms)) |top| {
        const top_ms = switch (top) {
            .vless2 => vless2_ms.?,
            .trojan => trojan_ms.?,
            .hysteria2 => hysteria2_ms.?,
            else => unreachable,
        };
        var class = top;
        if (vless3_ms) |v3| {
            if (top_ms > v3 *| 2 and clearlySlower(top_ms, v3)) {
                class = .vless3;
            }
        }
        if (ss_ms) |ss_lat| {
            if (top_ms >= ss_lat *| 3 and clearlySlower(top_ms, ss_lat)) {
                // SS eligible against the top tier: prefer VLESS³ unless it is >3× slower.
                if (vless3_ms) |v3| {
                    if (v3 > ss_lat *| 3 and clearlySlower(v3, ss_lat)) return .shadowsocks;
                    return .vless3;
                }
                return .shadowsocks;
            }
        }
        return class;
    }

    if (vless3_ms) |v3| {
        if (ss_ms) |ss_lat| {
            if (v3 > ss_lat *| 2 and clearlySlower(v3, ss_lat)) return .shadowsocks;
        }
        return .vless3;
    }

    return if (ss_ms != null) .shadowsocks else null;
}

/// Minimum latency, with ties resolved in enum preference order.
fn selectFastestClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
    hysteria2_ms: ?u64,
) ?PrefClass {
    const candidates = [_]struct { class: PrefClass, ms: ?u64 }{
        .{ .class = .vless2, .ms = vless2_ms },
        .{ .class = .trojan, .ms = trojan_ms },
        .{ .class = .vless3, .ms = vless3_ms },
        .{ .class = .shadowsocks, .ms = ss_ms },
        .{ .class = .hysteria2, .ms = hysteria2_ms },
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
    hysteria2_ms: ?u64,
) ?PrefClass {
    if (vless2_ms != null) return .vless2;
    if (trojan_ms != null) return .trojan;
    if (hysteria2_ms != null) return .hysteria2;
    if (vless3_ms != null) return .vless3;
    if (ss_ms != null) return .shadowsocks;
    return null;
}

/// `", retry N"` when a transient failure was retried, otherwise nothing.
pub const RetrySuffix = struct {
    retries: usize,

    pub fn format(self: RetrySuffix, w: *Io.Writer) Io.Writer.Error!void {
        if (self.retries > 0) try w.print(", retry {d}", .{self.retries});
    }
};

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

/// `failHint`, then `@stage` once the failing attempt got past setup:
/// `rejected/closed@handshake` is a reset on the first flight.
pub const FailReason = struct {
    err: anyerror,
    stage: util.Stage,

    pub fn format(self: FailReason, w: *Io.Writer) Io.Writer.Error!void {
        try w.writeAll(failHint(self.err));
        if (self.stage != .setup) try w.print("@{t}", .{self.stage});
    }
};

/// Short hint for FAIL logs (why the probe likely failed).
pub fn failHint(err: anyerror) []const u8 {
    return switch (err) {
        error.VolumeStalled => "volume/stalled",
        error.Timeout, error.ConnectTimeout, error.ConnectionTimedOut => "slow/timeout",
        // REALITY/TLS alert — rejected ClientHello (wrong pbk/sid/sni/client ver) or dest fallback.
        error.TlsAlert, error.TlsUnexpectedMessage, error.TlsFinishedVerifyFailed, error.TlsCertificateVerifyFailed => "handshake/alert",
        // The leaf was not REALITY's HMAC-signed one: the server fell back to its dest.
        error.RealityAuthFailed => "reality/auth",
        error.CertificateBundleLoadFailure => "tls/cert",
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.NetworkDown,
        => "unreachable",
        error.GrpcEmptyResponse => "empty/no-data",
        error.GrpcBadStatus => "grpc/status",
        error.XhttpBadStatus => "xhttp/status",
        error.UnsupportedXhttpMode => "xhttp/unsupported-mode",
        error.UnsupportedXhttpFlow => "xhttp/unsupported-flow",
        error.UnsupportedXhttpExtra => "xhttp/unsupported-extra",
        error.InvalidXhttpExtra => "xhttp/invalid-extra",
        error.InvalidXhttpPadding => "xhttp/invalid-padding",
        // Server picked h2 for a ws transport: the HTTP/1.1 upgrade gets HTTP/2 frames.
        error.WsAlpnHttp2 => "alpn/h2-breaks-ws",
        // The URI listed more ALPN protocols than a probe will carry.
        error.TooManyAlpnProtocols => "alpn/too-many",
        error.InvalidAlpnProtocol => "alpn/invalid",
        error.ProbeResponseMismatch => "bad/response",
        error.ExpectedVisionPadding => "vision/framing",
        error.InvalidSsChunk => "ss/chunk",
        error.UnsupportedVlessEncryption => "unsupported-encryption",
        error.UnsupportedTransport => "unsupported-transport",
        error.HysteriaAuthRejected => "hy2/auth",
        error.HysteriaTunnelRejected => "hy2/tunnel",
        error.HysteriaPinMismatch => "hy2/pin",
        error.InvalidHysteriaPin => "hy2/invalid-pin",
        error.HysteriaAlpnMismatch => "hy2/alpn",
        error.InvalidHysteriaResponse => "hy2/invalid-response",
        error.HysteriaSourceFamilyMismatch => "iface/family",
        error.UnsupportedHysteriaEch => "unsupported-ech",
        error.UnsupportedHysteriaPortHopping => "unsupported-port-hopping",
        error.UnsupportedObfs => "unsupported-obfs",
        error.UnsupportedPlugin => "unsupported-plugin",
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
        else => if (util.isPeerClosed(err)) "rejected/closed" else "error",
    };
}

fn probeGroup(shared: *Shared, items: []WorkItem, phase: enum { grouped, dns_fallback }) void {
    for (items) |*item| {
        const needs_dns = item.addresses.len == 0 and item.resolution_error == null;
        if (needs_dns != (phase == .dns_fallback)) continue;
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

        var stage: util.Stage = .setup;
        var dialed: ?Io.net.IpAddress = null;
        const latency = probeLatency(shared.gpa, shared.io, proxy, shared.timeout_secs, shared.bind, item.addresses, item.resolution_error, shared.check_volume, &stage, &dialed) catch |err| {
            if (shared.verbose) {
                std.log.warn("FAIL: {f}: {f} ({})", .{ HostIdent{ .name = proxy.name, .host = proxy.host }, FailReason{ .err = err, .stage = stage }, err });
            }
            continue;
        };

        {
            shared.lock();
            shared.stats.passed += 1;
            shared.unlock();
        }

        if (shared.verbose) {
            std.log.info("OK: {d}ms (min {d}, max {d}{f}) {s}{f}", .{ latency.median_ms, latency.min_ms, latency.max_ms, RetrySuffix{ .retries = latency.retries }, proxy.host, NameSuffix{ .name = proxy.name } });
        }

        item.latency = latency;
        item.dialed = dialed;
    }
}

/// Host groups handed out one at a time to `findBest`'s workers.
const HostQueue = struct {
    lists: []std.ArrayList(WorkItem),
    next: std.atomic.Value(usize) = .init(0),

    fn work(self: *HostQueue, shared: *Shared) void {
        while (true) {
            const i = self.next.fetchAdd(1, .monotonic);
            if (i >= self.lists.len) return;
            probeGroup(shared, self.lists[i].items, .grouped);
        }
    }

    fn workDeferred(self: *const HostQueue, shared: *Shared) void {
        for (self.lists) |list| probeGroup(shared, list.items, .dns_fallback);
    }
};

/// Disjoint resolved-address sets, plus one shared unresolved queue; each list is
/// probed sequentially, different lists in parallel.
const GroupMap = std.array_hash_map.String(std.ArrayList(WorkItem));

fn freeGroups(gpa: std.mem.Allocator, groups: *GroupMap) void {
    for (groups.keys()) |key| gpa.free(key);
    for (groups.values()) |*list| {
        for (list.items) |*item| {
            item.proxy.deinit(gpa);
            gpa.free(item.addresses);
        }
        list.deinit(gpa);
    }
    groups.deinit(gpa);
}

/// Never logs `line` itself: it carries the UUID / password.
fn logParseFail(gpa: std.mem.Allocator, index: usize, line: []const u8, err: anyerror) void {
    const name = proxy_uri.parseName(gpa, line) catch null;
    defer if (name) |n| gpa.free(n);
    std.log.warn("parse fail: entry {d}{f}: {}", .{ index + 1, NameSuffix{ .name = name }, err });
}

fn dupeIpKey(gpa: std.mem.Allocator, ip: Io.net.IpAddress) ![]u8 {
    var buf: [64]u8 = undefined;
    return gpa.dupe(u8, util.formatIpHost(ip, false, &buf));
}

fn dupeNameOwnerKey(gpa: std.mem.Allocator, host: []const u8) ![]u8 {
    // Keep both DNS spellings in one probe group even if search domains differ.
    const name = if (host.len > 1 and host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
    const key = try gpa.alloc(u8, "name:".len + name.len);
    @memcpy(key[0.."name:".len], "name:");
    for (key["name:".len..], name) |*dst, c| dst.* = std.ascii.toLower(c);
    return key;
}

const MAX_RESOLVED_ADDRESSES = 32;
const EndpointOwners = std.array_hash_map.String([]const u8);

const SystemResolver = struct {
    fn lookup(_: @This(), io: Io, host: []const u8, deadline: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
        // A truncated answer fails too: an omitted address could be the one shared
        // with another hostname.
        return netutil.resolveAllUntil(io, host, 0, deadline, addresses);
    }
};

fn freeEndpointOwners(gpa: std.mem.Allocator, owners: *EndpointOwners) void {
    for (owners.keys()) |key| gpa.free(key);
    owners.deinit(gpa);
}

fn getOrCreateGroup(
    gpa: std.mem.Allocator,
    groups: *GroupMap,
    key: []const u8,
) ![]const u8 {
    const owned_key = try gpa.dupe(u8, key);
    const gop = groups.getOrPut(gpa, owned_key) catch |err| {
        gpa.free(owned_key);
        return err;
    };
    if (gop.found_existing) {
        gpa.free(owned_key);
    } else {
        gop.value_ptr.* = .empty;
    }
    return gop.key_ptr.*;
}

/// Merge two queues when a hostname bridges address sets that were disjoint before.
fn mergeGroups(
    gpa: std.mem.Allocator,
    groups: *GroupMap,
    owners: *EndpointOwners,
    target_key: []const u8,
    source_key: []const u8,
) !void {
    if (std.mem.eql(u8, target_key, source_key)) return;

    const target = groups.getPtr(target_key).?;
    const source = groups.get(source_key).?;
    try target.ensureUnusedCapacity(gpa, source.items.len);
    target.appendSliceAssumeCapacity(source.items);

    const removed = groups.fetchOrderedRemove(source_key).?;
    var removed_list = removed.value;
    removed_list.deinit(gpa);
    for (owners.values()) |*owner| {
        if (std.mem.eql(u8, owner.*, source_key)) owner.* = target_key;
    }
    gpa.free(removed.key);
}

fn addEndpointOwner(gpa: std.mem.Allocator, owners: *EndpointOwners, endpoint_key: []const u8, group_key: []const u8) !void {
    const owned_key = try gpa.dupe(u8, endpoint_key);
    const gop = owners.getOrPut(gpa, owned_key) catch |err| {
        gpa.free(owned_key);
        return err;
    };
    if (gop.found_existing) {
        gpa.free(owned_key);
        std.debug.assert(std.mem.eql(u8, gop.value_ptr.*, group_key));
    } else {
        gop.value_ptr.* = group_key;
    }
}

const PendingEntry = struct {
    raw: []const u8,
    proxy: proxy_uri.Proxy,
    endpoint: union(enum) { literal: Io.net.IpAddress, lookup: usize },
};

const NameResolution = struct {
    host: []const u8,
    addresses: []Io.net.IpAddress = &.{},
    err: ?anyerror = null,
};

fn resolveWorker(
    names: []NameResolution,
    next: *std.atomic.Value(usize),
    oom: *std.atomic.Value(bool),
    gpa: std.mem.Allocator,
    io: Io,
    timeout_secs: u32,
    resolver: anytype,
) void {
    while (true) {
        const i = next.fetchAdd(1, .monotonic);
        if (i >= names.len) return;
        const name = &names[i];
        const deadline = netutil.deadlineNs(io, timeout_secs);
        if (timeout_secs == 0) {
            name.err = error.Timeout;
            continue;
        }
        var storage: [MAX_RESOLVED_ADDRESSES]Io.net.IpAddress = undefined;
        const addresses = resolver.lookup(io, name.host, deadline, &storage) catch |err| retry: {
            if (err != error.NameServerFailure) {
                name.err = err;
                continue;
            }
            if (netutil.monoNow(io) >= deadline) {
                name.err = error.Timeout;
                continue;
            }
            break :retry resolver.lookup(io, name.host, deadline, &storage) catch |retry_err| {
                name.err = if (retry_err == error.NameServerFailure and netutil.monoNow(io) >= deadline)
                    error.Timeout
                else
                    retry_err;
                continue;
            };
        };
        if (addresses.len == 0) {
            name.err = error.NoAddressReturned;
            continue;
        }
        name.addresses = gpa.dupe(Io.net.IpAddress, addresses) catch {
            oom.store(true, .release);
            return;
        };
    }
}

/// Build endpoint→proxies queues. Names sharing any resolved IP share one queue.
fn collectGroups(
    gpa: std.mem.Allocator,
    io: Io,
    lines: []const []const u8,
    stats: *Stats,
    verbose: bool,
    timeout_secs: u32,
) !GroupMap {
    return collectGroupsWithResolver(gpa, io, lines, stats, verbose, timeout_secs, SystemResolver{});
}

fn collectGroupsWithResolver(
    gpa: std.mem.Allocator,
    io: Io,
    lines: []const []const u8,
    stats: *Stats,
    verbose: bool,
    timeout_secs: u32,
    resolver: anytype,
) !GroupMap {
    var pending: std.ArrayList(PendingEntry) = .empty;
    defer pending.deinit(gpa);
    var moved: usize = 0;
    errdefer for (pending.items[moved..]) |*entry| entry.proxy.deinit(gpa);

    var names: std.array_hash_map.String(NameResolution) = .empty;
    defer {
        for (names.keys(), names.values()) |key, name| {
            gpa.free(key);
            gpa.free(name.addresses);
        }
        names.deinit(gpa);
    }

    for (lines, 0..) |line, i| {
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
            if (verbose) logParseFail(gpa, i, line, err);
            continue;
        };
        errdefer proxy.deinit(gpa);
        const endpoint: @FieldType(PendingEntry, "endpoint") = if (Io.net.IpAddress.parse(proxy.host, proxy.port)) |ip|
            .{ .literal = ip }
        else |_| lookup: {
            // Preserve the lookup spelling and group case variants of the same query.
            // A trailing dot affects DNS search domains, so it stays in the cache key.
            const key = try std.ascii.allocLowerString(gpa, proxy.host);
            const slot = names.getOrPut(gpa, key) catch |err| {
                gpa.free(key);
                return err;
            };
            if (slot.found_existing) {
                gpa.free(key);
            } else {
                slot.value_ptr.* = .{ .host = proxy.host };
            }
            break :lookup .{ .lookup = slot.index };
        };
        try pending.append(gpa, .{ .raw = line, .proxy = proxy, .endpoint = endpoint });
    }

    var oom: std.atomic.Value(bool) = .init(false);
    {
        var next: std.atomic.Value(usize) = .init(0);
        const threads = try gpa.alloc(std.Thread, @min(names.count(), MAX_PARALLEL_HOSTS));
        defer gpa.free(threads);
        var spawned: usize = 0;
        defer for (threads[0..spawned]) |t| t.join();
        for (threads) |*t| {
            t.* = try std.Thread.spawn(.{ .stack_size = WORKER_STACK_SIZE }, resolveWorker, .{ names.values(), &next, &oom, gpa, io, timeout_secs, resolver });
            spawned += 1;
        }
    }
    if (oom.load(.acquire)) return error.OutOfMemory;

    var groups: GroupMap = .empty;
    errdefer freeGroups(gpa, &groups);
    var owners: EndpointOwners = .empty;
    defer freeEndpointOwners(gpa, &owners);

    // Grouping stays sequential and in line order; only resolution was parallel.
    for (pending.items, 0..) |*entry, i| {
        const proxy = entry.proxy;
        const addresses = try gpa.dupe(Io.net.IpAddress, switch (entry.endpoint) {
            .literal => |ip| &.{ip},
            .lookup => |index| names.values()[index].addresses,
        });
        errdefer gpa.free(addresses);
        for (addresses) |*address| address.setPort(proxy.port);
        const resolution_error: ?anyerror = switch (entry.endpoint) {
            .literal => null,
            .lookup => |index| if (names.values()[index].err) |err| switch (err) {
                error.Timeout, error.UnknownHostName, error.NoAddressReturned => err,
                else => null,
            } else null,
        };

        var endpoint_keys: [MAX_RESOLVED_ADDRESSES][]u8 = undefined;
        var endpoint_count: usize = 0;
        defer for (endpoint_keys[0..endpoint_count]) |key| gpa.free(key);
        for (addresses) |address| {
            endpoint_keys[endpoint_count] = try dupeIpKey(gpa, address);
            endpoint_count += 1;
        }
        const endpoints = endpoint_keys[0..endpoint_count];
        const name_key: ?[]u8 = if (entry.endpoint == .lookup) try dupeNameOwnerKey(gpa, proxy.host) else null;
        defer if (name_key) |key| gpa.free(key);

        var group_key: ?[]const u8 = null;
        for (endpoints) |endpoint| {
            if (owners.get(endpoint)) |existing| {
                group_key = existing;
                break;
            }
        }
        if (group_key == null) {
            if (name_key) |key| {
                if (owners.get(key)) |existing| group_key = existing;
            }
        }
        if (group_key == null) {
            const first_key = if (endpoints.len > 0) endpoints[0] else "unresolved";
            group_key = try getOrCreateGroup(gpa, &groups, first_key);
        }

        // A new name can connect two previously separate address sets. Their queues
        // must become one before any workers start.
        for (endpoints) |endpoint| {
            if (owners.get(endpoint)) |existing| try mergeGroups(gpa, &groups, &owners, group_key.?, existing);
        }
        if (name_key) |key| {
            if (owners.get(key)) |existing| try mergeGroups(gpa, &groups, &owners, group_key.?, existing);
        }
        for (endpoints) |endpoint| try addEndpointOwner(gpa, &owners, endpoint, group_key.?);
        if (name_key) |key| try addEndpointOwner(gpa, &owners, key, group_key.?);

        try groups.getPtr(group_key.?).?.append(gpa, .{
            .raw = entry.raw,
            .proxy = proxy,
            .addresses = addresses,
            .resolution_error = resolution_error,
        });
        moved = i + 1;
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
    prefer_stable: bool,
    check_volume: bool,
    raw_output: bool,
    stats: *Stats,
) !?Result {
    var groups = try collectGroups(gpa, io, lines, stats, verbose, timeout_secs);
    defer freeGroups(gpa, &groups);

    if (groups.count() == 0) return null;

    var shared: Shared = .{
        .gpa = gpa,
        .io = io,
        .verbose = verbose,
        .check_volume = check_volume,
        .timeout_secs = timeout_secs,
        .bind = bind,
        .stats = stats,
    };

    // Each worker takes the next address set as soon as it is free, so one slow
    // endpoint holds up only its own thread, not a whole batch of others.
    var queue: HostQueue = .{ .lists = groups.values() };
    const threads = try gpa.alloc(std.Thread, @min(queue.lists.len, MAX_PARALLEL_HOSTS));
    defer gpa.free(threads);

    {
        var spawned: usize = 0;
        defer for (threads[0..spawned]) |t| t.join();
        for (threads) |*t| {
            t.* = try std.Thread.spawn(.{ .stack_size = WORKER_STACK_SIZE }, HostQueue.work, .{ &queue, &shared });
            spawned += 1;
        }
    }

    // A fresh lookup can land on any IP, so wait for all grouped probes to finish.
    queue.workDeferred(&shared);
    const winner = selectWinner(queue.lists, strategy, prefer_stable) orelse return null;
    const line = try printedLine(gpa, winner, raw_output);
    errdefer if (line.owned) gpa.free(line.text);
    return .{
        .latency_ms = winner.latency.?.median_ms,
        .raw = line.text,
        .owns_raw = line.owned,
        .host = try gpa.dupe(u8, winner.proxy.host),
    };
}

const PrintedLine = struct { text: []const u8, owned: bool };

/// Podkop dials `server` from the URI and resolves a domain through its own DoH.
/// Preserve the TLS name when replacing the host with the dialed address.
fn printedLine(gpa: std.mem.Allocator, winner: *const WorkItem, raw_output: bool) !PrintedLine {
    if (raw_output) return .{ .text = winner.raw, .owned = false };
    if (Io.net.IpAddress.parse(winner.proxy.host, winner.proxy.port)) |_| {
        return .{ .text = winner.raw, .owned = false };
    } else |_| {}
    const address = winner.dialed orelse return .{ .text = winner.raw, .owned = false };
    const text = proxy_uri.rewriteAuthorityHost(gpa, winner.raw, address) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return .{ .text = winner.raw, .owned = false },
    };
    switch (winner.proxy.kind) {
        .trojan, .vless, .hysteria2 => {},
        else => return .{ .text = text, .owned = true },
    }
    errdefer gpa.free(text);

    const frag_at = std.mem.findScalar(u8, text, '#') orelse text.len;
    const base = text[0..frag_at];
    var start = frag_at;
    var end = frag_at;
    var separator: []const u8 = "?";
    if (std.mem.findScalar(u8, base, '?')) |query_at| {
        separator = if (query_at + 1 == base.len) "" else "&";
        var params = std.mem.splitScalar(u8, base[query_at + 1 ..], '&');
        while (true) {
            const param_start = base.len - params.rest().len;
            const param = params.next() orelse break;
            if (!std.mem.eql(u8, std.mem.sliceTo(param, '='), "sni")) continue;
            if (param.len > "sni=".len) return .{ .text = text, .owned = true };
            start = param_start;
            end = start + param.len;
            separator = "";
            break;
        }
    }

    const with_sni = try gpa.print("{s}{s}sni={s}{s}", .{ text[0..start], separator, winner.proxy.host, text[end..] });
    gpa.free(text);
    return .{ .text = with_sni, .owned = true };
}

test "printed uri uses the ipv6 that answered, not an unreachable ipv4" {
    const io = std.testing.io;
    const v6_local: Io.net.IpAddress = .{ .ip6 = .loopback(0) };
    var server = v6_local.listen(io, .{ .reuse_address = true }) catch return error.SkipZigTest;
    defer server.deinit(io);

    var addresses = [_]Io.net.IpAddress{
        .{ .ip4 = .loopback(1) },
        server.socket.address,
    };
    var connected: Io.net.IpAddress = undefined;
    const stream = try netutil.connectHostPortWithAddresses(io, "example.com", 9, 2, null, &addresses, &connected);
    stream.close(io);
    try std.testing.expect(connected == .ip6);

    const gpa = std.testing.allocator;
    const raw = "trojan://pw@example.com:2058?security=tls&sni=example.com";
    var proxy = try proxy_uri.parse(gpa, raw);
    defer proxy.deinit(gpa);
    const item: WorkItem = .{
        .raw = raw,
        .proxy = proxy,
        .addresses = &addresses,
        .dialed = connected,
    };
    const line = try printedLine(gpa, &item, false);
    defer if (line.owned) gpa.free(line.text);
    try std.testing.expect(std.mem.indexOf(u8, line.text, "[::1]:2058") != null);
    try std.testing.expect(std.mem.indexOf(u8, line.text, "127.0.0.1") == null);
    try std.testing.expect(std.mem.indexOf(u8, line.text, "sni=example.com") != null);
}

test "printed uri uses the probe address when grouping stored none" {
    const gpa = std.testing.allocator;
    const raw = "trojan://pw@example.com:443?security=tls&sni=example.com";
    var proxy = try proxy_uri.parse(gpa, raw);
    defer proxy.deinit(gpa);
    var none: [0]Io.net.IpAddress = .{};
    const item: WorkItem = .{
        .raw = raw,
        .proxy = proxy,
        .addresses = &none,
        .dialed = try Io.net.IpAddress.parse("203.0.113.9", 443),
    };
    const line = try printedLine(gpa, &item, false);
    defer if (line.owned) gpa.free(line.text);
    try std.testing.expectEqualStrings("trojan://pw@203.0.113.9:443?security=tls&sni=example.com", line.text);
}

test "printed TLS proxy URIs preserve the server name with an IP authority" {
    const gpa = std.testing.allocator;
    const schemes = [_][]const u8{
        "hy2://pass@",
        "trojan://pass@",
        "vless://00000000-1111-2222-3333-444444444444@",
    };
    const cases = [_]struct { suffix: []const u8, want: []const u8 }{
        .{ .suffix = "#name", .want = "?sni=example.com#name" },
        .{ .suffix = "?insecure=0#name", .want = "?insecure=0&sni=example.com#name" },
        .{ .suffix = "?sni=&insecure=0#name", .want = "?sni=example.com&insecure=0#name" },
        .{ .suffix = "?insecure=0&sni#name", .want = "?insecure=0&sni=example.com#name" },
        .{ .suffix = "?sni=alt%2Eexample#name", .want = "?sni=alt%2Eexample#name" },
    };
    for (schemes) |scheme| {
        for (cases) |case| {
            const raw = try gpa.print("{s}example.com:8443/{s}", .{ scheme, case.suffix });
            defer gpa.free(raw);
            var proxy = try proxy_uri.parse(gpa, raw);
            defer proxy.deinit(gpa);
            const item: WorkItem = .{
                .raw = raw,
                .proxy = proxy,
                .addresses = &.{},
                .dialed = try Io.net.IpAddress.parse("2001:db8::1", 8443),
            };
            const want = try gpa.print("{s}[2001:db8::1]:8443/{s}", .{ scheme, case.want });
            defer gpa.free(want);

            const line = try printedLine(gpa, &item, false);
            defer if (line.owned) gpa.free(line.text);

            try std.testing.expectEqualStrings(want, line.text);
        }
    }
}

test "raw output preserves the original hysteria2 URI" {
    const gpa = std.testing.allocator;
    const raw = "hy2://pass@example.com:8443/?insecure=0#My%20proxy";
    var proxy = try proxy_uri.parse(gpa, raw);
    defer proxy.deinit(gpa);
    const item: WorkItem = .{
        .raw = raw,
        .proxy = proxy,
        .addresses = &.{},
        .dialed = try Io.net.IpAddress.parse("2001:db8::1", 8443),
    };

    const line = try printedLine(gpa, &item, true);
    defer if (line.owned) gpa.free(line.text);

    try std.testing.expectEqualStrings(raw, line.text);
}

fn inTopTier(class: PrefClass) bool {
    return class == .vless2 or class == .trojan or class == .hysteria2;
}

fn selectWinner(lists: []const std.ArrayList(WorkItem), strategy: Strategy, prefer_stable: bool) ?*const WorkItem {
    var ranks: std.EnumArray(PrefClass, ?Rank) = .initFill(null);
    var best: std.EnumArray(PrefClass, ?*const WorkItem) = .initFill(null);
    for (lists) |list| {
        for (list.items) |*item| {
            const latency = item.latency orelse continue;
            const class = PrefClass.fromProxy(item.proxy) orelse continue;
            const rank = Rank.of(latency, prefer_stable);
            if (ranks.get(class)) |current| {
                if (current.lessThan(rank)) continue;
                if (std.meta.eql(rank, current) and latency.median_ms >= best.get(class).?.latency.?.median_ms) continue;
            }
            ranks.set(class, rank);
            best.set(class, item);
        }
    }

    const chosen = selectBestRanked(strategy, ranks) orelse return null;
    const stable_rank: ?Rank = if (prefer_stable) ranks.get(chosen).? else null;
    const top_tier = strategy == .hydec and inTopTier(chosen);

    var eligible: std.EnumArray(PrefClass, bool) = .initFill(false);
    var median: u64 = std.math.maxInt(u64);
    for (std.enums.values(PrefClass)) |class| {
        const rank = ranks.get(class) orelse continue;
        if (stable_rank) |required| {
            if (!std.meta.eql(rank, required)) continue;
        }
        if (strategy != .fastest and class != chosen and
            !(top_tier and inTopTier(class))) continue;
        eligible.set(class, true);
        median = @min(median, best.get(class).?.latency.?.median_ms);
    }

    const limit = median +| median / 10;
    var winner: ?*const WorkItem = null;
    var winner_class: PrefClass = chosen;
    for (lists) |list| {
        for (list.items) |*item| {
            const latency = item.latency orelse continue;
            if (latency.median_ms > limit) continue;
            const class = meanCandidateClass(item.proxy, latency, eligible, stable_rank) orelse continue;

            if (winner) |win| {
                const current = win.latency.?;
                if (latency.mean_ms > current.mean_ms) continue;
                if (latency.mean_ms == current.mean_ms) {
                    if (latency.median_ms > current.median_ms) continue;
                    if (latency.median_ms == current.median_ms and @backingInt(class) <= @backingInt(winner_class)) continue;
                }
            }
            winner = item;
            winner_class = class;
        }
    }
    return winner;
}

fn meanCandidateClass(
    proxy: proxy_uri.Proxy,
    latency: Latency,
    eligible: std.EnumArray(PrefClass, bool),
    stable_rank: ?Rank,
) ?PrefClass {
    const class = PrefClass.fromProxy(proxy) orelse return null;
    if (!eligible.get(class)) return null;
    if (stable_rank) |required| {
        if (!std.meta.eql(Rank.of(latency, true), required)) return null;
    }
    return class;
}

test "selectWinner uses the lowest median as the inclusive 10% boundary" {
    const proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var fast = [_]u64{ 100, 100, 300 };
    var close = [_]u64{ 100, 110, 110 };
    var outside = [_]u64{ 2, 121, 121 };
    var items = [_]WorkItem{
        .{ .raw = "fast", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&fast) },
        .{ .raw = "close", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&close) },
        .{ .raw = "outside", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&outside) },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = items.len;

    try std.testing.expectEqualStrings("close", selectWinner(&lists, .hydec, false).?.raw);
    std.mem.swap(WorkItem, &items[0], &items[2]);
    try std.testing.expectEqualStrings("close", selectWinner(&lists, .hydec, false).?.raw);
}

test "selectWinner respects strategy classes and prefer-stable ranking" {
    const proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var vless = proxy;
    vless.kind = .vless;
    vless.transport = .grpc;
    var shadowsocks = proxy;
    shadowsocks.kind = .shadowsocks;
    var vless_samples = [_]u64{ 100, 100, 300 };
    var trojan_samples = [_]u64{ 100, 110, 110 };
    var ss_samples = [_]u64{ 2, 105, 105 };
    var items = [_]WorkItem{
        .{ .raw = "vless", .proxy = vless, .addresses = &.{}, .latency = .fromSamples(&vless_samples) },
        .{ .raw = "trojan", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&trojan_samples) },
        .{ .raw = "ss", .proxy = shadowsocks, .addresses = &.{}, .latency = .fromSamples(&ss_samples) },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = items.len;

    try std.testing.expectEqualStrings("vless", selectWinner(&lists, .strict, false).?.raw);
    try std.testing.expectEqualStrings("trojan", selectWinner(&lists, .hydec, false).?.raw);
    try std.testing.expectEqualStrings("ss", selectWinner(&lists, .fastest, false).?.raw);
    items[2].latency.?.retries = 1;
    try std.testing.expectEqualStrings("trojan", selectWinner(&lists, .fastest, true).?.raw);
}

test "selectWinner includes hysteria2 in each strategy" {
    const trojan_proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var hy_fast_proxy = trojan_proxy;
    hy_fast_proxy.kind = .hysteria2;
    const hy_steady_proxy = hy_fast_proxy;
    var trojan_samples = [_]u64{ 400, 400, 400 };
    var hy_fast = [_]u64{ 5, 5, 5 };
    var hy_steady = [_]u64{ 20, 20, 20 };
    var items = [_]WorkItem{
        .{ .raw = "hy-fast", .proxy = hy_fast_proxy, .addresses = &.{}, .latency = .fromSamples(&hy_fast) },
        .{ .raw = "hy-steady", .proxy = hy_steady_proxy, .addresses = &.{}, .latency = .fromSamples(&hy_steady) },
        .{ .raw = "trojan", .proxy = trojan_proxy, .addresses = &.{}, .latency = .fromSamples(&trojan_samples) },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = items.len;

    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .fastest, false).?.raw);
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .hydec, false).?.raw);
    try std.testing.expectEqualStrings("trojan", selectWinner(&lists, .strict, false).?.raw);
    items[2].latency.?.retries = 1;
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .strict, true).?.raw);

    items[2].latency = null;
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .fastest, false).?.raw);
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .strict, true).?.raw);

    items[0].latency.?.retries = 1;
    try std.testing.expectEqualStrings("hy-steady", selectWinner(&lists, .hydec, true).?.raw);
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .hydec, false).?.raw);

    var low_median = [_]u64{ 100, 100, 1000 };
    var low_mean = [_]u64{ 100, 110, 120 };
    items[0].latency = .fromSamples(&low_median);
    items[1].latency = .fromSamples(&low_mean);
    for ([_]Strategy{ .hydec, .strict }) |strategy| {
        try std.testing.expectEqualStrings("hy-steady", selectWinner(&lists, strategy, false).?.raw);
        try std.testing.expectEqualStrings("hy-steady", selectWinner(&lists, strategy, true).?.raw);
    }

    items[2].latency = items[0].latency;
    try std.testing.expectEqualStrings("hy-steady", selectWinner(&lists, .hydec, false).?.raw);
    items[2].latency = null;

    var tied = [_]u64{ 10, 10, 10 };
    items[0].latency = .fromSamples(&tied);
    items[1].latency = .fromSamples(&tied);
    try std.testing.expectEqualStrings("hy-fast", selectWinner(&lists, .hydec, false).?.raw);
    std.mem.swap(WorkItem, &items[0], &items[1]);
    try std.testing.expectEqualStrings("hy-steady", selectWinner(&lists, .hydec, false).?.raw);

    items[0].latency = null;
    items[1].latency = null;
    try std.testing.expect(selectWinner(&lists, .hydec, false) == null);
}

test "selectWinner with prefer-stable uses mean only for close medians at equal rank" {
    const proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var fast = [_]u64{ 95, 100, 150 };
    var steady = [_]u64{ 60, 105, 150 };
    var outside = [_]u64{ 2, 111, 150 };
    var slower_worst = [_]u64{ 2, 100, 151 };
    var items = [_]WorkItem{
        .{ .raw = "fast", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&fast) },
        .{ .raw = "steady", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&steady) },
        .{ .raw = "outside", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&outside) },
        .{ .raw = "slower_worst", .proxy = proxy, .addresses = &.{}, .latency = .fromSamples(&slower_worst) },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = items.len;

    try std.testing.expectEqualStrings("steady", selectWinner(&lists, .hydec, true).?.raw);
    std.mem.swap(WorkItem, &items[0], &items[2]);
    try std.testing.expectEqualStrings("steady", selectWinner(&lists, .hydec, true).?.raw);
    items[1].latency.?.retries = 1;
    try std.testing.expectEqualStrings("fast", selectWinner(&lists, .hydec, true).?.raw);
}

test "selectWinner with fastest breaks equal means and medians by protocol preference" {
    const trojan_proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var vless = trojan_proxy;
    vless.kind = .vless;
    vless.transport = .grpc;
    var shadowsocks = trojan_proxy;
    shadowsocks.kind = .shadowsocks;
    var fast = [_]u64{ 100, 100, 300 };
    var steady = [_]u64{ 109, 109, 109 };
    const latency: Latency = .fromSamples(&steady);
    var items = [_]WorkItem{
        .{ .raw = "ss", .proxy = shadowsocks, .addresses = &.{}, .latency = .fromSamples(&fast) },
        .{ .raw = "trojan", .proxy = trojan_proxy, .addresses = &.{}, .latency = latency },
        .{ .raw = "vless", .proxy = vless, .addresses = &.{}, .latency = latency },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = items.len;

    try std.testing.expectEqualStrings("vless", selectWinner(&lists, .fastest, false).?.raw);
    std.mem.swap(WorkItem, &items[1], &items[2]);
    try std.testing.expectEqualStrings("vless", selectWinner(&lists, .fastest, false).?.raw);
}

test "selectWinner with prefer-stable anchors the median window at the lowest eligible median" {
    const trojan_proxy: proxy_uri.Proxy = .{
        .kind = .trojan,
        .raw = "",
        .host = "192.0.2.1",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var vless = trojan_proxy;
    vless.kind = .vless;
    vless.transport = .grpc;
    var vless_samples = [_]u64{ 150, 150, 200 };
    var fast_trojan_samples = [_]u64{ 100, 100, 200 };
    var slower_trojan_samples = [_]u64{ 100, 137, 200 };
    var items = [_]WorkItem{
        .{ .raw = "vless", .proxy = vless, .addresses = &.{}, .latency = .fromSamples(&vless_samples) },
        .{ .raw = "trojan_fast", .proxy = trojan_proxy, .addresses = &.{}, .latency = .fromSamples(&fast_trojan_samples) },
        .{ .raw = "trojan_slower", .proxy = trojan_proxy, .addresses = &.{}, .latency = .fromSamples(&slower_trojan_samples) },
    };
    var lists = [_]std.ArrayList(WorkItem){.initBuffer(&items)};
    lists[0].items.len = 2;
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .fastest, true).?.raw);
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .hydec, true).?.raw);
    try std.testing.expectEqualStrings("vless", selectWinner(&lists, .strict, true).?.raw);

    // Adding a strictly slower Trojan node must not displace trojan_fast.
    lists[0].items.len = items.len;
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .fastest, true).?.raw);
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .hydec, true).?.raw);

    // A higher-class tie on worst sample that falls outside the 10% median window
    // cannot win even with a lower mean.
    var vless_low_mean = [_]u64{ 1, 150, 200 };
    items[0].latency = .fromSamples(&vless_low_mean);
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .fastest, true).?.raw);
    try std.testing.expectEqualStrings("trojan_fast", selectWinner(&lists, .hydec, true).?.raw);
    try std.testing.expectEqualStrings("vless", selectWinner(&lists, .strict, true).?.raw);
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

test "probeOne rejects Trojan transports it cannot carry before dialing" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{
        "trojan://pw@192.0.2.1:443?type=grpc&serviceName=x#g",
        "trojan://pw@192.0.2.1:443?type=httpupgrade#h",
    }) |line| {
        // Arrange
        var proxy = try proxy_uri.parse(gpa, line);
        defer proxy.deinit(gpa);
        var stage: util.Stage = .setup;

        // Act / Assert: 192.0.2.1 is TEST-NET, so reaching the dial would hang or fail differently.
        try std.testing.expectError(error.UnsupportedTransport, probeOne(gpa, std.testing.io, proxy, util.LATENCY_TARGET, 1, null, null, &stage, null));
        try std.testing.expectEqual(util.Stage.setup, stage);
    }
}

test "probeOne rejects non-TLS Trojan security before dialing" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{
        "trojan://pw@192.0.2.1:443?security=none#n",
        "trojan://pw@192.0.2.1:443?security=reality#r",
    }) |line| {
        // Arrange
        var proxy = try proxy_uri.parse(gpa, line);
        defer proxy.deinit(gpa);
        var stage: util.Stage = .setup;

        // Act / Assert: 192.0.2.1 is TEST-NET, so reaching the dial would fail differently.
        try std.testing.expectError(error.UnsupportedSecurity, probeOne(gpa, std.testing.io, proxy, util.LATENCY_TARGET, 1, null, null, &stage, null));
        try std.testing.expectEqual(util.Stage.setup, stage);
    }
}

test "probeOne rejects SS plugins before opening a socket" {
    if (comptime builtin.target.os.tag == .windows) return error.SkipZigTest;

    // Arrange: both URI forms point at a real listener, so a direct SS dial is observable.
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    var sip_buf: [256]u8 = undefined;
    const sip = try std.fmt.bufPrint(&sip_buf, "ss://{s}@127.0.0.1:{d}/?plugin=obfs%2Dlocal", .{
        "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk",
        port,
    });
    var sip_duplicate_buf: [256]u8 = undefined;
    const sip_duplicate = try std.fmt.bufPrint(&sip_duplicate_buf, "ss://{s}@127.0.0.1:{d}/?plugin=&plugin=obfs%2Dlocal", .{
        "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk",
        port,
    });
    var plain_buf: [128]u8 = undefined;
    const plain = try std.fmt.bufPrint(&plain_buf, "chacha20-ietf-poly1305:test-password@127.0.0.1:{d}", .{port});
    var blob_buf: [256]u8 = undefined;
    const blob = std.base64.standard_no_pad.Encoder.encode(&blob_buf, plain);
    var legacy_buf: [384]u8 = undefined;
    const legacy = try std.fmt.bufPrint(&legacy_buf, "ss://{s}/?plugin=obfs-local", .{blob});
    var legacy_duplicate_buf: [384]u8 = undefined;
    const legacy_duplicate = try std.fmt.bufPrint(&legacy_duplicate_buf, "ss://{s}/?plugin=&plugin=obfs-local", .{blob});

    for ([_][]const u8{ sip, sip_duplicate, legacy, legacy_duplicate }) |line| {
        var proxy = try proxy_uri.parse(gpa, line);
        defer proxy.deinit(gpa);
        var stage: util.Stage = .setup;
        try std.testing.expectError(error.UnsupportedPlugin, probeOne(gpa, io, proxy, util.LATENCY_TARGET, 1, null, null, &stage, null));
        try std.testing.expectEqual(util.Stage.setup, stage);
    }

    var fds = [_]std.posix.pollfd{.{
        .fd = server.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&fds, 0));
}

test "FailReason appends the stage once the attempt got past setup" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "rejected/closed@handshake",
        try std.mem.print(&buf, "{f}", .{FailReason{ .err = error.ConnectionResetByPeer, .stage = .handshake }}),
    );
    try std.testing.expectEqualStrings(
        "slow/timeout@connect",
        try std.mem.print(&buf, "{f}", .{FailReason{ .err = error.ConnectTimeout, .stage = .connect }}),
    );
    try std.testing.expectEqualStrings(
        "alpn/h2-breaks-ws",
        try std.mem.print(&buf, "{f}", .{FailReason{ .err = error.WsAlpnHttp2, .stage = .setup }}),
    );
}

test "Latency.fromSamples: median ignores a single spike, min/max keep it" {
    var spike = [_]u64{ 40, 300, 42 };
    try std.testing.expectEqual(Latency{ .median_ms = 42, .mean_ms = 382.0 / 3.0, .min_ms = 40, .max_ms = 300 }, Latency.fromSamples(&spike));
    var even = [_]u64{ 30, 10, 20, 40 };
    try std.testing.expectEqual(Latency{ .median_ms = 30, .mean_ms = 25, .min_ms = 10, .max_ms = 40 }, Latency.fromSamples(&even));
    var one = [_]u64{7};
    try std.testing.expectEqual(Latency{ .median_ms = 7, .mean_ms = 7, .min_ms = 7, .max_ms = 7 }, Latency.fromSamples(&one));
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
    const retries = try collectSamples(FakeProber{ .script = &script, .calls = &calls }, &samples);

    // Assert
    try std.testing.expectEqual(@as(usize, 1), retries);
    try std.testing.expectEqual(@as(usize, 4), calls);
    try std.testing.expectEqualSlices(u64, &.{ 10, 20, 30 }, &samples);
}

test "collectSamples reports no retries on a clean run" {
    var calls: usize = 0;
    const script = [_]anyerror!u64{ 10, 20, 30 };
    var samples: [PROBE_ATTEMPTS]u64 = undefined;

    try std.testing.expectEqual(@as(usize, 0), try collectSamples(FakeProber{ .script = &script, .calls = &calls }, &samples));
}

test "Rank.of: median by default, worst sample with --prefer-stable" {
    // Arrange
    const spiky: Latency = .{ .median_ms = 42, .mean_ms = 382.0 / 3.0, .min_ms = 40, .max_ms = 300 };
    const steady: Latency = .{ .median_ms = 46, .mean_ms = 46, .min_ms = 45, .max_ms = 47 };

    // Act / Assert
    try std.testing.expect(Rank.of(spiky, false).lessThan(Rank.of(steady, false)));
    try std.testing.expect(Rank.of(steady, true).lessThan(Rank.of(spiky, true)));
}

test "Rank.of: a retried candidate loses to any clean one only with --prefer-stable" {
    const retried: Latency = .{ .median_ms = 20, .mean_ms = 20, .min_ms = 20, .max_ms = 20, .retries = 1 };
    const clean: Latency = .{ .median_ms = 200, .mean_ms = 200, .min_ms = 200, .max_ms = 200 };

    try std.testing.expect(Rank.of(clean, true).lessThan(Rank.of(retried, true)));
    try std.testing.expect(Rank.of(retried, false).lessThan(Rank.of(clean, false)));
    // Among retried candidates the worst sample still decides.
    const retried_slow: Latency = .{ .median_ms = 30, .mean_ms = 30, .min_ms = 30, .max_ms = 30, .retries = 1 };
    try std.testing.expect(Rank.of(retried, true).lessThan(Rank.of(retried_slow, true)));
}

test "selectBestRanked: retried classes compete only when nothing is clean" {
    var ranks: std.EnumArray(PrefClass, ?Rank) = .initFill(null);
    ranks.set(.vless2, .{ .retried = true, .ms = 50 });
    ranks.set(.shadowsocks, .{ .retried = false, .ms = 100 });
    // A clean SS beats a faster, retried VLESS² (hydec would otherwise keep VLESS²).
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestRanked(.hydec, ranks));

    ranks.set(.shadowsocks, .{ .retried = true, .ms = 100 });
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestRanked(.hydec, ranks));

    try std.testing.expectEqual(@as(?PrefClass, null), selectBestRanked(.hydec, .initFill(null)));
}

test "RetrySuffix renders only when a retry happened" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings(", retry 1", try std.mem.print(&buf, "{f}", .{RetrySuffix{ .retries = 1 }}));
    try std.testing.expectEqualStrings("", try std.mem.print(&buf, "{f}", .{RetrySuffix{ .retries = 0 }}));
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

test "isTransient splits network blips from deterministic failures" {
    try std.testing.expect(isTransient(error.Timeout));
    try std.testing.expect(isTransient(error.ConnectTimeout));
    try std.testing.expectEqualStrings("slow/timeout", failHint(error.ConnectTimeout));
    try std.testing.expect(isTransient(error.ConnectionResetByPeer));
    try std.testing.expect(isTransient(error.EndOfStream));
    // Same "peer closed" set the log calls rejected/closed.
    for ([_]anyerror{ error.SocketUnconnected, error.NotOpenForReading, error.NotOpenForWriting }) |e| {
        try std.testing.expect(isTransient(e));
        try std.testing.expectEqualStrings("rejected/closed", failHint(e));
    }
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
    var groups = try collectGroups(gpa, std.testing.io, &lines, &stats, false, 3);
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), groups.count());
    try std.testing.expectEqual(@as(usize, 2), groups.get("192.0.2.1").?.items.len);
    try std.testing.expectEqual(@as(usize, 1), groups.get("198.51.100.1").?.items.len);
}

const FakeResolver = struct {
    fn sameName(host: []const u8, name: []const u8) bool {
        const without_root = if (host.len > 1 and host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
        return std.ascii.eqlIgnoreCase(without_root, name);
    }

    fn lookup(_: @This(), _: Io, host: []const u8, _: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
        if (sameName(host, "example.com") or sameName(host, "one.example") or sameName(host, "after.example")) {
            addresses[0] = try Io.net.IpAddress.parse(if (sameName(host, "example.com")) "192.0.2.10" else "192.0.2.1", 0);
            return addresses[0..1];
        }
        if (sameName(host, "two.example")) {
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.2", 0);
            return addresses[0..1];
        }
        if (sameName(host, "bridge.example")) {
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.2", 0);
            addresses[1] = try Io.net.IpAddress.parse("192.0.2.1", 0);
            return addresses[0..2];
        }
        if (sameName(host, "other.example")) {
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.3", 0);
            return addresses[0..1];
        }
        return error.UnknownHostName;
    }
};

test "collectGroups resolves DNS aliases and root dots and normalizes IP literals" {
    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@EXAMPLE.COM:443#a",
        "trojan://pw@example.com.:443#b",
        "trojan://pw@[2001:db8:0:0:0:0:0:1]:443#c",
        "trojan://pw@[2001:db8::1]:443#d",
        "trojan://pw@UNRESOLVED.EXAMPLE:443#e",
        "trojan://pw@unresolved.example.:443#f",
    };
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 5, FakeResolver{});
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 3), groups.count());
    const resolved = groups.get("192.0.2.10").?.items;
    try std.testing.expectEqual(@as(usize, 2), resolved.len);
    try std.testing.expectEqualStrings("EXAMPLE.COM", resolved[0].proxy.host);
    try std.testing.expectEqualStrings("example.com.", resolved[1].proxy.host);
    try std.testing.expectEqualSlices(Io.net.IpAddress, &.{try Io.net.IpAddress.parse("192.0.2.10", 443)}, resolved[0].addresses);
    try std.testing.expectEqual(@as(usize, 2), groups.get("2001:db8::1").?.items.len);
    const unresolved = groups.get("unresolved").?.items;
    try std.testing.expectEqual(@as(usize, 2), unresolved.len);
    try std.testing.expectEqualStrings("UNRESOLVED.EXAMPLE", unresolved[0].proxy.host);
    try std.testing.expectEqualStrings("unresolved.example.", unresolved[1].proxy.host);
    try std.testing.expectEqual(@as(usize, 0), unresolved[0].addresses.len);
}

test "collectGroups resolves case variants once and sets each entry's port" {
    const Resolver = struct {
        calls: *std.atomic.Value(usize),

        fn lookup(self: @This(), _: Io, _: []const u8, _: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
            _ = self.calls.fetchAdd(1, .monotonic);
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.20", 0);
            return addresses[0..1];
        }
    };

    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@round.example:443#a",
        "trojan://pw@ROUND.EXAMPLE:8443#b",
    };
    var calls: std.atomic.Value(usize) = .init(0);
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 5, Resolver{ .calls = &calls });
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 1), calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), groups.count());
    const items = groups.get("192.0.2.20").?.items;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqual(@as(u16, 443), items[0].addresses[0].getPort());
    try std.testing.expectEqual(@as(u16, 8443), items[1].addresses[0].getPort());
}

test "collectGroups merges aliases, IP literals, and overlapping resolved address sets" {
    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@one.example:443#a",
        "trojan://pw@two.example:443#b",
        "trojan://pw@bridge.example:443#c",
        "trojan://pw@other.example:443#d",
        "trojan://pw@after.example:443#e",
        "trojan://pw@192.0.2.1:443#literal",
        "trojan://pw@[::ffff:192.0.2.1]:8443#mapped",
    };
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 5, FakeResolver{});
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), groups.count());
    const merged = groups.get("192.0.2.2").?.items;
    try std.testing.expectEqual(@as(usize, 6), merged.len);
    try std.testing.expectEqualStrings("two.example", merged[0].proxy.host);
    try std.testing.expectEqualStrings("one.example", merged[1].proxy.host);
    try std.testing.expectEqualStrings("bridge.example", merged[2].proxy.host);
    try std.testing.expectEqualStrings("after.example", merged[3].proxy.host);
    try std.testing.expectEqualStrings("192.0.2.1", merged[4].proxy.host);
    try std.testing.expectEqualStrings("::ffff:192.0.2.1", merged[5].proxy.host);
    try std.testing.expectEqual(@as(usize, 1), groups.get("192.0.2.3").?.items.len);
}

test "collectGroups puts distinct unresolved names in one sequential queue" {
    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@missing-a.example:443#a",
        "trojan://pw@other.example:443#known",
        "trojan://pw@missing-b.example:443#b",
    };
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 5, FakeResolver{});
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), groups.count());
    try std.testing.expectEqual(@as(usize, 1), groups.get("192.0.2.3").?.items.len);
    const unresolved = groups.get("unresolved").?.items;
    try std.testing.expectEqual(@as(usize, 2), unresolved.len);
    try std.testing.expectEqualStrings("missing-a.example", unresolved[0].proxy.host);
    try std.testing.expectEqualStrings("missing-b.example", unresolved[1].proxy.host);
}

test "collectGroups retries a name server failure within the original deadline" {
    const Resolver = struct {
        calls: *std.atomic.Value(usize),
        first_deadline: *i128,

        fn lookup(self: @This(), _: Io, _: []const u8, deadline: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
            const call = self.calls.fetchAdd(1, .monotonic);
            if (call == 0) {
                self.first_deadline.* = deadline;
                return error.NameServerFailure;
            }
            try std.testing.expectEqual(self.first_deadline.*, deadline);
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.30", 0);
            return addresses[0..1];
        }
    };

    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@flaky.example:443#a",
        "trojan://pw@flaky.example:8443#b",
        "trojan://pw@192.0.2.30:443#literal",
    };
    var calls: std.atomic.Value(usize) = .init(0);
    var first_deadline: i128 = undefined;
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 5, Resolver{
        .calls = &calls,
        .first_deadline = &first_deadline,
    });
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), groups.count());
    const items = groups.get("192.0.2.30").?.items;
    try std.testing.expectEqual(@as(usize, 3), items.len);
    for (items) |item| try std.testing.expectEqual(@as(?anyerror, null), item.resolution_error);
}

test "collectGroups preserves DNS errors without losing IP literals" {
    const Resolver = struct {
        fn lookup(_: @This(), _: Io, _: []const u8, _: i128, _: []Io.net.IpAddress) ![]Io.net.IpAddress {
            return error.Unexpected;
        }
    };
    const gpa = std.testing.allocator;
    const lines = [_][]const u8{
        "trojan://pw@late-a.example:443#a",
        "trojan://pw@late-b.example:443#b",
        "trojan://pw@192.0.2.40:443#literal",
    };
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &lines, &stats, false, 0, Resolver{});
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 2), groups.count());
    const unresolved = groups.get("unresolved").?.items;
    try std.testing.expectEqual(@as(usize, 2), unresolved.len);
    for (unresolved) |item| try std.testing.expectEqual(@as(?anyerror, error.Timeout), item.resolution_error);
    try std.testing.expectEqual(@as(usize, 1), groups.get("192.0.2.40").?.items.len);
}

test "collectGroups leaves resource failures eligible for a deferred DNS probe" {
    const Resolver = struct {
        fn lookup(_: @This(), _: Io, _: []const u8, _: i128, _: []Io.net.IpAddress) ![]Io.net.IpAddress {
            return error.SystemResources;
        }
    };
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const lines = [_][]const u8{
        "trojan://pw@temporarily-unresolved.example:443?type=grpc",
        "trojan://pw@192.0.2.1:443?type=grpc",
    };
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, io, &lines, &stats, false, 5, Resolver{});
    defer freeGroups(gpa, &groups);

    const item = groups.get("unresolved").?.items[0];
    try std.testing.expectEqual(@as(usize, 0), item.addresses.len);
    try std.testing.expectEqual(@as(?anyerror, null), item.resolution_error);

    var shared: Shared = .{
        .gpa = gpa,
        .io = io,
        .verbose = false,
        .check_volume = false,
        .timeout_secs = 5,
        .bind = null,
        .stats = &stats,
    };
    // The unsupported transport lets us exercise scheduling without a socket.
    var queue: HostQueue = .{ .lists = groups.values() };
    queue.work(&shared);
    try std.testing.expectEqual(@as(usize, 1), stats.tested);
    queue.workDeferred(&shared);
    try std.testing.expectEqual(@as(usize, 2), stats.tested);
}

test "resolveWorker gives a queued hostname a fresh budget after a timeout" {
    const Resolver = struct {
        first_deadline: *i128,
        second_deadline: *i128,

        fn lookup(self: @This(), io: Io, host: []const u8, deadline: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
            if (std.mem.eql(u8, host, "first.example")) {
                self.first_deadline.* = deadline;
                const until: Io.Clock.Timestamp = .{ .raw = .fromNanoseconds(@intCast(deadline)), .clock = .awake };
                try until.wait(io);
                return error.Timeout;
            }
            self.second_deadline.* = deadline;
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.1", 0);
            return addresses[0..1];
        }
    };
    const gpa = std.testing.allocator;
    var names = [_]NameResolution{ .{ .host = "first.example" }, .{ .host = "second.example" } };
    defer for (names) |name| gpa.free(name.addresses);
    var next: std.atomic.Value(usize) = .init(0);
    var oom: std.atomic.Value(bool) = .init(false);
    var first_deadline: i128 = 0;
    var second_deadline: i128 = 0;

    resolveWorker(&names, &next, &oom, gpa, std.testing.io, 1, Resolver{
        .first_deadline = &first_deadline,
        .second_deadline = &second_deadline,
    });

    try std.testing.expectEqual(@as(?anyerror, error.Timeout), names[0].err);
    try std.testing.expectEqual(@as(?anyerror, null), names[1].err);
    try std.testing.expectEqual(@as(usize, 1), names[1].addresses.len);
    try std.testing.expect(second_deadline - first_deadline >= std.time.ns_per_s);
}

test "collectGroups keeps DNS timeout without restarting the lookup" {
    const Resolver = struct {
        calls: *std.atomic.Value(usize),

        fn lookup(self: @This(), _: Io, _: []const u8, _: i128, _: []Io.net.IpAddress) ![]Io.net.IpAddress {
            _ = self.calls.fetchAdd(1, .monotonic);
            return error.Timeout;
        }
    };
    const gpa = std.testing.allocator;
    var calls: std.atomic.Value(usize) = .init(0);
    var stats: Stats = .{};
    var groups = try collectGroupsWithResolver(gpa, std.testing.io, &.{"trojan://pw@hung.example:443"}, &stats, false, 5, Resolver{ .calls = &calls });
    defer freeGroups(gpa, &groups);

    try std.testing.expectEqual(@as(usize, 1), calls.load(.monotonic));
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), groups.get("unresolved").?.items[0].resolution_error);
}

test "collectGroups resolves slow lookups in parallel" {
    // Arrange: the parallel lookups should complete in about one resolver delay.
    const SlowResolver = struct {
        fn lookup(_: @This(), io: Io, _: []const u8, deadline: i128, addresses: []Io.net.IpAddress) ![]Io.net.IpAddress {
            if (netutil.monoNow(io) >= deadline) return error.Timeout;
            io.sleep(.fromMilliseconds(300), .awake) catch {};
            if (netutil.monoNow(io) >= deadline) return error.Timeout;
            addresses[0] = try Io.net.IpAddress.parse("192.0.2.1", 0);
            return addresses[0..1];
        }
    };
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const lines = [_][]const u8{
        "trojan://pw@a.example:443#1",
        "trojan://pw@b.example:443#2",
        "trojan://pw@c.example:443#3",
        "trojan://pw@d.example:443#4",
        "trojan://pw@e.example:443#5",
        "trojan://pw@f.example:443#6",
        "trojan://pw@g.example:443#7",
        "trojan://pw@h.example:443#8",
    };
    var stats: Stats = .{};
    const start = netutil.monoNow(io);

    // Act
    var groups = try collectGroupsWithResolver(gpa, io, &lines, &stats, false, 2, SlowResolver{});
    defer freeGroups(gpa, &groups);

    // Assert: every entry resolved, and the pass took one lookup's time, not eight.
    try std.testing.expectEqual(@as(usize, 1), groups.count());
    const items = groups.values()[0].items;
    try std.testing.expectEqual(@as(usize, 8), items.len);
    for (items) |item| {
        try std.testing.expectEqual(@as(?anyerror, null), item.resolution_error);
        try std.testing.expectEqual(@as(usize, 1), item.addresses.len);
    }
    try std.testing.expect(netutil.elapsedMs(start, io) < 1500);
}

test "collectGroups owns keys for legacy SS hosts" {
    const gpa = std.testing.allocator;
    // method:password@host:port base64url
    const lines = [_][]const u8{
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3JkQDE5Mi4wLjIuMTo4Mzg4#legacy-a",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3JkQDE5Mi4wLjIuMTo0NDM#legacy-b",
    };
    var stats: Stats = .{};
    var groups = try collectGroups(gpa, std.testing.io, &lines, &stats, false, 3);
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
    try std.testing.expectEqualStrings("unsupported-obfs", failHint(error.UnsupportedObfs));
}

test "XHTTP reads panel defaults and configured padding from share links" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const address = "vless://00000000-1111-2222-3333-444444444444@192.0.2.10:443?type=xhttp&security=reality";
    const cases = [_]struct { query: []const u8, min: u32, max: u32 }{
        .{ .query = "", .min = 100, .max = 1000 },
        .{ .query = "&mode=auto&extra=%7B%22scMaxEachPostBytes%22%3A%221000000%22%2C+%22scMinPostsIntervalMs%22%3A%2230%22%2C+%22xPaddingBytes%22%3A%22100-1000%22%7D", .min = 100, .max = 1000 },
        .{ .query = "&mode=stream-one&x_padding_bytes=500%2D1500&extra=%7B%22noGRPCHeader%22:false,%22xPaddingObfsMode%22:false,%22downloadSettings%22:null%7D", .min = 500, .max = 1500 },
        .{ .query = "&x_padding_bytes=500-1500&extra=%257B%2522xPaddingBytes%2522%253A%25221500-1600%2522%257D", .min = 1500, .max = 1600 },
        .{ .query = "&extra=%7B%22mode%22:%22stream-one%22,%22xPaddingBytes%22:800%7D", .min = 800, .max = 800 },
        .{ .query = "&extra=%7B%22headers%22:%7B%7D%7D", .min = 100, .max = 1000 },
        .{ .query = "&extra=%7B%22headers%22:null%7D", .min = 100, .max = 1000 },
    };
    for (cases) |case| {
        const raw = try std.mem.concat(gpa, u8, &.{ address, case.query });
        const proxy = try proxy_uri.parse(gpa, raw);

        const options = try parseXhttp(gpa, proxy);

        try std.testing.expectEqual(reality.XhttpPadding{ .min = case.min, .max = case.max }, options.padding);
    }
}

test "XHTTP rejects incompatible options and malformed padding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const address = "vless://00000000-1111-2222-3333-444444444444@192.0.2.10:443?type=xhttp&security=reality";
    const cases = [_]struct { query: []const u8, err: anyerror }{
        .{ .query = "&extra=%7B%22xPaddingObfsMode%22:true%7D", .err = error.UnsupportedXhttpExtra },
        .{ .query = "&extra=%7B%22noGRPCHeader%22:true%7D", .err = error.UnsupportedXhttpExtra },
        .{ .query = "&extra=%7B%22downloadSettings%22:%7B%7D%7D", .err = error.UnsupportedXhttpExtra },
        .{ .query = "&extra=%7B%22headers%22:%7B%22X-Route%22:%22fixture%22%7D%7D", .err = error.UnsupportedXhttpExtra },
        .{ .query = "&extra=%7B%22headers%22:%5B%5D%7D", .err = error.InvalidXhttpExtra },
        .{ .query = "&mode=packet-up", .err = error.UnsupportedXhttpMode },
        .{ .query = "&mode=auto&extra=%7B%22mode%22:%22stream-up%22%7D", .err = error.UnsupportedXhttpMode },
        .{ .query = "&extra=%7B", .err = error.InvalidXhttpExtra },
        .{ .query = "&x_padding_bytes=1500-500", .err = error.InvalidXhttpPadding },
        .{ .query = "&x_padding_bytes=0-500", .err = error.InvalidXhttpPadding },
        .{ .query = "&extra=%7B%22xPaddingBytes%22:-1%7D", .err = error.InvalidXhttpPadding },
    };
    for (cases) |case| {
        const raw = try std.mem.concat(gpa, u8, &.{ address, case.query });
        const proxy = try proxy_uri.parse(gpa, raw);

        try std.testing.expectError(case.err, parseXhttp(gpa, proxy));
    }
}

test "PrefClass.fromProxy maps vless transport and protocols" {
    const gpa = std.testing.allocator;
    const v2_line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:2053?security=reality&type=grpc&mode=gun&serviceName=xyz&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#VLESS2
    ;
    const v3_line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:8444?security=reality&type=tcp&flow=xtls-rprx-vision&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#VLESS3
    ;
    const xhttp_line = "vless://00000000-1111-2222-3333-444444444444@192.0.2.10:443?security=reality&type=xhttp&mode=auto&path=%2Ftest";
    const ss_line = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.1:8388#ss";
    const tj_line = "trojan://password@192.0.2.1:443?security=tls&type=ws&sni=example.com&path=%2F#tj";

    var v2 = try proxy_uri.parse(gpa, v2_line);
    defer v2.deinit(gpa);
    var v3 = try proxy_uri.parse(gpa, v3_line);
    defer v3.deinit(gpa);
    var xhttp = try proxy_uri.parse(gpa, xhttp_line);
    defer xhttp.deinit(gpa);
    var ss_p = try proxy_uri.parse(gpa, ss_line);
    defer ss_p.deinit(gpa);
    var tj = try proxy_uri.parse(gpa, tj_line);
    defer tj.deinit(gpa);

    try std.testing.expect(PrefClass.fromProxy(v2) == .vless2);
    try std.testing.expect(PrefClass.fromProxy(v3) == .vless3);
    try std.testing.expectEqual(proxy_uri.Transport.xhttp, xhttp.transport);
    try std.testing.expectEqual(@as(?PrefClass, .vless3), PrefClass.fromProxy(xhttp));
    try std.testing.expect(volumeRefusalIgnored(xhttp));
    try std.testing.expect(PrefClass.fromProxy(ss_p) == .shadowsocks);
    try std.testing.expect(PrefClass.fromProxy(tj) == .trojan);
}

test "selectBestClass hydec prefers VLESS2 then demotes on 2x / SS on 3x" {
    // Fastest VLESS² wins when close to others.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 100, 90, 80, null, null));
    // Exactly 2×: keep VLESS² ("больше чем в два раза").
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 200, 100, null, null, null));
    // Strictly more than 2× → VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 201, 100, null, null, null));
    // SS needs ≥3× vs VLESS².
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 299, null, 100, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 300, null, 100, null, null));
    // Demoted to VLESS³; SS eligible via VLESS²≥3×SS, then 3× vs VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 600, 100, 40, null, null)); // 100 ≯ 3×40
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 600, 100, 30, null, null)); // 100 > 3×30
    // VLESS² kept vs VLESS³, but SS eligible (≥3×); still apply 3× to VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 100, 40, 20, null, null)); // 40 ≯ 3×20
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 100, 70, 20, null, null)); // 70 > 3×20
    // No VLESS² / Trojan: VLESS³ vs SS at 2×.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 200, 100, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, 201, 100, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, null, 40, null, null));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.hydec, null, null, null, null, null));
}

test "selectBestClass hydec ranks Trojan in the VLESS2 tier" {
    // Both present: the faster of the two stands for the tier, VLESS² on a tie.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, 100, 90, 80, 50, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 50, 90, 80, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 100, null, null, 100, null));
    // Trojan beats a faster SS until the 3× gap, even with no VLESS at all.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, null, 20, 40, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, null, 10, 40, null));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, null, null, 10, null));
    // Trojan alone in the tier: same thresholds VLESS² would get.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, 100, null, 200, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 100, null, 201, null));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, null, null, 100, 299, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, null, 100, 300, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 100, 40, 600, null));
    // The faster of VLESS² / Trojan is what SS and VLESS³ are compared against.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, 600, null, 100, 250, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 600, null, 100, 300, null));
    // Live HyNet NL: VLESS² 333, VLESS³ 330, SS 161, Trojan 307 — Trojan (307 < 3×161).
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.hydec, 333, 330, 161, 307, null));
}

test "selectBestClass hydec ignores ratio wins below the absolute gap" {
    // 3× but only 14 ms apart: no VLESS²→SS demotion.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 21, null, 7, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 23, null, 7, null, null));
    // >2× but 15 ms apart (not more): no VLESS²→VLESS³ demotion.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.hydec, 29, 14, null, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 30, 14, null, null, null));
    // No VLESS²: VLESS³ 20 ms vs SS 5 ms stays VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 20, 5, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, 21, 5, null, null));
    // SS eligible vs VLESS², VLESS³ >3× SS yet within the gap: keep VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, 100, 20, 5, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, 100, 21, 5, null, null));
}

test "selectBestClass fastest picks minimum latency" {
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.fastest, 100, 90, 80, 50, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.fastest, 300, 100, 40, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.fastest, 201, 100, null, null, null));
    // Tie: keep the higher preference class.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.fastest, 100, 100, 100, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.fastest, null, 100, 100, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.fastest, null, 100, 100, null, null));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.fastest, null, null, null, null, null));
}

test "selectBestClass strict never demotes" {
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(.strict, 500, 10, 5, 1, null));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.strict, null, 200, 10, 300, null));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.strict, null, 200, 10, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.strict, null, null, 40, null, null));
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(.strict, null, null, null, 10, null));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(.strict, null, null, null, null, null));
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

test "Hysteria 2 follows top-tier demotion, strict order, and fastest tie order" {
    try std.testing.expectEqual(@as(?PrefClass, .hysteria2), selectBestClass(.hydec, null, 100, null, null, 200));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.hydec, null, 100, null, null, 201));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(.hydec, null, null, 100, null, 300));
    try std.testing.expectEqual(@as(?PrefClass, .hysteria2), selectBestClass(.strict, null, 30, 10, null, 500));
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(.fastest, null, 25, 25, null, 25));
}

test "volumeError names only post-connect stalls and keeps lookup timeouts" {
    try std.testing.expectEqual(error.Timeout, volumeError(error.Timeout, .setup));
    try std.testing.expectEqual(error.Timeout, volumeError(error.Timeout, .connect));
    try std.testing.expectEqual(error.ConnectionTimedOut, volumeError(error.ConnectionTimedOut, .connect));
    try std.testing.expectEqual(error.VolumeStalled, volumeError(error.Timeout, .handshake));
    try std.testing.expectEqual(error.VolumeStalled, volumeError(error.ConnectionTimedOut, .reply));
    try std.testing.expectEqual(error.ConnectTimeout, volumeError(error.ConnectTimeout, .connect));
    try std.testing.expectEqual(error.ProbeResponseMismatch, volumeError(error.ProbeResponseMismatch, .reply));
    try std.testing.expectEqualStrings("volume/stalled", failHint(error.VolumeStalled));
    try std.testing.expectEqualStrings("slow/timeout", failHint(volumeError(error.Timeout, .connect)));
}

test "volume refusal is ignored only after a warmup" {
    const vless_tcp: proxy_uri.Proxy = .{
        .kind = .vless,
        .raw = "",
        .host = "",
        .port = 443,
        .userinfo = "",
        .query = "",
        .transport = .tcp,
    };
    try std.testing.expect(!volumeRefusalIgnored(vless_tcp));

    var vless_grpc = vless_tcp;
    vless_grpc.transport = .grpc;
    try std.testing.expect(volumeRefusalIgnored(vless_grpc));

    var trojan_proxy = vless_tcp;
    trojan_proxy.kind = .trojan;
    try std.testing.expect(volumeRefusalIgnored(trojan_proxy));
}

test "probeLatency returns a grouping DNS timeout before probing" {
    const proxy: proxy_uri.Proxy = .{
        .kind = .unsupported,
        .raw = "",
        .host = "would-resolve.example",
        .port = 443,
        .userinfo = "",
        .query = "",
    };
    var stage: util.Stage = .setup;
    var dialed: ?Io.net.IpAddress = null;
    try std.testing.expectError(error.Timeout, probeLatency(
        std.testing.allocator,
        std.testing.io,
        proxy,
        5,
        null,
        null,
        error.Timeout,
        true,
        &stage,
        &dialed,
    ));
}

test "failHint names the ALPN and plugin failures" {
    try std.testing.expectEqualStrings("alpn/h2-breaks-ws", failHint(error.WsAlpnHttp2));
    try std.testing.expectEqualStrings("alpn/too-many", failHint(error.TooManyAlpnProtocols));
    try std.testing.expectEqualStrings("alpn/invalid", failHint(error.InvalidAlpnProtocol));
    try std.testing.expectEqualStrings("unsupported-plugin", failHint(error.UnsupportedPlugin));
}
