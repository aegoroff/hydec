const std = @import("std");
const proxy_uri = @import("proxy_uri.zig");
const util = @import("util.zig");
const ss = @import("ss.zig");
const trojan = @import("trojan.zig");
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
};

const WorkItem = struct {
    raw: []const u8,
    proxy: proxy_uri.Proxy,
};

/// Cap concurrent host workers so a large subscription cannot exhaust OS threads.
const max_parallel_hosts: usize = 64;

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

/// How many successful probes are required for `ping` / `best` (fail-fast on first error).
pub const probe_attempts: usize = 3;

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
            const sni = proxy.getParam("sni") orelse proxy.host;
            const path_enc = proxy.getParam("path") orelse "/";
            const path = try util.urlDecodeStrict(gpa, path_enc);
            defer gpa.free(path);
            const host_hdr = proxy.getParam("host") orelse sni;
            const allow_insecure = util.queryParamTruthy(proxy.query, "allowInsecure") or
                util.queryParamTruthy(proxy.query, "allow_insecure") or
                util.queryParamTruthy(proxy.query, "insecure");
            break :blk try trojan.probe(
                gpa,
                io,
                proxy.host,
                proxy.port,
                proxy.userinfo,
                sni,
                proxy.transport == .ws,
                path,
                host_hdr,
                allow_insecure,
                timeout_secs,
                bind,
            );
        },
        .vless => blk: {
            if (proxy.security != .reality) return error.UnsupportedSecurity;
            if (proxy.transport == .other) return error.UnsupportedTransport;
            if (proxy.transport == .ws) return error.UnsupportedTransport;

            const enc = proxy.getParam("encryption") orelse "none";
            if (enc.len != 0 and !std.mem.eql(u8, enc, "none")) return error.UnsupportedVlessEncryption;

            const sni = proxy.getParam("sni") orelse proxy.host;
            const pbk = proxy.getParam("pbk") orelse return error.MissingRealityPublicKey;
            const sid = proxy.getParam("sid") orelse "";
            const flow = proxy.getParam("flow") orelse "";
            const service = proxy.getParam("serviceName") orelse "";
            const use_grpc = proxy.transport == .grpc;
            if (use_grpc) {
                const mode = proxy.getParam("mode") orelse "gun";
                if (!std.mem.eql(u8, mode, "gun") and mode.len != 0) return error.UnsupportedGrpcMode;
            }
            const authority = proxy.getParam("authority") orelse "";
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

/// Rounded mean of `samples` (at least one). Used by `probeAverage` and tests.
pub fn averageMs(samples: []const u64) u64 {
    std.debug.assert(samples.len > 0);
    var sum: u64 = 0;
    for (samples) |s| sum += s;
    return (sum + samples.len / 2) / samples.len;
}

/// Run `probe_attempts` full probes; stop on the first failure.
/// On success returns the rounded average latency in ms.
pub fn probeAverage(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    timeout_secs: u32,
    bind: ?[]const u8,
) !u64 {
    var samples: [probe_attempts]u64 = undefined;
    for (&samples) |*slot| {
        slot.* = try probeOne(gpa, io, proxy, timeout_secs, bind);
    }
    return averageMs(&samples);
}

/// `a > ratio * b`, saturating on mul overflow (treat as not exceeding).
fn exceedsRatio(a: u64, b: u64, ratio: u64) bool {
    const limit = std.math.mul(u64, ratio, b) catch return false;
    return a > limit;
}

/// `a >= ratio * b`, saturating on mul overflow.
fn atLeastRatio(a: u64, b: u64, ratio: u64) bool {
    const limit = std.math.mul(u64, ratio, b) catch return false;
    return a >= limit;
}

/// Pick the winning preference class from per-class fastest latencies.
///
/// Policy:
/// 1. Prefer fastest VLESS² (gRPC).
/// 2. Prefer VLESS³ over VLESS² when VLESS² is strictly more than 3× slower.
/// 3. Prefer SS over VLESS² only when there is no VLESS², or VLESS² is ≥5× slower than SS.
///    When VLESS² was demoted to VLESS³ and SS is eligible, apply the 3× rule (as in 4).
/// 4. With VLESS³ but no VLESS²: prefer VLESS³ unless it is strictly more than 3× slower than SS.
/// 5. Trojan only when no VLESS² / VLESS³ / SS succeeded.
pub fn selectBestClass(
    vless2_ms: ?u64,
    vless3_ms: ?u64,
    ss_ms: ?u64,
    trojan_ms: ?u64,
) ?PrefClass {
    if (vless2_ms) |v2| {
        var class: PrefClass = .vless2;
        var win_ms = v2;
        if (vless3_ms) |v3| {
            if (exceedsRatio(v2, v3, 3)) {
                class = .vless3;
                win_ms = v3;
            }
        }
        if (ss_ms) |ss_lat| {
            if (atLeastRatio(v2, ss_lat, 5)) {
                if (class == .vless2) {
                    return .shadowsocks;
                }
                // Demoted to VLESS³: same 3× rule as when VLESS² is absent.
                if (exceedsRatio(win_ms, ss_lat, 3)) return .shadowsocks;
            }
        }
        return class;
    }

    if (vless3_ms) |v3| {
        if (ss_ms) |ss_lat| {
            if (exceedsRatio(v3, ss_lat, 3)) return .shadowsocks;
        }
        return .vless3;
    }

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

/// Short hint for FAIL logs (why the probe likely failed).
pub fn failHint(err: anyerror) []const u8 {
    return switch (err) {
        error.Timeout, error.ConnectionTimedOut => "slow/timeout",
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
        error.ProbeResponseMismatch => "bad/response",
        error.ExpectedVisionPadding => "vision/framing",
        error.InvalidSsChunk => "ss/chunk",
        error.UnsupportedVlessEncryption => "unsupported-encryption",
        error.BufferTooSmall, error.RecordTooLarge => "buffer/overflow",
        error.SystemResources => "sys/resources",
        // --interface binding failures (interface name / source IP).
        error.NoSuchInterface => "iface/missing",
        error.InterfaceBindingUnsupported => "iface/unsupported",
        error.InterfaceNameTooLong => "iface/toolong",
        error.AccessDenied => "denied",
        error.AddressFamilyUnsupported => "family",
        // Opaque Io wrappers — Reality/Vision should unwrap socket causes first.
        error.WriteFailed => "write/failed",
        error.ReadFailed => "read/failed",
        else => "error",
    };
}

fn probeGroup(shared: *Shared, items: []WorkItem) void {
    for (items) |*item| {
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

        // Three probes, fail-fast; ranking uses the average of all three.
        const latency = probeAverage(shared.gpa, shared.io, proxy, shared.timeout_secs, shared.bind) catch |err| {
            if (shared.verbose) {
                if (proxy.name) |n| {
                    std.log.warn("FAIL: {s} ({s}): {s} ({})", .{ n, proxy.host, failHint(err), err });
                } else {
                    std.log.warn("FAIL: {s}: {s} ({})", .{ proxy.host, failHint(err), err });
                }
            }
            continue;
        };

        {
            shared.lock();
            shared.stats.passed += 1;
            shared.unlock();
        }

        if (shared.verbose) {
            if (proxy.name) |n| {
                std.log.info("OK: {d}ms {s} — {s}", .{ latency, proxy.host, n });
            } else {
                std.log.info("OK: {d}ms {s}", .{ latency, proxy.host });
            }
        }

        const class = PrefClass.fromProxy(proxy) orelse continue;
        considerBest(shared, class, latency, item.raw, proxy.host);
    }
}

fn freeGroups(gpa: std.mem.Allocator, groups: *std.StringArrayHashMapUnmanaged(std.ArrayList(WorkItem))) void {
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
) !std.StringArrayHashMapUnmanaged(std.ArrayList(WorkItem)) {
    var groups: std.StringArrayHashMapUnmanaged(std.ArrayList(WorkItem)) = .empty;
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
    const threads = try gpa.alloc(std.Thread, @min(n, max_parallel_hosts));
    defer gpa.free(threads);

    var next: usize = 0;
    while (next < n) {
        const batch = @min(max_parallel_hosts, n - next);
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

test "averageMs rounds half up via integer bias" {
    try std.testing.expectEqual(@as(u64, 10), averageMs(&.{ 10, 10, 10 }));
    try std.testing.expectEqual(@as(u64, 30), averageMs(&.{ 20, 30, 40 }));
    // (10+10+11 + 1) / 3 = 32/3 = 10
    try std.testing.expectEqual(@as(u64, 10), averageMs(&.{ 10, 10, 11 }));
    // (10+11+11 + 1) / 3 = 33/3 = 11
    try std.testing.expectEqual(@as(u64, 11), averageMs(&.{ 10, 11, 11 }));
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

test "selectBestClass prefers VLESS2 then demotes on 3x / SS on 5x" {
    // Fastest VLESS² wins when close to others.
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(100, 90, 80, 50));
    // Exactly 3×: keep VLESS² ("больше чем в три раза").
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(300, 100, null, null));
    // Strictly more than 3× → VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(301, 100, null, null));
    // SS needs ≥5× vs VLESS².
    try std.testing.expectEqual(@as(?PrefClass, .vless2), selectBestClass(499, null, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(500, null, 100, null));
    // Demoted to VLESS³; SS eligible via VLESS²≥5×SS, then 3× vs VLESS³.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(600, 100, 40, null)); // 100 ≯ 3×40
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(600, 100, 30, null)); // 100 > 3×30
    // No VLESS²: VLESS³ vs SS at 3×.
    try std.testing.expectEqual(@as(?PrefClass, .vless3), selectBestClass(null, 300, 100, null));
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(null, 301, 100, null));
    // SS without VLESS.
    try std.testing.expectEqual(@as(?PrefClass, .shadowsocks), selectBestClass(null, null, 40, 10));
    // Trojan only as last resort.
    try std.testing.expectEqual(@as(?PrefClass, .trojan), selectBestClass(null, null, null, 10));
    try std.testing.expectEqual(@as(?PrefClass, null), selectBestClass(null, null, null, null));
}
