const std = @import("std");
const proxy_uri = @import("proxy_uri.zig");
const util = @import("util.zig");
const ss = @import("ss.zig");
const trojan = @import("trojan.zig");
const reality = @import("reality.zig");
const Io = std.Io;

pub const Result = struct {
    latency_ms: u64,
    raw: []const u8,
    host: []const u8,
};

pub const Stats = struct {
    tested: usize = 0,
    passed: usize = 0,
    skipped_vmess: usize = 0,
    skipped_other: usize = 0,
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
    mutex: Io.Mutex = .init,
    best: ?Result = null,
    stats: *Stats,

    fn lock(self: *Shared) void {
        self.mutex.lockUncancelable(self.io);
    }

    fn unlock(self: *Shared) void {
        self.mutex.unlock(self.io);
    }
};

pub fn probeOne(gpa: std.mem.Allocator, io: Io, proxy: proxy_uri.Proxy, timeout_secs: u32) !u64 {
    return switch (proxy.kind) {
        .shadowsocks => blk: {
            const method = proxy.method orelse return error.InvalidProxyUri;
            const password = proxy.password orelse return error.InvalidProxyUri;
            break :blk try ss.probe(gpa, io, proxy.host, proxy.port, method, password, timeout_secs);
        },
        .trojan => blk: {
            const sni = proxy.getParam("sni") orelse proxy.host;
            const path_enc = proxy.getParam("path") orelse "/";
            const path = try util.urlDecode(gpa, path_enc);
            defer gpa.free(path);
            const host_hdr = proxy.getParam("host") orelse sni;
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
                timeout_secs,
            );
        },
        .vless => blk: {
            if (proxy.security != .reality) return error.UnsupportedSecurity;
            if (proxy.transport == .other) return error.UnsupportedTransport;
            if (proxy.transport == .ws) return error.UnsupportedTransport;

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
            );
        },
        .vmess => error.SkippedVmess,
        .unsupported => error.UnsupportedProtocol,
    };
}

fn considerBest(shared: *Shared, latency: u64, raw: []const u8, host: []const u8) void {
    shared.lock();
    defer shared.unlock();
    if (shared.best == null or latency < shared.best.?.latency_ms) {
        shared.best = .{
            .latency_ms = latency,
            .raw = raw,
            .host = host,
        };
    }
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
        => "rejected/closed",
        // REALITY/TLS alert record — peer rejected ClientHello (wrong pbk/sid/sni), not CA verify.
        error.TlsAlert, error.TlsUnexpectedMessage => "handshake/alert",
        error.CertificateBundleLoadFailure => "tls/cert",
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        => "unreachable",
        error.EmptyTunnelResponse,
        error.GrpcEmptyResponse,
        error.GrpcNoData,
        => "empty/no-data",
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
                std.log.info("Testing: {s} ({s}:{d})", .{ n, proxy.host, proxy.port });
            } else {
                std.log.info("Testing: {s}:{d}", .{ proxy.host, proxy.port });
            }
        }

        const latency = probeOne(shared.gpa, shared.io, proxy, shared.timeout_secs) catch |err| {
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

        considerBest(shared, latency, item.raw, proxy.host);
    }
}

fn freeGroups(gpa: std.mem.Allocator, groups: *std.StringArrayHashMapUnmanaged(std.ArrayList(WorkItem))) void {
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
            stats.tested += 1;
            if (verbose) std.log.warn("parse fail: {s}: {}", .{ line, err });
            continue;
        };
        errdefer proxy.deinit(gpa);

        const gop = try groups.getOrPut(gpa, proxy.host);
        if (!gop.found_existing) {
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
        .stats = stats,
    };

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

    return shared.best;
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
