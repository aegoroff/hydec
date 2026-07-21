const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const cli = @import("cli.zig");
const fetch = @import("fetch.zig");
const subscription = @import("subscription.zig");
const proxy_uri = @import("proxy_uri.zig");
const probe = @import("probe.zig");
const trojan = @import("trojan.zig");

const utf8_console = if (builtin.os.tag == .windows)
    @import("utf8_console.zig")
else
    struct {
        pub fn setupConsole() void {}
    };

pub fn main(init: std.process.Init) !void {
    utf8_console.setupConsole();
    const gpa = init.gpa;
    const io = init.io;
    defer trojan.deinitCaBundle(gpa, io);

    const parsed = cli.parse(gpa, io, init.minimal.args) catch |err| switch (err) {
        error.MissingRequiredArgument => {
            std.log.err("missing required argument", .{});
            std.process.exit(2);
        },
        error.InvalidTimeout => {
            std.log.err("invalid --timeout", .{});
            std.process.exit(2);
        },
        error.UnknownCommand => {
            std.log.err("unknown command (try 'hydec --help')", .{});
            std.process.exit(2);
        },
        else => |e| return e,
    };

    switch (parsed) {
        .help => return,
        .version => {
            try cli.printVersion(io);
            return;
        },
        .run => |opts| {
            defer gpa.free(opts.uri);
            switch (opts.command) {
                .best => try runBest(gpa, io, opts),
                .ping => try runPing(gpa, io, opts),
            }
        },
    }
}

fn runBest(gpa: std.mem.Allocator, io: Io, opts: cli.Options) !void {
    std.log.info("Downloading subscription...", .{});
    const body = fetch.fetchUrl(gpa, io, opts.uri, opts.timeout_secs) catch |err| {
        std.log.err("failed to download subscription: {}", .{err});
        std.process.exit(1);
    };
    defer gpa.free(body);

    const decoded = subscription.decodeBase64(gpa, body) catch |err| {
        std.log.err("failed to base64-decode subscription: {}", .{err});
        std.process.exit(1);
    };
    defer gpa.free(decoded);

    if (decoded.len == 0) {
        std.log.err("empty subscription", .{});
        std.process.exit(1);
    }

    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(gpa);

    const Ctx = struct {
        list: *std.ArrayList([]const u8),
        gpa: std.mem.Allocator,
        fn on(self: *@This(), line: []const u8) !void {
            try self.list.append(self.gpa, line);
        }
    };
    var ctx: Ctx = .{ .list = &lines, .gpa = gpa };
    try subscription.iterLines(decoded, Ctx.on, &ctx);

    var stats: probe.Stats = .{};
    var best = try probe.findBest(gpa, io, lines.items, opts.verbose, opts.timeout_secs, &stats);
    defer if (best) |*b| b.deinit(gpa);

    std.log.info("Tested: {d}, passed: {d}, skipped vmess: {d}, skipped other: {d}, parse failed: {d}", .{
        stats.tested,
        stats.passed,
        stats.skipped_vmess,
        stats.skipped_other,
        stats.parse_failed,
    });

    if (best) |b| {
        const name = try proxy_uri.parseName(gpa, b.raw);
        defer if (name) |n| gpa.free(n);
        if (name) |n| {
            std.log.info("Best: {d}ms {s} — {s}", .{ b.latency_ms, b.host, n });
        } else {
            std.log.info("Best: {d}ms {s}", .{ b.latency_ms, b.host });
        }

        var out_buf: [1024]u8 = undefined;
        var file_writer = Io.File.stdout().writerStreaming(io, &out_buf);
        try file_writer.interface.print("{s}\n", .{b.raw});
        try file_writer.interface.flush();
    } else {
        std.log.err("No working proxies found", .{});
        std.process.exit(1);
    }
}

fn runPing(gpa: std.mem.Allocator, io: Io, opts: cli.Options) !void {
    var proxy = proxy_uri.parse(gpa, opts.uri) catch |err| {
        std.log.err("invalid proxy URI: {}", .{err});
        std.process.exit(2);
    };
    defer proxy.deinit(gpa);

    const latency = probe.probeAverage(gpa, io, proxy, opts.timeout_secs) catch |err| {
        if (proxy.name) |n| {
            std.log.warn("FAIL: {s} ({s}): {s} ({})", .{ n, proxy.host, probe.failHint(err), err });
        } else {
            std.log.warn("FAIL: {s}: {s} ({})", .{ proxy.host, probe.failHint(err), err });
        }
        std.process.exit(1);
    };

    if (proxy.name) |n| {
        std.log.info("OK: {d}ms {s} — {s}", .{ latency, proxy.host, n });
    } else {
        std.log.info("OK: {d}ms {s}", .{ latency, proxy.host });
    }
}

test {
    _ = @import("cli.zig");
    _ = @import("util.zig");
    _ = @import("subscription.zig");
    _ = @import("proxy_uri.zig");
    _ = @import("ss.zig");
    _ = @import("vless.zig");
    _ = @import("ws.zig");
    _ = @import("trojan.zig");
    _ = @import("grpc_gun.zig");
    _ = @import("reality.zig");
    _ = @import("probe.zig");
    _ = @import("netutil.zig");
    _ = @import("fetch.zig");
}
