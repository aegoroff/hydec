const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const cli = @import("cli.zig");
const fetch = @import("fetch.zig");
const subscription = @import("subscription.zig");
const proxy_uri = @import("proxy_uri.zig");
const probe = @import("probe.zig");

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

    const parsed = cli.parse(gpa, init.minimal.args) catch |err| switch (err) {
        error.MissingRequiredArgument => {
            std.log.err("missing subscription URI", .{});
            std.process.exit(2);
        },
        error.InvalidTimeout => {
            std.log.err("invalid --timeout", .{});
            std.process.exit(2);
        },
        else => |e| return e,
    };

    switch (parsed) {
        .help => return,
        .version => {
            try cli.printVersion();
            return;
        },
        .run => |opts| {
            defer gpa.free(opts.uri);
            try run(gpa, io, opts);
        },
    }
}

fn run(gpa: std.mem.Allocator, io: Io, opts: cli.Options) !void {
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
    const best = try probe.findBest(gpa, io, lines.items, opts.verbose, opts.timeout_secs, &stats);

    std.log.info("Tested: {d}, passed: {d}, skipped vmess: {d}, skipped other: {d}", .{
        stats.tested,
        stats.passed,
        stats.skipped_vmess,
        stats.skipped_other,
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
}
