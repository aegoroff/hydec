const std = @import("std");
const http = std.http;
const Io = std.Io;
const build_options = @import("build_options");
const netutil = @import("netutil.zig");

const DEFAULT_USER_AGENT = std.fmt.comptimePrint("hydec/{s}", .{build_options.version});

const FetchCtx = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Owned copy; freed with the context.
    url: []u8,
    body: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    /// Set just before detach: worker destroys ctx when it finishes.
    worker_owns_cleanup: std.atomic.Value(bool) = .init(false),
    /// Only one side destroys the context.
    cleanup_taken: std.atomic.Value(bool) = .init(false),
};

fn tryTakeCleanup(ctx: *FetchCtx) bool {
    return ctx.cleanup_taken.swap(true, .acq_rel) == false;
}

fn destroyCtx(ctx: *FetchCtx) void {
    const gpa = ctx.gpa;
    gpa.free(ctx.url);
    if (ctx.body) |b| gpa.free(b);
    gpa.destroy(ctx);
}

fn finishWorker(ctx: *FetchCtx) void {
    ctx.done.store(true, .release);
    if (ctx.worker_owns_cleanup.load(.acquire)) {
        if (tryTakeCleanup(ctx)) destroyCtx(ctx);
    }
}

fn fetchWorker(ctx: *FetchCtx) void {
    const gpa = ctx.gpa;
    const body = fetchUrlInner(gpa, ctx.io, ctx.url) catch |e| {
        ctx.err = e;
        finishWorker(ctx);
        return;
    };

    // Always store the body: a grace-period joiner may still return success.
    ctx.body = body;
    finishWorker(ctx);
}

/// Download URL body with an overall wall-clock deadline.
pub fn fetchUrl(gpa: std.mem.Allocator, io: Io, url: []const u8, timeout_secs: u32) ![]u8 {
    if (timeout_secs == 0) return fetchUrlInner(gpa, io, url);

    const url_owned = try gpa.dupe(u8, url);
    const ctx = gpa.create(FetchCtx) catch |err| {
        gpa.free(url_owned);
        return err;
    };
    ctx.* = .{
        .gpa = gpa,
        .io = io,
        .url = url_owned,
    };

    const thread = std.Thread.spawn(.{}, fetchWorker, .{ctx}) catch |err| {
        destroyCtx(ctx);
        return err;
    };

    return fetchUrlWait(io, ctx, thread, timeout_secs);
}

/// After abandon + join: return body if the download finished, else Timeout.
fn takeResultAfterAbandon(ctx: *FetchCtx) ![]u8 {
    if (!tryTakeCleanup(ctx)) {
        // Worker already destroyed under worker_owns_cleanup.
        return error.Timeout;
    }
    const body = ctx.body;
    ctx.body = null;
    destroyCtx(ctx);
    return body orelse error.Timeout;
}

fn fetchUrlWait(io: Io, ctx: *FetchCtx, thread: std.Thread, timeout_secs: u32) ![]u8 {
    const start = netutil.monoNow(io);
    const budget: i128 = @as(i128, timeout_secs) * std.time.ns_per_s;
    while (!ctx.done.load(.acquire)) {
        if (netutil.monoNow(io) - start >= budget) {
            // Brief grace so a nearly-finished worker can publish done before detach.
            const grace_deadline = netutil.monoNow(io) + 250 * std.time.ns_per_ms;
            while (!ctx.done.load(.acquire) and netutil.monoNow(io) < grace_deadline) {
                const pause: Io.Duration = .fromMilliseconds(20);
                io.sleep(pause, .awake) catch {};
            }
            if (ctx.done.load(.acquire)) {
                thread.join();
                return takeResultAfterAbandon(ctx);
            }
            // Hand cleanup to the worker and detach. Do not re-read ctx after
            // this store: the worker may destroy ctx as soon as it sees the flag
            // (UAF if we join/takeResultAfterAbandon on freed memory). Rare
            // leak if the worker finished between the grace check and this
            // store without seeing the flag — preferred over UAF.
            ctx.worker_owns_cleanup.store(true, .release);
            // std.http has no cancel; worker destroys FetchCtx when it exits.
            thread.detach();
            return error.Timeout;
        }
        const pause: Io.Duration = .fromMilliseconds(50);
        io.sleep(pause, .awake) catch {};
    }
    thread.join();

    if (!tryTakeCleanup(ctx)) return error.FetchStateCorrupt;

    const err = ctx.err;
    const body = ctx.body;
    ctx.body = null;
    destroyCtx(ctx);

    if (err) |e| return e;
    return body orelse error.EmptySubscriptionBody;
}

fn fetchUrlInner(gpa: std.mem.Allocator, io: Io, url: []const u8) ![]u8 {
    const uri = try std.Uri.parse(url);

    var client = http.Client{
        .allocator = gpa,
        .io = io,
    };
    defer client.deinit();

    try ensureTlsReady(&client);

    var req = try client.request(.GET, uri, .{
        .headers = .{
            .user_agent = .{ .override = DEFAULT_USER_AGENT },
        },
        .redirect_behavior = .init(5),
    });
    defer req.deinit();

    try req.sendBodiless();

    var header_buffer: [16 * 1024]u8 = undefined;
    var response = try req.receiveHead(&header_buffer);

    if (response.head.status != .ok) {
        return error.HttpStatusNotOk;
    }

    var transfer_buffer: [8 * 1024]u8 = undefined;
    var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: http.Decompress = undefined;
    var body_reader = response.readerDecompressing(&transfer_buffer, &decompress, &decompress_buffer);

    return try body_reader.allocRemaining(gpa, .limited(4 * 1024 * 1024));
}

fn ensureTlsReady(client: *http.Client) !void {
    if (http.Client.disable_tls) return;

    const io = client.io;
    {
        try client.ca_bundle_lock.lockShared(io);
        defer client.ca_bundle_lock.unlockShared(io);
        if (client.now != null) return;
    }

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(client.allocator);
    const now = Io.Clock.real.now(io);
    bundle.rescan(client.allocator, io, now) catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => return error.CertificateBundleLoadFailure,
    };
    try client.ca_bundle_lock.lock(io);
    defer client.ca_bundle_lock.unlock(io);
    if (client.now != null) return;
    client.now = now;
    std.mem.swap(std.crypto.Certificate.Bundle, &client.ca_bundle, &bundle);
}
