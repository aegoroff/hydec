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
    // Own redirect targets so resolve buffers do not alias across iterations.
    var owned_url: ?[]u8 = null;
    defer if (owned_url) |u| gpa.free(u);
    var current_url: []const u8 = url;
    var redirects_left: u16 = 5;

    var client = http.Client{
        .allocator = gpa,
        .io = io,
    };
    defer client.deinit();

    try ensureTlsReady(&client);

    while (true) {
        const uri = try requireHttpsUri(current_url);

        var req = try client.request(.GET, uri, .{
            .headers = .{
                .user_agent = .{ .override = DEFAULT_USER_AGENT },
            },
            // Manual follow so each hop can be re-checked for HTTPS.
            .redirect_behavior = .unhandled,
        });

        req.sendBodiless() catch |err| {
            req.deinit();
            return err;
        };

        var header_buffer: [16 * 1024]u8 = undefined;
        var response = req.receiveHead(&header_buffer) catch |err| {
            req.deinit();
            return err;
        };

        if (response.head.status.class() == .redirect) {
            const next = takeHttpsRedirect(gpa, uri, &response, &redirects_left) catch |err| {
                req.deinit();
                return err;
            };
            req.deinit();
            if (owned_url) |u| gpa.free(u);
            owned_url = next;
            current_url = next;
            continue;
        }

        if (response.head.status != .ok) {
            req.deinit();
            return error.HttpStatusNotOk;
        }

        defer req.deinit();

        var transfer_buffer: [8 * 1024]u8 = undefined;
        var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
        var decompress: http.Decompress = undefined;
        var body_reader = response.readerDecompressing(&transfer_buffer, &decompress, &decompress_buffer);

        return try body_reader.allocRemaining(gpa, .limited(4 * 1024 * 1024));
    }
}

/// Follow one redirect only when the resolved target is HTTPS. Returns an owned absolute URL.
fn takeHttpsRedirect(
    gpa: std.mem.Allocator,
    base: std.Uri,
    response: *http.Client.Response,
    redirects_left: *u16,
) ![]u8 {
    if (redirects_left.* == 0) return error.TooManyHttpRedirects;
    redirects_left.* -= 1;

    const location = response.head.location orelse return error.HttpRedirectLocationMissing;
    const loc_copy = try gpa.dupe(u8, location);
    defer gpa.free(loc_copy);

    // Discard body before resolve — Location pointers into the head buffer are invalidated.
    const reader = response.reader(&.{});
    _ = reader.discardRemaining() catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
    };

    var resolve_storage: [16 * 1024]u8 = undefined;
    if (loc_copy.len > resolve_storage.len) return error.HttpRedirectLocationOversize;
    @memcpy(resolve_storage[0..loc_copy.len], loc_copy);
    var aux: []u8 = &resolve_storage;
    const new_uri = base.resolveInPlace(loc_copy.len, &aux) catch |err| switch (err) {
        error.NoSpaceLeft => return error.HttpRedirectLocationOversize,
        else => return error.HttpRedirectLocationInvalid,
    };

    // Re-apply the HTTPS gate — std client would otherwise allow http:// hops.
    _ = try ensureHttpsScheme(new_uri.scheme);

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var normalized = new_uri;
    normalized.scheme = "https";
    try normalized.writeToStream(&aw.writer, std.Uri.Format.Flags.all);
    return try aw.toOwnedSlice();
}

/// Subscription bodies embed proxy credentials; only HTTPS is allowed.
/// Scheme is normalized to lowercase `"https"` for `std.http.Client` (case-sensitive).
fn requireHttpsUri(url: []const u8) (std.Uri.ParseError || error{InsecureSubscriptionUrl})!std.Uri {
    var uri = try std.Uri.parse(url);
    try ensureHttpsScheme(uri.scheme);
    uri.scheme = "https";
    return uri;
}

fn ensureHttpsScheme(scheme: []const u8) error{InsecureSubscriptionUrl}!void {
    if (!std.ascii.eqlIgnoreCase(scheme, "https")) return error.InsecureSubscriptionUrl;
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

test "requireHttpsUri rejects plaintext and normalizes scheme case" {
    try std.testing.expectError(error.InsecureSubscriptionUrl, requireHttpsUri("http://example.com/sub"));
    try std.testing.expectError(error.InsecureSubscriptionUrl, requireHttpsUri("ftp://example.com/sub"));
    const uri = try requireHttpsUri("HTTPS://example.com/sub");
    try std.testing.expectEqualStrings("https", uri.scheme);
}

test "ensureHttpsScheme rejects http redirect targets" {
    try ensureHttpsScheme("https");
    try ensureHttpsScheme("HTTPS");
    try std.testing.expectError(error.InsecureSubscriptionUrl, ensureHttpsScheme("http"));
    try std.testing.expectError(error.InsecureSubscriptionUrl, ensureHttpsScheme("HTTP"));
}
