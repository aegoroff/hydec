const std = @import("std");
const http = std.http;
const Io = std.Io;
const build_options = @import("build_options");
const netutil = @import("netutil.zig");

const DEFAULT_USER_AGENT = std.fmt.comptimePrint("hydec/{s}", .{build_options.version});

/// Waiter/worker handoff for timed fetches. `swap` decides who destroys `FetchCtx`.
const FetchState = enum(u8) {
    running = 0,
    /// Worker finished; waiter joins and frees.
    done = 1,
    /// Waiter timed out; worker frees when it finishes.
    abandoned = 2,
};

const FetchCtx = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Owned copy; freed with the context.
    url: []u8,
    body: ?[]u8 = null,
    err: ?anyerror = null,
    state: std.atomic.Value(FetchState) = .init(.running),
};

fn destroyCtx(ctx: *FetchCtx) void {
    const gpa = ctx.gpa;
    gpa.free(ctx.url);
    if (ctx.body) |b| gpa.free(b);
    gpa.destroy(ctx);
}

fn finishWorker(ctx: *FetchCtx) void {
    // Publish body/err first, then claim `.done`. If the waiter already abandoned,
    // we own cleanup; otherwise the waiter will join and free.
    const prev = ctx.state.swap(.done, .acq_rel);
    if (prev == .abandoned) destroyCtx(ctx);
}

fn createFetchCtx(gpa: std.mem.Allocator, io: Io, url: []const u8) !*FetchCtx {
    const url_owned = try gpa.dupe(u8, url);
    errdefer gpa.free(url_owned);
    const ctx = try gpa.create(FetchCtx);
    ctx.* = .{
        .gpa = gpa,
        .io = io,
        .url = url_owned,
    };
    return ctx;
}

fn fetchWorker(ctx: *FetchCtx) void {
    const gpa = ctx.gpa;
    const body = fetchUrlInner(gpa, ctx.io, ctx.url) catch |e| {
        ctx.err = e;
        finishWorker(ctx);
        return;
    };

    // Always store the body: a late joiner may still return success.
    ctx.body = body;
    finishWorker(ctx);
}

/// Download URL body with an overall wall-clock deadline.
pub fn fetchUrl(gpa: std.mem.Allocator, io: Io, url: []const u8, timeout_secs: u32) ![]u8 {
    const ctx = try createFetchCtx(gpa, io, url);
    const thread = std.Thread.spawn(.{}, fetchWorker, .{ctx}) catch |err| {
        destroyCtx(ctx);
        return err;
    };

    return fetchUrlWait(io, ctx, thread, timeout_secs);
}

/// After join when the download finished first: take body/err and free ctx.
fn takeFinishedResult(ctx: *FetchCtx) ![]u8 {
    const err = ctx.err;
    const body = ctx.body;
    ctx.body = null;
    destroyCtx(ctx);
    if (err) |e| return e;
    return body orelse error.EmptySubscriptionBody;
}

fn fetchUrlWait(io: Io, ctx: *FetchCtx, thread: std.Thread, timeout_secs: u32) ![]u8 {
    // Slack on top of the nominal budget so a nearly-finished worker still wins.
    const budget: i128 = @as(i128, timeout_secs) * std.time.ns_per_s + 250 * std.time.ns_per_ms;
    return fetchUrlWaitBudget(io, ctx, thread, budget);
}

fn fetchUrlWaitBudget(io: Io, ctx: *FetchCtx, thread: std.Thread, budget: i128) ![]u8 {
    const start = netutil.monoNow(io);
    while (ctx.state.load(.acquire) != .done) {
        if (netutil.monoNow(io) - start >= budget) {
            // Claim abandon, or observe that the worker won with `.done`.
            const prev = ctx.state.swap(.abandoned, .acq_rel);
            if (prev == .done) {
                thread.join();
                return takeFinishedResult(ctx);
            }
            // Was `.running` — there is only one waiter, so the worker frees ctx.
            // std.http has no cancel; do not touch ctx after this.
            thread.detach();
            return error.Timeout;
        }
        const pause: Io.Duration = .fromMilliseconds(50);
        io.sleep(pause, .awake) catch {};
    }
    thread.join();
    return takeFinishedResult(ctx);
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

    return resolveHttpsRedirect(gpa, base, loc_copy);
}

/// Resolve `location` against `base`; only an HTTPS result is kept. Returns an owned
/// absolute URL.
fn resolveHttpsRedirect(gpa: std.mem.Allocator, base: std.Uri, location: []const u8) ![]u8 {
    var resolve_storage: [16 * 1024]u8 = undefined;
    if (location.len > resolve_storage.len) return error.HttpRedirectLocationOversize;
    @memcpy(resolve_storage[0..location.len], location);
    var aux: []u8 = &resolve_storage;
    const new_uri = base.resolveInPlace(location.len, &aux) catch |err| switch (err) {
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

test "requireHttpsUri rejects plaintext and normalizes scheme case" {
    try std.testing.expectError(error.InsecureSubscriptionUrl, requireHttpsUri("http://example.com/sub"));
    try std.testing.expectError(error.InsecureSubscriptionUrl, requireHttpsUri("ftp://example.com/sub"));
    const uri = try requireHttpsUri("HTTPS://example.com/sub");
    try std.testing.expectEqualStrings("https", uri.scheme);
}

test "resolveHttpsRedirect keeps HTTPS targets and rejects plaintext hops" {
    const gpa = std.testing.allocator;
    const base = try std.Uri.parse("https://sub.example/s/abc?x=1");

    // Rejected: an absolute plaintext target, in any case.
    try std.testing.expectError(error.InsecureSubscriptionUrl, resolveHttpsRedirect(gpa, base, "http://evil.example/s"));
    try std.testing.expectError(error.InsecureSubscriptionUrl, resolveHttpsRedirect(gpa, base, "HTTP://evil.example/s"));

    // Kept: relative and scheme-relative targets inherit the HTTPS base.
    for ([_][2][]const u8{
        .{ "/s/def", "https://sub.example/s/def" },
        .{ "def", "https://sub.example/s/def" },
        .{ "//other.example/s", "https://other.example/s" },
        .{ "HTTPS://other.example/s", "https://other.example/s" },
    }) |case| {
        const got = try resolveHttpsRedirect(gpa, base, case[0]);
        defer gpa.free(got);
        try std.testing.expectEqualStrings(case[1], got);
    }
}

test "ensureHttpsScheme rejects http redirect targets" {
    try ensureHttpsScheme("https");
    try ensureHttpsScheme("HTTPS");
    try std.testing.expectError(error.InsecureSubscriptionUrl, ensureHttpsScheme("http"));
    try std.testing.expectError(error.InsecureSubscriptionUrl, ensureHttpsScheme("HTTP"));
}

const HandoffTestControl = struct {
    started: Io.Event = .unset,
    release: Io.Event = .unset,
    finished: Io.Event = .unset,
    body: []const u8,

    fn complete(ctx: *FetchCtx, control: *HandoffTestControl) void {
        defer control.finished.set(std.testing.io);
        setBody(ctx, control.body);
    }

    fn completeLate(ctx: *FetchCtx, control: *HandoffTestControl) void {
        defer control.finished.set(std.testing.io);
        control.started.set(std.testing.io);
        control.release.waitUncancelable(std.testing.io);
        setBody(ctx, control.body);
    }

    fn setBody(ctx: *FetchCtx, body: []const u8) void {
        ctx.body = ctx.gpa.dupe(u8, body) catch |err| {
            ctx.err = err;
            finishWorker(ctx);
            return;
        };
        finishWorker(ctx);
    }
};

test "fetch handoff joins a completed worker and transfers body ownership" {
    // Arrange: the worker has published its result before the waiter starts.
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const ctx = try createFetchCtx(gpa, io, "https://unused.test/sub");
    var control: HandoffTestControl = .{ .body = "completed body" };
    const thread = try std.Thread.spawn(.{}, HandoffTestControl.complete, .{ ctx, &control });
    try control.finished.wait(io);

    // Act: a zero budget still accepts an already-completed worker.
    const body = try fetchUrlWaitBudget(io, ctx, thread, 0);
    defer gpa.free(body);

    // Assert: the waiter owns only the returned body; ctx and URL were freed.
    try std.testing.expectEqualStrings(control.body, body);
}

test "fetch handoff abandons on timeout and late worker frees its result" {
    // Arrange: hold the worker until the waiter has abandoned the context.
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const ctx = try createFetchCtx(gpa, io, "https://unused.test/sub");
    var control: HandoffTestControl = .{ .body = "late body" };
    const thread = try std.Thread.spawn(.{}, HandoffTestControl.completeLate, .{ ctx, &control });
    try control.started.wait(io);

    // Act: timeout detaches without touching ctx again; then release the worker.
    try std.testing.expectError(error.Timeout, fetchUrlWaitBudget(io, ctx, thread, 0));
    control.release.set(io);
    try control.finished.wait(io);

    // Assert: finished is set after finishWorker, so the late body, URL, and ctx
    // have all been freed before the testing allocator checks this test.
}
