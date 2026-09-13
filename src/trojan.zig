const std = @import("std");
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const ws = @import("ws.zig");
const alpn = @import("alpn.zig");
const Io = std.Io;
const Certificate = std.crypto.Certificate;

fn trojanHash(password: []const u8, out: *[56]u8) void {
    var digest: [28]u8 = undefined;
    std.crypto.hash.sha2.Sha224.hash(password, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    @memcpy(out, &hex);
}

/// HTTP/1.1 on port 80 — remote replies immediately so the probe read unblocks.
/// Targeting :443 without payload would hang (TLS server waits for ClientHello).
fn buildRequest(password: []const u8, out: []u8) !usize {
    var hex: [56]u8 = undefined;
    trojanHash(password, &hex);

    var i: usize = 0;
    @memcpy(out[i..][0..56], &hex);
    i += 56;
    out[i] = '\r';
    i += 1;
    out[i] = '\n';
    i += 1;
    out[i] = 0x01; // CONNECT
    i += 1;
    const n = try util.writeSocksAddrDomain(out[i..], util.probe_domain, util.probe_http_port);
    i += n;
    out[i] = '\r';
    i += 1;
    out[i] = '\n';
    i += 1;
    if (out.len < i + util.probe_http.len) return error.BufferTooSmall;
    @memcpy(out[i..][0..util.probe_http.len], util.probe_http);
    i += util.probe_http.len;
    return i;
}

/// Everything one Trojan endpoint's URI says about how to reach it.
pub const Options = struct {
    password: []const u8,
    sni: []const u8,
    transport_ws: bool,
    ws_path: []const u8,
    ws_host: []const u8,
    alpn: []const []const u8,
    allow_insecure: bool,
};

const CaState = struct {
    mutex: Io.Mutex = .init,
    rw: Io.RwLock = .init,
    bundle: Certificate.Bundle = .empty,
    loaded: bool = false,
};

var ca_state: CaState = .{};

fn ensureCaBundle(gpa: std.mem.Allocator, io: Io) !*Certificate.Bundle {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    if (ca_state.loaded) return &ca_state.bundle;
    const now = Io.Clock.real.now(io);
    ca_state.bundle.rescan(gpa, io, now) catch return error.CertificateBundleLoadFailure;
    ca_state.loaded = true;
    return &ca_state.bundle;
}

/// Free the process-wide CA cache. Call once after all Trojan probes finish
/// (DebugAllocator otherwise reports Bundle.rescan allocations as leaks).
pub fn deinitCaBundle(gpa: std.mem.Allocator, io: Io) void {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    if (!ca_state.loaded) return;
    ca_state.bundle.deinit(gpa);
    ca_state.bundle = .empty;
    ca_state.loaded = false;
}

fn tlsOptions(
    gpa: std.mem.Allocator,
    io: Io,
    sni: []const u8,
    read_buf: []u8,
    write_buf: []u8,
    entropy: *const [std.crypto.tls.Client.Options.entropy_len]u8,
    now: std.Io.Timestamp,
    allow_insecure: bool,
    bundle: ?*Certificate.Bundle,
) std.crypto.tls.Client.Options {
    // Keep host.explicit so SNI is still sent; Zig couples SNI with hostname
    // checks, so allowInsecure only skips the CA chain (common for self-signed).
    return .{
        .host = .{ .explicit = sni },
        .ca = if (allow_insecure)
            .no_verification
        else
            .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &ca_state.rw,
                .bundle = bundle.?,
            } },
        .read_buffer = read_buf,
        .write_buffer = write_buf,
        .entropy = entropy,
        .realtime_now = now,
        .allow_truncation_attacks = true,
    };
}

/// Drain until `http_buf[0..http_len]` is a complete HTTP response, or peer close
/// ends an HTTP/1.0 close-delimited body. Updates `http_len` in place.
fn readHttpUntilReady(
    http_buf: []u8,
    http_len: *usize,
    frame_buf: []u8,
    transport_ws: bool,
    conn: ws.Conn,
    stream_reader: *const Io.net.Stream.Reader,
    stream_writer: *Io.net.Stream.Writer,
    io: Io,
    fired: *const std.atomic.Value(bool),
) !void {
    while (util.httpResponseTotalLen(http_buf[0..http_len.*]) == null) {
        const n = if (transport_ws)
            ws.readBinaryFrame(conn, io, frame_buf) catch |err| {
                const e = netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
                if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) return;
                return e;
            }
        else blk: {
            const got = conn.reader.readSliceShort(frame_buf) catch |err| {
                const e = netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
                if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) return;
                return e;
            };
            if (got == 0) {
                const e = netutil.classifyDeadlineErr(error.EndOfStream, fired.load(.acquire));
                if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) return;
                return e;
            }
            break :blk got;
        };
        if (http_len.* + n > http_buf.len) return error.BufferTooSmall;
        @memcpy(http_buf[http_len.*..][0..n], frame_buf[0..n]);
        http_len.* += n;
    }
}

/// How much of the caller's `-t` budget the ALPN side check may spend.
///
/// The check dials its own connection before the real probe, so whatever it burns is
/// taken from the probe that actually decides the verdict — and a check that times
/// out would otherwise leave nothing, failing the candidate as `Timeout` without ever
/// testing it. Half the budget is ample for one ClientHello/ServerHello round trip;
/// below two seconds there is no room to split, so the probe keeps everything.
const AlpnBudget = union(enum) {
    /// Nothing to split: run no check, leaving the whole budget to the probe.
    skip,
    /// Seconds the check may spend.
    secs: u32,

    fn forTimeout(timeout_secs: u32) AlpnBudget {
        const half = timeout_secs / 2;
        return if (half == 0) .skip else .{ .secs = half };
    }

    /// The `timeout_secs` argument for `alpn.negotiated`, or `null` when no check
    /// may run. Never 0, which `alpn.negotiated` would read as "no limit".
    fn negotiateSecs(self: AlpnBudget) ?u32 {
        return switch (self) {
            .skip => null,
            .secs => |s| s,
        };
    }
};

pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    opts: Options,
    timeout_secs: u32,
    bind: ?[]const u8,
) !u64 {
    const start = netutil.monoNow(io);
    const sni_use = if (opts.sni.len > 0) opts.sni else host;

    // Xray-family clients negotiate ALPN before the WebSocket upgrade. A server that
    // answers "h2" then speaks HTTP/2 where the upgrade expects HTTP/1.1, so the
    // transport is dead for them even though a no-ALPN handshake would succeed.
    // Only h2 can break it, so an offer without h2 skips the extra round trip.
    if (opts.transport_ws and alpn.offersH2(opts.alpn)) {
        if (AlpnBudget.forTimeout(timeout_secs).negotiateSecs()) |alpn_secs| {
            var selected_buf: [64]u8 = undefined;
            // Only a confirmed h2 pick is evidence against the node. If the side connection
            // cannot answer at all — a transient failure, or a TLS 1.3-only server that
            // rejects the 1.2 hello — fall through and let the real probe judge it, rather
            // than failing a candidate whose transport may well work.
            const selected = alpn.negotiated(io, host, port, sni_use, opts.alpn, alpn_secs, bind, &selected_buf) catch |err| skipped: {
                std.log.debug("ALPN check skipped for {s}:{d}: {t}", .{ host, port, err });
                break :skipped null;
            };
            if (selected) |proto| {
                if (std.mem.eql(u8, proto, "h2")) return error.WsAlpnHttp2;
            }
        }
    }

    // The ALPN check already spent part of the caller's budget; the rest of the probe
    // gets what is left, so `-t` still bounds the whole attempt.
    const connect_secs = netutil.remainingTimeoutSecs(start, io, timeout_secs);
    if (connect_secs == 0) return error.Timeout;
    const stream = try netutil.connectHostPort(io, host, port, connect_secs, bind);
    defer stream.close(io);

    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;

    // std.crypto.tls blocks without our poll deadlines — force-unblock via shutdown.
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(stream.socket.handle, remain, &done, &fired);
    defer guard.disarm();

    const bundle: ?*Certificate.Bundle = if (opts.allow_insecure) null else try ensureCaBundle(gpa, io);

    var sock_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var sock_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    var stream_writer = stream.writer(io, &sock_write_buf);
    var stream_reader = stream.reader(io, &sock_read_buf);

    const now = Io.Clock.real.now(io);

    var tls_client = std.crypto.tls.Client.init(
        &stream_reader.interface,
        &stream_writer.interface,
        tlsOptions(gpa, io, sni_use, &tls_read_buf, &tls_write_buf, &entropy, now, opts.allow_insecure, bundle),
    ) catch |err| return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));

    const tls_writer = &tls_client.writer;
    const conn: ws.Conn = .{
        .reader = &tls_client.reader,
        .tls = tls_writer,
        .socket = &stream_writer.interface,
    };

    if (opts.transport_ws) {
        const path = if (opts.ws_path.len > 0) opts.ws_path else "/";
        const host_hdr = if (opts.ws_host.len > 0) opts.ws_host else sni_use;
        ws.performUpgrade(conn, io, path, host_hdr) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    }

    var req_buf: [256]u8 = undefined;
    const req_len = try buildRequest(opts.password, &req_buf);

    if (opts.transport_ws) {
        ws.writeBinaryFrame(conn, io, req_buf[0..req_len]) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    } else {
        tls_writer.writeAll(req_buf[0..req_len]) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
        netutil.flushTls(tls_writer, &stream_writer.interface) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    }

    // Warmup: drain first HTTP response; require echoed warmup UA (same as gRPC/SS/Vision).
    const http_buf = try gpa.alloc(u8, 16384);
    defer gpa.free(http_buf);
    var http_len: usize = 0;
    const frame_buf = try gpa.alloc(u8, 16384);
    defer gpa.free(frame_buf);
    try readHttpUntilReady(http_buf, &http_len, frame_buf, opts.transport_ws, conn, &stream_reader, &stream_writer, io, &fired);
    if (!util.looksLikeCloudflareTraceUag(http_buf[0..http_len], util.probe_ua_warmup))
        return error.ProbeResponseMismatch;

    // Steady-state: require a real keep-alive reply (same fail-closed policy as gRPC/Vision).
    const steady_start = netutil.monoNow(io);
    if (opts.transport_ws) {
        ws.writeBinaryFrame(conn, io, util.probe_http_steady) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    } else {
        tls_writer.writeAll(util.probe_http_steady) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
        netutil.flushTls(tls_writer, &stream_writer.interface) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    }
    http_len = 0;
    try readHttpUntilReady(http_buf, &http_len, frame_buf, opts.transport_ws, conn, &stream_reader, &stream_writer, io, &fired);
    if (!util.looksLikeCloudflareTraceUag(http_buf[0..http_len], util.probe_ua_steady))
        return error.ProbeResponseMismatch;

    return netutil.elapsedMs(steady_start, io);
}

test "AlpnBudget always leaves the probe part of the budget" {
    // Too small to split: the probe that decides the verdict keeps everything.
    try std.testing.expectEqual(@as(AlpnBudget, .skip), AlpnBudget.forTimeout(0));
    try std.testing.expectEqual(@as(AlpnBudget, .skip), AlpnBudget.forTimeout(1));
    // Otherwise half, so `remainingTimeoutSecs` can never reach 0 on the check alone.
    try std.testing.expectEqual(@as(AlpnBudget, .{ .secs = 1 }), AlpnBudget.forTimeout(2));
    try std.testing.expectEqual(@as(AlpnBudget, .{ .secs = 1 }), AlpnBudget.forTimeout(3));
    try std.testing.expectEqual(@as(AlpnBudget, .{ .secs = 2 }), AlpnBudget.forTimeout(5));
    try std.testing.expectEqual(@as(AlpnBudget, .{ .secs = 15 }), AlpnBudget.forTimeout(30));

    // Skipping is `null`, never 0 — `alpn.negotiated` reads 0 as "no limit".
    try std.testing.expectEqual(@as(?u32, null), AlpnBudget.forTimeout(1).negotiateSecs());
    try std.testing.expectEqual(@as(?u32, 2), AlpnBudget.forTimeout(5).negotiateSecs());
}

test "trojanHash matches SHA-224 hex (lowercase)" {
    var hex: [56]u8 = undefined;
    trojanHash("password", &hex);
    try std.testing.expectEqualStrings(
        "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01",
        &hex,
    );
    for (hex) |c| try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
}

test "trojanHash empty password" {
    var hex: [56]u8 = undefined;
    trojanHash("", &hex);
    try std.testing.expectEqualStrings(
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        &hex,
    );
}

test "buildRequest wire layout" {
    var buf: [256]u8 = undefined;
    const n = try buildRequest("password", &buf);
    try std.testing.expectEqual(@as(usize, 82 + util.probe_http.len), n);

    var want_hex: [56]u8 = undefined;
    trojanHash("password", &want_hex);
    try std.testing.expectEqualStrings(&want_hex, buf[0..56]);

    try std.testing.expectEqual(@as(u8, '\r'), buf[56]);
    try std.testing.expectEqual(@as(u8, '\n'), buf[57]);
    try std.testing.expectEqual(@as(u8, 0x01), buf[58]); // CONNECT
    try std.testing.expectEqual(@as(u8, 0x03), buf[59]); // ATYP domain
    try std.testing.expectEqual(@as(u8, 17), buf[60]); // domain length
    try std.testing.expectEqualStrings("cp.cloudflare.com", buf[61..78]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[78]); // port 80 high
    try std.testing.expectEqual(@as(u8, 0x50), buf[79]); // port 80 low
    try std.testing.expectEqual(@as(u8, '\r'), buf[80]);
    try std.testing.expectEqual(@as(u8, '\n'), buf[81]);
    try std.testing.expectEqualStrings(util.probe_http, buf[82..n]);
}
