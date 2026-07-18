const std = @import("std");
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const ws = @import("ws.zig");
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

fn tlsOptions(
    gpa: std.mem.Allocator,
    io: Io,
    sni: []const u8,
    read_buf: []u8,
    write_buf: []u8,
    entropy: *const [std.crypto.tls.Client.Options.entropy_len]u8,
    now: std.Io.Timestamp,
    bundle: *Certificate.Bundle,
) std.crypto.tls.Client.Options {
    return .{
        .host = .{ .explicit = sni },
        .ca = .{ .bundle = .{
            .gpa = gpa,
            .io = io,
            .lock = &ca_state.rw,
            .bundle = bundle,
        } },
        .read_buffer = read_buf,
        .write_buffer = write_buf,
        .entropy = entropy,
        .realtime_now = now,
        .allow_truncation_attacks = true,
    };
}

/// Classify an I/O error from the probe pipeline.
///
/// Genuine timeouts (`ConnectionTimedOut`, `Timeout`) always map to `Timeout`.
/// `shutdown(2)`-induced EOF/reset errors map to `Timeout` only when our watchdog
/// actually fired (`fired == true`); otherwise they are real server-side rejections
/// (wrong password, dead upstream, TLS protocol error) and pass through unchanged
/// so the caller can distinguish "slow" from "broken/auth-rejected".
fn classifyErr(err: anyerror, fired: bool) anyerror {
    return switch (err) {
        error.ConnectionTimedOut,
        error.Timeout,
        => error.Timeout,
        // Errors that shutdown(fd, SHUT.RDWR) typically produces on a blocked
        // TLS/reader — only treat as timeout if we caused them.
        error.EndOfStream,
        error.UnexpectedEndOfStream,
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.TlsConnectionTruncated,
        error.SocketNotConnected,
        error.NotOpenForReading,
        error.NotOpenForWriting,
        => if (fired) error.Timeout else err,
        else => err,
    };
}

pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    password: []const u8,
    sni: []const u8,
    transport_ws: bool,
    ws_path: []const u8,
    ws_host: []const u8,
    timeout_secs: u32,
) !u64 {
    const start = netutil.monoNow(io);
    const stream = try netutil.connectHostPort(io, host, port, timeout_secs);
    defer stream.close(io);

    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;

    // std.crypto.tls blocks without our poll deadlines — force-unblock via shutdown.
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(stream.socket.handle, remain, &done, &fired);
    defer guard.disarm();

    const bundle = try ensureCaBundle(gpa, io);

    var sock_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var sock_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var tls_write_buf: [std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    var stream_writer = stream.writer(io, &sock_write_buf);
    var stream_reader = stream.reader(io, &sock_read_buf);

    const now = Io.Clock.real.now(io);
    const sni_use = if (sni.len > 0) sni else host;

    var tls_client = std.crypto.tls.Client.init(
        &stream_reader.interface,
        &stream_writer.interface,
        tlsOptions(gpa, io, sni_use, &tls_read_buf, &tls_write_buf, &entropy, now, bundle),
    ) catch |err| return classifyErr(err, fired.load(.acquire));

    const tls_reader = &tls_client.reader;
    const tls_writer = &tls_client.writer;

    if (transport_ws) {
        const path = if (ws_path.len > 0) ws_path else "/";
        const host_hdr = if (ws_host.len > 0) ws_host else sni_use;
        ws.performUpgrade(tls_reader, tls_writer, io, path, host_hdr) catch |err| return classifyErr(err, fired.load(.acquire));
    }

    var req_buf: [256]u8 = undefined;
    const req_len = try buildRequest(password, &req_buf);

    const first_start = netutil.monoNow(io);
    if (transport_ws) {
        ws.writeBinaryFrame(tls_writer, io, req_buf[0..req_len]) catch |err| return classifyErr(err, fired.load(.acquire));
    } else {
        tls_writer.writeAll(req_buf[0..req_len]) catch |err| return classifyErr(err, fired.load(.acquire));
        tls_writer.flush() catch |err| return classifyErr(err, fired.load(.acquire));
    }

    // Warmup: drain first HTTP response so the second request is clean.
    var http_buf: [4096]u8 = undefined;
    var http_len: usize = 0;
    while (util.httpResponseTotalLen(http_buf[0..http_len]) == null) {
        if (transport_ws) {
            var frame_buf: [2048]u8 = undefined;
            const n = ws.readBinaryFrame(tls_reader, tls_writer, io, &frame_buf) catch |err| return classifyErr(err, fired.load(.acquire));
            if (http_len + n > http_buf.len) return error.BufferTooSmall;
            @memcpy(http_buf[http_len..][0..n], frame_buf[0..n]);
            http_len += n;
        } else {
            var chunk: [512]u8 = undefined;
            const n = tls_reader.readSliceShort(&chunk) catch |err| return classifyErr(err, fired.load(.acquire));
            if (n == 0) return classifyErr(error.EndOfStream, fired.load(.acquire));
            if (http_len + n > http_buf.len) return error.BufferTooSmall;
            @memcpy(http_buf[http_len..][0..n], chunk[0..n]);
            http_len += n;
        }
    }
    const first_ms = netutil.elapsedMs(first_start, io);

    const steady_start = netutil.monoNow(io);
    if (transport_ws) {
        ws.writeBinaryFrame(tls_writer, io, util.probe_http) catch |err| {
            const e = classifyErr(err, fired.load(.acquire));
            return if (util.isPeerClosed(e)) first_ms else e;
        };
        var frame_buf: [2048]u8 = undefined;
        _ = ws.readBinaryFrame(tls_reader, tls_writer, io, &frame_buf) catch |err| {
            const e = classifyErr(err, fired.load(.acquire));
            return if (util.isPeerClosed(e)) first_ms else e;
        };
    } else {
        tls_writer.writeAll(util.probe_http) catch |err| {
            const e = classifyErr(err, fired.load(.acquire));
            return if (util.isPeerClosed(e)) first_ms else e;
        };
        tls_writer.flush() catch |err| {
            const e = classifyErr(err, fired.load(.acquire));
            return if (util.isPeerClosed(e)) first_ms else e;
        };
        var one: [1]u8 = undefined;
        tls_reader.readSliceAll(&one) catch |err| {
            const e = classifyErr(err, fired.load(.acquire));
            return if (util.isPeerClosed(e)) first_ms else e;
        };
    }

    return netutil.elapsedMs(steady_start, io);
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

test "classifyErr: genuine timeouts always map to Timeout" {
    try std.testing.expect(classifyErr(error.ConnectionTimedOut, false) == error.Timeout);
    try std.testing.expect(classifyErr(error.Timeout, false) == error.Timeout);
    try std.testing.expect(classifyErr(error.ConnectionTimedOut, true) == error.Timeout);
}

test "classifyErr: shutdown-induced errors map to Timeout only when fired" {
    // Not fired → real server-side close/reset, pass through unchanged.
    try std.testing.expect(classifyErr(error.EndOfStream, false) == error.EndOfStream);
    try std.testing.expect(classifyErr(error.UnexpectedEndOfStream, false) == error.UnexpectedEndOfStream);
    try std.testing.expect(classifyErr(error.ConnectionResetByPeer, false) == error.ConnectionResetByPeer);
    try std.testing.expect(classifyErr(error.TlsConnectionTruncated, false) == error.TlsConnectionTruncated);
    try std.testing.expect(classifyErr(error.BrokenPipe, false) == error.BrokenPipe);
    // Fired → our watchdog shut the socket, treat as timeout.
    try std.testing.expect(classifyErr(error.EndOfStream, true) == error.Timeout);
    try std.testing.expect(classifyErr(error.UnexpectedEndOfStream, true) == error.Timeout);
    try std.testing.expect(classifyErr(error.ConnectionResetByPeer, true) == error.Timeout);
    try std.testing.expect(classifyErr(error.TlsConnectionTruncated, true) == error.Timeout);
    try std.testing.expect(classifyErr(error.BrokenPipe, true) == error.Timeout);
}

test "classifyErr: unrelated and protocol errors pass through regardless of fired" {
    try std.testing.expect(classifyErr(error.OutOfMemory, false) == error.OutOfMemory);
    try std.testing.expect(classifyErr(error.OutOfMemory, true) == error.OutOfMemory);
    // TlsUnexpectedMessage is a real protocol failure, not shutdown-induced.
    try std.testing.expect(classifyErr(error.TlsUnexpectedMessage, false) == error.TlsUnexpectedMessage);
    try std.testing.expect(classifyErr(error.TlsUnexpectedMessage, true) == error.TlsUnexpectedMessage);
}
