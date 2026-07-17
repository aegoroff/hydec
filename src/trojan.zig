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
const probe_http_port: u16 = 80;
const probe_http =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ util.probe_domain ++ "\r\nConnection: close\r\n\r\n";

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
    const n = try util.writeSocksAddrDomain(out[i..], util.probe_domain, probe_http_port);
    i += n;
    out[i] = '\r';
    i += 1;
    out[i] = '\n';
    i += 1;
    if (out.len < i + probe_http.len) return error.BufferTooSmall;
    @memcpy(out[i..][0..probe_http.len], probe_http);
    i += probe_http.len;
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

fn mapTimeout(err: anyerror) anyerror {
    return switch (err) {
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        error.EndOfStream,
        error.BrokenPipe,
        error.SocketNotConnected,
        error.NotOpenForReading,
        error.NotOpenForWriting,
        error.TlsConnectionTruncated,
        error.TlsUnexpectedMessage,
        error.UnexpectedEndOfStream,
        => error.Timeout,
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
    var guard = try netutil.DeadlineShutdown.arm(stream.socket.handle, remain, &done);
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
    ) catch |err| return mapTimeout(err);

    const tls_reader = &tls_client.reader;
    const tls_writer = &tls_client.writer;

    if (transport_ws) {
        const path = if (ws_path.len > 0) ws_path else "/";
        const host_hdr = if (ws_host.len > 0) ws_host else sni_use;
        ws.performUpgrade(tls_reader, tls_writer, io, path, host_hdr) catch |err| return mapTimeout(err);
    }

    var req_buf: [256]u8 = undefined;
    const req_len = try buildRequest(password, &req_buf);

    if (transport_ws) {
        ws.writeBinaryFrame(tls_writer, io, req_buf[0..req_len]) catch |err| return mapTimeout(err);
    } else {
        tls_writer.writeAll(req_buf[0..req_len]) catch |err| return mapTimeout(err);
        tls_writer.flush() catch |err| return mapTimeout(err);
    }

    var one: [1]u8 = undefined;
    if (transport_ws) {
        var frame_buf: [2048]u8 = undefined;
        _ = ws.readBinaryFrame(tls_reader, tls_writer, io, &frame_buf) catch |err| return mapTimeout(err);
    } else {
        tls_reader.readSliceAll(&one) catch |err| return mapTimeout(err);
    }

    return netutil.elapsedMs(start, io);
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
    try std.testing.expectEqual(@as(usize, 82 + probe_http.len), n);

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
    try std.testing.expectEqualStrings(probe_http, buf[82..n]);
}

test "mapTimeout collapses stream errors to Timeout" {
    try std.testing.expect(mapTimeout(error.ConnectionResetByPeer) == error.Timeout);
    try std.testing.expect(mapTimeout(error.TlsConnectionTruncated) == error.Timeout);
    try std.testing.expect(mapTimeout(error.EndOfStream) == error.Timeout);
    try std.testing.expect(mapTimeout(error.UnexpectedEndOfStream) == error.Timeout);
}

test "mapTimeout passes through unrelated errors" {
    try std.testing.expect(mapTimeout(error.OutOfMemory) == error.OutOfMemory);
}
