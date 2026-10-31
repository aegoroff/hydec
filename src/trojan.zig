const std = @import("std");
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const ws = @import("ws.zig");
const tls = @import("tls_client.zig");
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
fn buildRequest(password: []const u8, target: util.Target, out: []u8) !usize {
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
    const n = try util.writeSocksAddrDomain(out[i..], target.domain, util.PROBE_HTTP_PORT);
    i += n;
    out[i] = '\r';
    i += 1;
    out[i] = '\n';
    i += 1;
    if (out.len < i + target.warmup.len) return error.BufferTooSmall;
    @memcpy(out[i..][0..target.warmup.len], target.warmup);
    i += target.warmup.len;
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
    /// Set after the one rescan attempt fails; do not retry for every probe.
    failed: bool = false,
};

var ca_state: CaState = .{};

fn ensureCaBundle(gpa: std.mem.Allocator, io: Io) !*Certificate.Bundle {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    if (ca_state.loaded) return &ca_state.bundle;
    if (ca_state.failed) return error.CertificateBundleLoadFailure;
    const now = Io.Clock.real.now(io);
    ca_state.bundle.rescan(gpa, io, now) catch {
        ca_state.failed = true;
        return error.CertificateBundleLoadFailure;
    };
    ca_state.loaded = true;
    return &ca_state.bundle;
}

/// Free the process-wide CA cache. Call once after all Trojan probes finish
/// (DebugAllocator otherwise reports Bundle.rescan allocations as leaks).
pub fn deinitCaBundle(gpa: std.mem.Allocator, io: Io) void {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    // A failed rescan can leave allocations even though `loaded` is false.
    ca_state.bundle.deinit(gpa);
    ca_state.bundle = .empty;
    ca_state.loaded = false;
    ca_state.failed = false;
}

fn tlsOptions(
    gpa: std.mem.Allocator,
    io: Io,
    sni: []const u8,
    read_buf: []u8,
    write_buf: []u8,
    entropy: *const [tls.Client.Options.entropy_len]u8,
    now: std.Io.Timestamp,
    application_protocols: []const []const u8,
    allow_insecure: bool,
    bundle: ?*Certificate.Bundle,
) tls.Client.Options {
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
        .application_protocols = application_protocols,
        .read_buffer = read_buf,
        .write_buffer = write_buf,
        .entropy = entropy,
        .realtime_now = now,
        .allow_truncation_attacks = true,
    };
}

/// Drain until `http_buf[0..http_len]` is a complete HTTP response, or peer close
/// ends an unframed close-delimited body. Updates `http_len` in place.
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
    while (true) {
        switch (util.httpResponseState(http_buf[0..http_len.*])) {
            .complete => return,
            .malformed => return error.ProbeResponseMismatch,
            .incomplete, .close_delimited => {},
        }
        const n = if (transport_ws)
            ws.readBinaryFrame(conn, io, frame_buf) catch |err| {
                const e = netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
                if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) return;
                return e;
            }
        else
            readTlsChunk(conn.reader, frame_buf) catch |err| {
                const e = netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
                if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) return;
                return e;
            };
        if (http_len.* + n > http_buf.len) return error.BufferTooSmall;
        @memcpy(http_buf[http_len.*..][0..n], frame_buf[0..n]);
        http_len.* += n;
    }
}

/// Whatever decrypted bytes are ready (at least one), copied into `out`.
///
/// Not `readSliceShort`: it keeps reading until `out` is full, which on a keep-alive
/// tunnel blocks after the reply until `DeadlineShutdown` fires.
fn readTlsChunk(reader: *Io.Reader, out: []u8) !usize {
    try reader.fill(1);
    const chunk = reader.buffered();
    const n = @min(chunk.len, out.len);
    @memcpy(out[0..n], chunk[0..n]);
    reader.toss(n);
    return n;
}

pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    opts: Options,
    target: util.Target,
    timeout_secs: u32,
    bind: ?[]const u8,
    stage: *util.Stage,
) !u64 {
    const start = netutil.monoNow(io);
    const sni_use = if (opts.sni.len > 0) opts.sni else host;

    // Loaded once per process; keep it out of the measured time.
    const bundle: ?*Certificate.Bundle = if (opts.allow_insecure) null else try ensureCaBundle(gpa, io);

    const connect_secs = netutil.remainingTimeoutSecs(start, io, timeout_secs);
    if (connect_secs == 0) return error.Timeout;
    // Measured from the real dial; ALPN is part of this handshake.
    const attempt_start = netutil.monoNow(io);
    stage.* = .connect;
    const stream = try netutil.connectHostPort(io, host, port, connect_secs, bind);
    defer stream.close(io);
    stage.* = .handshake;

    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;

    // std.crypto.tls blocks without our poll deadlines — force-unblock via shutdown.
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(io, stream, remain, &done, &fired);
    defer guard.disarm();

    var sock_write_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var sock_read_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var tls_read_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var tls_write_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    var stream_writer = stream.writer(io, &sock_write_buf);
    var stream_reader = stream.reader(io, &sock_read_buf);

    const now = Io.Clock.real.now(io);

    var tls_client = tls.Client.init(
        &stream_reader.interface,
        &stream_writer.interface,
        tlsOptions(gpa, io, sni_use, &tls_read_buf, &tls_write_buf, &entropy, now, opts.alpn, opts.allow_insecure, bundle),
    ) catch |err| return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
    // WebSocket is HTTP/1.1 here; an h2 pick would make the following upgrade invalid.
    if (opts.transport_ws) {
        if (tls_client.applicationProtocol()) |proto| {
            if (std.mem.eql(u8, proto, "h2")) return error.WsAlpnHttp2;
        }
    }
    stage.* = .tunnel;

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
    const req_len = try buildRequest(opts.password, target, &req_buf);

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
    stage.* = .reply;

    // Warmup: drain first HTTP response; require echoed warmup UA (same as gRPC/SS/Vision).
    const http_buf = try gpa.alloc(u8, util.PROBE_HTTP_BUF_LEN);
    defer gpa.free(http_buf);
    var http_len: usize = 0;
    // A `--check-volume` download may come as one large WS frame.
    const frame_buf = try gpa.alloc(u8, util.PROBE_HTTP_BUF_LEN);
    defer gpa.free(frame_buf);
    try readHttpUntilReady(http_buf, &http_len, frame_buf, opts.transport_ws, conn, &stream_reader, &stream_writer, io, &fired);
    if (!util.looksLikeCloudflareTraceUag(http_buf[0..http_len], util.PROBE_UA_WARMUP))
        return error.ProbeResponseMismatch;

    // Steady-state: require a real keep-alive reply (same fail-closed policy as gRPC/Vision).
    if (opts.transport_ws) {
        ws.writeBinaryFrame(conn, io, target.steady) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    } else {
        tls_writer.writeAll(target.steady) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
        netutil.flushTls(tls_writer, &stream_writer.interface) catch |err| {
            return netutil.classifyIoErr(err, stream_writer.err, stream_reader.err, fired.load(.acquire));
        };
    }
    http_len = 0;
    try readHttpUntilReady(http_buf, &http_len, frame_buf, opts.transport_ws, conn, &stream_reader, &stream_writer, io, &fired);
    try target.steady_reply.check(http_buf[0..http_len]);

    return netutil.elapsedMs(attempt_start, io);
}

test "deinitCaBundle frees a partial failed rescan" {
    // Arrange: rescan can allocate before returning an error, leaving loaded=false.
    const gpa = std.testing.allocator;
    try ca_state.bundle.bytes.append(gpa, 0x01);
    ca_state.loaded = false;

    // Act
    deinitCaBundle(gpa, std.testing.io);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.bytes.capacity);
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.map.count());
}

test "ensureCaBundle does not rescan after a previous failure" {
    // Arrange
    const gpa = std.testing.allocator;
    deinitCaBundle(gpa, std.testing.io);
    ca_state.failed = true;
    defer ca_state.failed = false;

    // Act
    const result = ensureCaBundle(gpa, std.testing.io);

    // Assert
    try std.testing.expectError(error.CertificateBundleLoadFailure, result);
    try std.testing.expectEqual(false, ca_state.loaded);
    try std.testing.expectEqual(true, ca_state.failed);
}

/// Hands out `reply` on the first read; any further read fails the test, standing in
/// for a keep-alive socket that would block.
const OneReplyReader = struct {
    reply: []const u8,
    calls: usize = 0,
    r: Io.Reader,

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *OneReplyReader = @fieldParentPtr("r", r);
        self.calls += 1;
        if (self.calls > 1) return error.ReadFailed;
        const n = @min(self.reply.len, @backingInt(limit));
        try w.writeAll(self.reply[0..n]);
        return n;
    }
};

test "readTlsChunk returns the ready reply without waiting to fill the buffer" {
    // Arrange
    const reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var buf: [64]u8 = undefined;
    var src: OneReplyReader = .{
        .reply = reply,
        .r = .{ .vtable = &.{ .stream = OneReplyReader.stream }, .buffer = &buf, .seek = 0, .end = 0 },
    };
    var out: [4096]u8 = undefined;

    // Act
    const n = try readTlsChunk(&src.r, &out);

    // Assert
    try std.testing.expectEqualStrings(reply, out[0..n]);
    try std.testing.expectEqual(@as(usize, 1), src.calls);
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
    const n = try buildRequest("password", util.LATENCY_TARGET, &buf);
    try std.testing.expectEqual(@as(usize, 82 + util.PROBE_HTTP.len), n);

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
    try std.testing.expectEqualStrings(util.PROBE_HTTP, buf[82..n]);
}

test "buildRequest tunnels the volume check to its own domain" {
    var buf: [256]u8 = undefined;
    const n = try buildRequest("password", util.VOLUME_TARGET, &buf);
    try std.testing.expectEqual(@as(u8, util.VOLUME_DOMAIN.len), buf[60]);
    try std.testing.expectEqualStrings(util.VOLUME_DOMAIN, buf[61..][0..util.VOLUME_DOMAIN.len]);
    try std.testing.expect(std.mem.endsWith(u8, buf[0..n], util.VOLUME_TARGET.warmup));
}
