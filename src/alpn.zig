const std = @import("std");
const netutil = @import("netutil.zig");
const Io = std.Io;

/// What Xray-family clients advertise when a share link carries no `alpn=`.
/// hydec mirrors it so a probe fails wherever the real client would.
const default: []const []const u8 = &.{ "h2", "http/1.1" };

/// Share links carry one or two protocols; the cap only keeps the list on the stack.
pub const max_protocols: usize = 8;

/// Split a decoded `alpn=` value on commas into `storage`. An absent or empty value
/// falls back to the Xray default, matching how those clients treat a blank setting.
/// More than `storage.len` protocols is rejected rather than silently truncated —
/// a probe must not negotiate a different list than the URI asked for.
pub fn parseList(decoded: ?[]const u8, storage: [][]const u8) ![]const []const u8 {
    const raw = decoded orelse return default;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const p = std.mem.trim(u8, part, " \t");
        if (p.len == 0) continue;
        if (n == storage.len) return error.TooManyAlpnProtocols;
        storage[n] = p;
        n += 1;
    }
    return if (n == 0) default else storage[0..n];
}

/// h2 is the only protocol that can break a WebSocket transport, so an offer without
/// it needs no negotiation round trip at all.
pub fn offersH2(protos: []const []const u8) bool {
    for (protos) |p| if (std.mem.eql(u8, p, "h2")) return true;
    return false;
}

/// Enough for a TLS 1.2 ClientHello carrying an SNI and a short protocol list.
const hello_buf_len = 512;
/// ServerHello plus whatever the peer pipelines into the same flight.
const reply_buf_len = 4096;

/// Build a TLS 1.2 ClientHello advertising `protos`.
///
/// TLS 1.2 on purpose: 1.3 moves the server's ALPN pick into the encrypted
/// EncryptedExtensions message, so reading it there would need a full handshake.
/// Omitting `supported_versions` keeps a 1.3-capable server on 1.2.
fn buildClientHello(
    buf: []u8,
    sni: []const u8,
    protos: []const []const u8,
    random: *const [32]u8,
) ![]u8 {
    const suites = [_]u16{ 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8 };
    const sigalgs = [_]u16{ 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501 };
    const groups = [_]u16{ 0x001d, 0x0017, 0x0018 };

    if (protos.len == 0) return error.InvalidAlpnProtocol;
    var alpn_list_len: usize = 0;
    for (protos) |p| {
        if (p.len == 0 or p.len > 255) return error.InvalidAlpnProtocol;
        alpn_list_len += 1 + p.len;
    }

    const ext_sni: usize = if (sni.len > 0) 4 + 2 + 1 + 2 + sni.len else 0;
    const ext_total = ext_sni +
        (4 + 2 + groups.len * 2) +
        (4 + 1 + 1) +
        (4 + 2 + sigalgs.len * 2) +
        (4 + 2 + alpn_list_len);
    const body_len = 2 + 32 + 1 + (2 + suites.len * 2) + 2 + 2 + ext_total;
    if (body_len > std.math.maxInt(u16)) return error.BufferTooSmall;
    if (buf.len < 5 + 4 + body_len) return error.BufferTooSmall;

    var i: usize = 0;
    buf[i] = 0x16; // handshake record
    buf[i + 1] = 0x03;
    buf[i + 2] = 0x01; // legacy record version
    i += 3;
    std.mem.writeInt(u16, buf[i..][0..2], @intCast(4 + body_len), .big);
    i += 2;

    buf[i] = 0x01; // client_hello
    i += 1;
    std.mem.writeInt(u24, buf[i..][0..3], @intCast(body_len), .big);
    i += 3;

    buf[i] = 0x03;
    buf[i + 1] = 0x03; // TLS 1.2
    i += 2;
    @memcpy(buf[i..][0..32], random);
    i += 32;
    buf[i] = 0; // empty session id
    i += 1;

    std.mem.writeInt(u16, buf[i..][0..2], @intCast(suites.len * 2), .big);
    i += 2;
    for (suites) |s| {
        std.mem.writeInt(u16, buf[i..][0..2], s, .big);
        i += 2;
    }

    buf[i] = 1; // one compression method
    buf[i + 1] = 0; // null
    i += 2;

    std.mem.writeInt(u16, buf[i..][0..2], @intCast(ext_total), .big);
    i += 2;

    if (sni.len > 0) {
        std.mem.writeInt(u16, buf[i..][0..2], 0x0000, .big); // server_name
        std.mem.writeInt(u16, buf[i + 2 ..][0..2], @intCast(2 + 1 + 2 + sni.len), .big);
        std.mem.writeInt(u16, buf[i + 4 ..][0..2], @intCast(1 + 2 + sni.len), .big);
        buf[i + 6] = 0; // host_name
        std.mem.writeInt(u16, buf[i + 7 ..][0..2], @intCast(sni.len), .big);
        i += 9;
        @memcpy(buf[i..][0..sni.len], sni);
        i += sni.len;
    }

    std.mem.writeInt(u16, buf[i..][0..2], 0x000a, .big); // supported_groups
    std.mem.writeInt(u16, buf[i + 2 ..][0..2], @intCast(2 + groups.len * 2), .big);
    std.mem.writeInt(u16, buf[i + 4 ..][0..2], @intCast(groups.len * 2), .big);
    i += 6;
    for (groups) |g| {
        std.mem.writeInt(u16, buf[i..][0..2], g, .big);
        i += 2;
    }

    std.mem.writeInt(u16, buf[i..][0..2], 0x000b, .big); // ec_point_formats
    std.mem.writeInt(u16, buf[i + 2 ..][0..2], 2, .big);
    buf[i + 4] = 1;
    buf[i + 5] = 0; // uncompressed
    i += 6;

    std.mem.writeInt(u16, buf[i..][0..2], 0x000d, .big); // signature_algorithms
    std.mem.writeInt(u16, buf[i + 2 ..][0..2], @intCast(2 + sigalgs.len * 2), .big);
    std.mem.writeInt(u16, buf[i + 4 ..][0..2], @intCast(sigalgs.len * 2), .big);
    i += 6;
    for (sigalgs) |a| {
        std.mem.writeInt(u16, buf[i..][0..2], a, .big);
        i += 2;
    }

    std.mem.writeInt(u16, buf[i..][0..2], 0x0010, .big); // application_layer_protocol_negotiation
    std.mem.writeInt(u16, buf[i + 2 ..][0..2], @intCast(2 + alpn_list_len), .big);
    std.mem.writeInt(u16, buf[i + 4 ..][0..2], @intCast(alpn_list_len), .big);
    i += 6;
    for (protos) |p| {
        buf[i] = @intCast(p.len);
        i += 1;
        @memcpy(buf[i..][0..p.len], p);
        i += p.len;
    }

    return buf[0..i];
}

/// Extract the selected protocol from a ServerHello body (handshake header stripped).
/// `null` when the server answered without an ALPN extension.
fn parseFromServerHello(body: []const u8, out: []u8) !?[]const u8 {
    if (body.len < 2 + 32 + 1) return error.MalformedServerHello;
    var i: usize = 2 + 32;
    const sid_len = body[i];
    i += 1;
    // session id + cipher suite + compression method
    if (body.len < i + sid_len + 3) return error.MalformedServerHello;
    i += @as(usize, sid_len) + 3;

    if (body.len < i + 2) return null; // no extension block at all
    const ext_total = std.mem.readInt(u16, body[i..][0..2], .big);
    i += 2;
    if (body.len < i + ext_total) return error.MalformedServerHello;

    const end = i + ext_total;
    while (i + 4 <= end) {
        const et = std.mem.readInt(u16, body[i..][0..2], .big);
        const el = std.mem.readInt(u16, body[i + 2 ..][0..2], .big);
        i += 4;
        if (i + el > end) return error.MalformedServerHello;
        if (et != 0x0010) {
            i += el;
            continue;
        }
        const data = body[i..][0..el];
        if (data.len < 3) return error.MalformedServerHello;
        // RFC 7301 §3.1: extension_data is a ProtocolNameList — a u16 list length
        // followed by length-prefixed names, and a server selects exactly one. Check
        // the list length too, not just the name length: a peer whose framing
        // disagrees with itself is rejected rather than half-read into `out`.
        const list_len: usize = std.mem.readInt(u16, data[0..2], .big);
        if (list_len != data.len - 2) return error.MalformedServerHello;
        const name_len: usize = data[2];
        if (name_len == 0 or name_len + 1 != list_len) return error.MalformedServerHello;
        if (name_len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..name_len], data[3..][0..name_len]);
        return out[0..name_len];
    }
    return null;
}

/// Read TLS records until the first handshake message is complete, returning its body.
fn readServerHello(
    r: *Io.net.Stream.Reader,
    fired: *const std.atomic.Value(bool),
    buf: []u8,
) ![]const u8 {
    var len: usize = 0;
    while (true) {
        var hdr: [5]u8 = undefined;
        r.interface.readSliceAll(&hdr) catch |err|
            return netutil.classifyIoErr(err, null, r.err, fired.load(.acquire));
        // A server that dislikes the hello answers with an alert instead.
        if (hdr[0] == 0x15) return error.TlsAlert;
        if (hdr[0] != 0x16) return error.TlsUnexpectedMessage;
        const rec_len = std.mem.readInt(u16, hdr[3..5], .big);
        if (len + rec_len > buf.len) return error.BufferTooSmall;
        r.interface.readSliceAll(buf[len..][0..rec_len]) catch |err|
            return netutil.classifyIoErr(err, null, r.err, fired.load(.acquire));
        len += rec_len;
        if (len < 4) continue;
        if (buf[0] != 0x02) return error.TlsUnexpectedMessage; // not a ServerHello
        const hs_len: usize = std.mem.readInt(u24, buf[1..4], .big);
        if (len >= 4 + hs_len) return buf[4 .. 4 + hs_len];
    }
}

/// Which protocol the server selects when offered `protos`, or `null` for none.
///
/// Runs its own short-lived connection: the answer is needed before the real probe
/// decides whether the transport can work at all.
pub fn negotiated(
    io: Io,
    host: []const u8,
    port: u16,
    sni: []const u8,
    protos: []const []const u8,
    timeout_secs: u32,
    bind: ?[]const u8,
    out: []u8,
) !?[]const u8 {
    const start = netutil.monoNow(io);
    const stream = try netutil.connectHostPort(io, host, port, timeout_secs, bind);
    defer stream.close(io);

    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(stream.socket.handle, remain, &done, &fired);
    defer guard.disarm();

    var random: [32]u8 = undefined;
    io.random(&random);
    var hello_buf: [hello_buf_len]u8 = undefined;
    const hello = try buildClientHello(&hello_buf, sni, protos, &random);

    var wbuf: [hello_buf_len]u8 = undefined;
    var rbuf: [reply_buf_len]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var r = stream.reader(io, &rbuf);

    w.interface.writeAll(hello) catch |err|
        return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));
    w.interface.flush() catch |err|
        return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));

    var hs_buf: [reply_buf_len]u8 = undefined;
    const body = try readServerHello(&r, &fired, &hs_buf);
    return parseFromServerHello(body, out);
}

test "buildClientHello wire layout" {
    var buf: [hello_buf_len]u8 = undefined;
    var random: [32]u8 = undefined;
    @memset(&random, 0xab);

    const hello = try buildClientHello(&buf, "example.com", &.{ "h2", "http/1.1" }, &random);

    try std.testing.expectEqual(@as(u8, 0x16), hello[0]); // handshake record
    try std.testing.expectEqual(hello.len - 5, std.mem.readInt(u16, hello[3..5], .big));
    try std.testing.expectEqual(@as(u8, 0x01), hello[5]); // client_hello
    try std.testing.expectEqual(hello.len - 9, std.mem.readInt(u24, hello[6..9], .big));
    // TLS 1.2 with no supported_versions, so the pick stays in the clear.
    try std.testing.expectEqual(@as(u8, 0x03), hello[9]);
    try std.testing.expectEqual(@as(u8, 0x03), hello[10]);

    const h2 = [_]u8{ 2, 'h', '2' };
    const h11 = [_]u8{ 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    try std.testing.expect(std.mem.indexOf(u8, hello, &h2) != null);
    try std.testing.expect(std.mem.indexOf(u8, hello, &h11) != null);
    try std.testing.expect(std.mem.indexOf(u8, hello, "example.com") != null);
}

test "buildClientHello rejects unusable protocol lists" {
    var buf: [hello_buf_len]u8 = undefined;
    var random: [32]u8 = undefined;
    @memset(&random, 0);

    try std.testing.expectError(error.InvalidAlpnProtocol, buildClientHello(&buf, "x", &.{}, &random));
    try std.testing.expectError(error.InvalidAlpnProtocol, buildClientHello(&buf, "x", &.{""}, &random));

    var tiny: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, buildClientHello(&tiny, "x", &.{"h2"}, &random));
}

/// ServerHello body: version, random, session id, cipher, compression, extensions.
fn testServerHelloBody(buf: []u8, exts: []const u8, with_ext_block: bool) []const u8 {
    var i: usize = 0;
    buf[0] = 0x03;
    buf[1] = 0x03;
    i = 2;
    @memset(buf[i..][0..32], 0);
    i += 32;
    buf[i] = 0; // empty session id
    i += 1;
    buf[i] = 0xc0;
    buf[i + 1] = 0x2f; // cipher suite
    buf[i + 2] = 0; // compression
    i += 3;
    if (with_ext_block) {
        std.mem.writeInt(u16, buf[i..][0..2], @intCast(exts.len), .big);
        i += 2;
        @memcpy(buf[i..][0..exts.len], exts);
        i += exts.len;
    }
    return buf[0..i];
}

test "parseFromServerHello reads the selected protocol" {
    var buf: [128]u8 = undefined;
    // ext type 0x0010, len 5, list len 3, name len 2, "h2"
    const exts = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' };
    const body = testServerHelloBody(&buf, &exts, true);

    var out: [16]u8 = undefined;
    const selected = try parseFromServerHello(body, &out);
    try std.testing.expectEqualStrings("h2", selected.?);
}

test "parseFromServerHello returns null when the server selects nothing" {
    var buf: [128]u8 = undefined;

    // No extension block at all.
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try parseFromServerHello(testServerHelloBody(&buf, &.{}, false), &.{}),
    );

    // An extension block that carries something else (session_ticket).
    const other = [_]u8{ 0x00, 0x23, 0x00, 0x00 };
    var out: [16]u8 = undefined;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try parseFromServerHello(testServerHelloBody(&buf, &other, true), &out),
    );
}

test "parseFromServerHello rejects truncated input" {
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.MalformedServerHello, parseFromServerHello("short", &out));

    var buf: [128]u8 = undefined;
    // Extension claims 5 bytes but only 3 follow.
    const bad = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02 };
    try std.testing.expectError(
        error.MalformedServerHello,
        parseFromServerHello(testServerHelloBody(&buf, &bad, true), &out),
    );
}

test "parseFromServerHello rejects self-inconsistent ALPN framing" {
    var buf: [128]u8 = undefined;
    var out: [16]u8 = undefined;

    // List length says 3, but the extension carries 4 more bytes.
    const long_ext = [_]u8{ 0x00, 0x10, 0x00, 0x06, 0x00, 0x03, 0x02, 'h', '2', 0x00 };
    try std.testing.expectError(
        error.MalformedServerHello,
        parseFromServerHello(testServerHelloBody(&buf, &long_ext, true), &out),
    );

    // Name length disagrees with the list length (list 3, name 1).
    const bad_name = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x01, 'h', '2' };
    try std.testing.expectError(
        error.MalformedServerHello,
        parseFromServerHello(testServerHelloBody(&buf, &bad_name, true), &out),
    );

    // Empty protocol name.
    const empty_name = [_]u8{ 0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00 };
    try std.testing.expectError(
        error.MalformedServerHello,
        parseFromServerHello(testServerHelloBody(&buf, &empty_name, true), &out),
    );

    // The well-formed shape still reads back, one name only.
    const good = [_]u8{ 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    const selected = try parseFromServerHello(testServerHelloBody(&buf, &good, true), &out);
    try std.testing.expectEqualStrings("http/1.1", selected.?);
}

test "parseList splits and trims the URI value" {
    var storage: [4][]const u8 = undefined;
    const got = try parseList("h2, http/1.1", &storage);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("h2", got[0]);
    try std.testing.expectEqualStrings("http/1.1", got[1]);

    const one = try parseList("http/1.1", &storage);
    try std.testing.expectEqual(@as(usize, 1), one.len);
    try std.testing.expectEqualStrings("http/1.1", one[0]);
}

test "parseList falls back to the Xray default when absent or blank" {
    var storage: [4][]const u8 = undefined;
    for ([_]?[]const u8{ null, "", " , " }) |value| {
        const got = try parseList(value, &storage);
        try std.testing.expectEqual(@as(usize, 2), got.len);
        try std.testing.expectEqualStrings("h2", got[0]);
        try std.testing.expectEqualStrings("http/1.1", got[1]);
    }
}

test "parseList rejects a list it cannot carry" {
    var storage: [2][]const u8 = undefined;
    try std.testing.expectError(error.TooManyAlpnProtocols, parseList("h2,http/1.1,h3", &storage));

    // Exactly filling storage is fine; only the overflow is an error.
    const full = try parseList("h2,http/1.1", &storage);
    try std.testing.expectEqual(@as(usize, 2), full.len);
}

test "offersH2 spots the protocol that breaks ws" {
    try std.testing.expect(offersH2(&.{ "h2", "http/1.1" }));
    try std.testing.expect(offersH2(&.{"h2"}));
    try std.testing.expect(!offersH2(&.{"http/1.1"}));
    try std.testing.expect(!offersH2(&.{}));
}
