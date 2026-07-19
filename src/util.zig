const std = @import("std");

/// Decode percent-encoding. When `plus_as_space`, `+` becomes space (query-string style).
pub fn urlDecodeOpts(gpa: std.mem.Allocator, input: []const u8, plus_as_space: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (plus_as_space and c == '+') {
            try out.append(gpa, ' ');
            i += 1;
        } else if (c == '%' and i + 2 < input.len) {
            const hi = std.fmt.parseInt(u8, input[i + 1 ..][0..1], 16) catch {
                try out.append(gpa, c);
                i += 1;
                continue;
            };
            const lo = std.fmt.parseInt(u8, input[i + 2 ..][0..1], 16) catch {
                try out.append(gpa, c);
                i += 1;
                continue;
            };
            try out.append(gpa, (hi << 4) | lo);
            i += 3;
        } else {
            try out.append(gpa, c);
            i += 1;
        }
    }
    return try out.toOwnedSlice(gpa);
}

/// Decode percent-encoding (`%XX` and `+` → space). Caller owns result.
pub fn urlDecode(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    return urlDecodeOpts(gpa, input, true);
}

/// Decode percent-encoding without treating `+` as space (RFC 3986 fragment/userinfo).
pub fn urlDecodeStrict(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    return urlDecodeOpts(gpa, input, false);
}

/// Map URL-safe / unpadded base64 into the standard alphabet with `=` padding.
/// Strips existing `=` (re-pads at the end). Optionally skips ASCII whitespace.
/// Returns a prefix of `out`.
pub fn normalizeBase64Url(out: []u8, input: []const u8, skip_whitespace: bool) error{BufferTooSmall}![]u8 {
    var n: usize = 0;
    for (input) |c| {
        const mapped: ?u8 = switch (c) {
            ' ', '\t', '\n', '\r' => if (skip_whitespace) null else c,
            '=' => null,
            '-' => '+',
            '_' => '/',
            else => c,
        };
        if (mapped) |b| {
            if (n >= out.len) return error.BufferTooSmall;
            out[n] = b;
            n += 1;
        }
    }
    while (n % 4 != 0) {
        if (n >= out.len) return error.BufferTooSmall;
        out[n] = '=';
        n += 1;
    }
    return out[0..n];
}

/// Decode standard or URL-safe base64 (optional whitespace). Caller owns the result.
pub fn decodeBase64Url(gpa: std.mem.Allocator, input: []const u8, skip_whitespace: bool) ![]u8 {
    const tmp = try gpa.alloc(u8, input.len + 3);
    defer gpa.free(tmp);
    const normalized = try normalizeBase64Url(tmp, input, skip_whitespace);
    const max_len = try std.base64.standard.Decoder.calcSizeForSlice(normalized);
    const out = try gpa.alloc(u8, max_len);
    errdefer gpa.free(out);
    try std.base64.standard.Decoder.decode(out, normalized);
    return out;
}

pub fn getQueryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (pair.len == 0) continue;
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
        } else if (std.mem.eql(u8, pair, key)) {
            return "";
        }
    }
    return null;
}

/// True for bare flag, `1`, `true`, or `yes` (case-insensitive).
pub fn queryParamTruthy(query: []const u8, key: []const u8) bool {
    const v = getQueryParam(query, key) orelse return false;
    if (v.len == 0) return true;
    if (std.mem.eql(u8, v, "1")) return true;
    if (std.ascii.eqlIgnoreCase(v, "true")) return true;
    if (std.ascii.eqlIgnoreCase(v, "yes")) return true;
    return false;
}

pub const HostPort = struct {
    host: []const u8,
    port: u16,
};

/// Split `host:port`, `[ipv6]:port`. Bare IPv6 without brackets → error.
pub fn splitHostPort(address: []const u8) error{InvalidAddress}!HostPort {
    if (address.len == 0) return error.InvalidAddress;

    if (address[0] == '[') {
        const close = std.mem.indexOfScalar(u8, address, ']') orelse return error.InvalidAddress;
        if (close + 1 >= address.len or address[close + 1] != ':') return error.InvalidAddress;
        if (close + 2 >= address.len) return error.InvalidAddress;
        const port = std.fmt.parseInt(u16, address[close + 2 ..], 10) catch return error.InvalidAddress;
        if (close < 2) return error.InvalidAddress;
        return .{ .host = address[1..close], .port = port };
    }

    // Bare IPv6 has multiple colons — require brackets.
    if (std.mem.count(u8, address, ":") > 1) return error.InvalidAddress;

    const colon = std.mem.lastIndexOfScalar(u8, address, ':') orelse return error.InvalidAddress;
    if (colon == 0 or colon + 1 >= address.len) return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, address[colon + 1 ..], 10) catch return error.InvalidAddress;
    return .{ .host = address[0..colon], .port = port };
}

/// Like `splitHostPort`, but if no port is present use `default_port`.
/// `[ipv6]` without port also gets `default_port`. Bare IPv6 still errors.
pub fn splitHostPortOrDefault(address: []const u8, default_port: u16) error{InvalidAddress}!HostPort {
    if (address.len == 0) return error.InvalidAddress;

    if (address[0] == '[') {
        const close = std.mem.indexOfScalar(u8, address, ']') orelse return error.InvalidAddress;
        if (close + 1 == address.len) {
            if (close < 2) return error.InvalidAddress;
            return .{ .host = address[1..close], .port = default_port };
        }
        return splitHostPort(address);
    }

    if (std.mem.count(u8, address, ":") > 1) return error.InvalidAddress;
    if (std.mem.indexOfScalar(u8, address, ':') == null) {
        return .{ .host = address, .port = default_port };
    }
    return splitHostPort(address);
}

/// SOCKS5 ATYP domain for a fixed well-known host (reachable from most VPS).
pub const probe_domain = "cp.cloudflare.com";
pub const probe_http_port: u16 = 80;
pub const probe_tls_port: u16 = 443;

/// Keep-alive so the tunnel stays open for a second (steady-state) request.
pub const probe_http =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ probe_domain ++ "\r\nConnection: keep-alive\r\n\r\n";

/// True if `buf` begins with a TLS handshake record (ServerHello / HRR / …).
pub fn looksLikeTlsHandshakeRecord(buf: []const u8) bool {
    if (buf.len < 5) return false;
    if (buf[0] != 0x16) return false; // ContentType handshake
    if (buf[1] != 0x03) return false; // legacy version major
    return buf[2] >= 0x01 and buf[2] <= 0x04;
}

/// Full TLS record length including header, or null if incomplete.
pub fn tlsRecordTotalLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const frag = std.mem.readInt(u16, buf[3..5], .big);
    const total = 5 + @as(usize, frag);
    if (total < 5 or frag > 16384) return null;
    if (buf.len < total) return null;
    return total;
}

/// First record must be handshake + ServerHello (type 0x02), including HRR.
pub fn isTlsServerHelloRecord(buf: []const u8) bool {
    const total = tlsRecordTotalLen(buf) orelse return false;
    if (!looksLikeTlsHandshakeRecord(buf)) return false;
    if (total < 6) return false;
    return buf[5] == 0x02; // HandshakeType server_hello
}

fn putU16(buf: []u8, v: u16) void {
    std.mem.writeInt(u16, buf[0..2], v, .big);
}

/// Minimal TLS 1.3 ClientHello with SNI + x25519 key_share.
/// Enough for a real HTTPS peer to answer with ServerHello (we never finish the handshake).
pub fn writeProbeClientHello(out: []u8, sni: []const u8) error{ BufferTooSmall, SniTooLong, InsufficientEntropy }!usize {
    if (sni.len > 255) return error.SniTooLong;

    // Real X25519 share so the peer emits the full ServerHello flight (not a lone HRR wait).
    const seed = [_]u8{0x42} ** 32;
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(seed) catch return error.InsufficientEntropy;

    var body: [512]u8 = undefined;
    var i: usize = 0;

    putU16(body[i..][0..2], 0x0303); // legacy_version TLS 1.2
    i += 2;
    @memset(body[i..][0..32], 0x42); // client_random
    i += 32;
    body[i] = 0; // session_id empty
    i += 1;

    putU16(body[i..][0..2], 2); // cipher_suites len
    i += 2;
    putU16(body[i..][0..2], 0x1301); // TLS_AES_128_GCM_SHA256
    i += 2;

    body[i] = 1; // compression methods
    i += 1;
    body[i] = 0;
    i += 1;

    const ext_len_at = i;
    i += 2;
    const ext_start = i;

    // supported_versions: TLS 1.3
    putU16(body[i..][0..2], 43);
    i += 2;
    putU16(body[i..][0..2], 3);
    i += 2;
    body[i] = 2;
    i += 1;
    putU16(body[i..][0..2], 0x0304);
    i += 2;

    // psk_key_exchange_modes: psk_dhe_ke (required by many stacks)
    putU16(body[i..][0..2], 45);
    i += 2;
    putU16(body[i..][0..2], 2);
    i += 2;
    body[i] = 1;
    i += 1;
    body[i] = 1;
    i += 1;

    // supported_groups: x25519
    putU16(body[i..][0..2], 10);
    i += 2;
    putU16(body[i..][0..2], 4);
    i += 2;
    putU16(body[i..][0..2], 2);
    i += 2;
    putU16(body[i..][0..2], 0x001d);
    i += 2;

    // key_share: x25519
    putU16(body[i..][0..2], 51);
    i += 2;
    putU16(body[i..][0..2], 38);
    i += 2;
    putU16(body[i..][0..2], 36);
    i += 2;
    putU16(body[i..][0..2], 0x001d);
    i += 2;
    putU16(body[i..][0..2], 32);
    i += 2;
    @memcpy(body[i..][0..32], &kp.public_key);
    i += 32;

    // signature_algorithms
    putU16(body[i..][0..2], 13);
    i += 2;
    putU16(body[i..][0..2], 8);
    i += 2;
    putU16(body[i..][0..2], 6);
    i += 2;
    inline for (.{ 0x0403, 0x0804, 0x0401 }) |scheme| {
        putU16(body[i..][0..2], scheme);
        i += 2;
    }

    // server_name
    if (sni.len > 0) {
        const sni_payload = 1 + 2 + sni.len;
        const sni_list = 2 + sni_payload;
        putU16(body[i..][0..2], 0); // server_name
        i += 2;
        putU16(body[i..][0..2], @intCast(sni_list));
        i += 2;
        putU16(body[i..][0..2], @intCast(sni_payload));
        i += 2;
        body[i] = 0; // host_name
        i += 1;
        putU16(body[i..][0..2], @intCast(sni.len));
        i += 2;
        @memcpy(body[i..][0..sni.len], sni);
        i += sni.len;
    }

    putU16(body[ext_len_at..][0..2], @intCast(i - ext_start));

    const hs_len = i;
    const record_len = 4 + hs_len; // handshake header + body
    if (out.len < 5 + record_len) return error.BufferTooSmall;

    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x01; // record legacy version TLS 1.0 for ClientHello
    putU16(out[3..5], @intCast(record_len));
    out[5] = 0x01; // client_hello
    out[6] = @intCast((hs_len >> 16) & 0xff);
    out[7] = @intCast((hs_len >> 8) & 0xff);
    out[8] = @intCast(hs_len & 0xff);
    @memcpy(out[9..][0..hs_len], body[0..hs_len]);
    return 5 + record_len;
}

/// True if `buf` contains a complete HTTP header block (`\r\n\r\n`).
pub fn httpHeadersComplete(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "\r\n\r\n") != null;
}

/// If `buf` holds a complete HTTP/1.x response, return its total size; otherwise `null`.
/// Supports `Content-Length`, `Transfer-Encoding: chunked`, and HTTP/1.1 empty body
/// when neither is present (RFC 7230 §3.3.3). HTTP/1.0 without framing stays
/// incomplete until the peer closes (see warmup loops + `isPeerClosed`).
pub fn httpResponseTotalLen(buf: []const u8) ?usize {
    const sep = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    const headers = buf[0..sep];
    const body_start = sep + 4;

    var chunked = false;
    var content_len: ?usize = null;
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    const status = lines.next() orelse return null;
    while (lines.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "transfer-encoding:")) {
            const v = std.mem.trim(u8, line["transfer-encoding:".len..], " \t");
            if (std.ascii.indexOfIgnoreCase(v, "chunked") != null) chunked = true;
        } else if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
            const v = std.mem.trim(u8, line["content-length:".len..], " \t");
            content_len = std.fmt.parseInt(usize, v, 10) catch return null;
        }
    }

    if (chunked) return httpChunkedBodyEnd(buf, body_start);

    if (content_len) |cl| {
        if (buf.len < body_start + cl) return null;
        return body_start + cl;
    }

    // No Content-Length / chunked: HTTP/1.1+ means empty body. HTTP/1.0 is
    // close-delimited — caller must accept via peer close after headers.
    if (std.mem.startsWith(u8, status, "HTTP/1.0")) return null;
    return body_start;
}

/// Parse chunked body starting at `body_start`; return end offset past the final chunk, or null.
fn httpChunkedBodyEnd(buf: []const u8, body_start: usize) ?usize {
    var pos = body_start;
    while (true) {
        const line_end = std.mem.indexOfPos(u8, buf, pos, "\r\n") orelse return null;
        const size_line = buf[pos..line_end];
        const size_tok = if (std.mem.indexOfScalar(u8, size_line, ';')) |sc|
            size_line[0..sc]
        else
            size_line;
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_tok, " \t"), 16) catch return null;
        pos = line_end + 2;
        if (size == 0) {
            // Optional trailers, then terminating CRLF.
            if (std.mem.indexOfPos(u8, buf, pos, "\r\n\r\n")) |end| return end + 4;
            if (pos + 2 <= buf.len and buf[pos] == '\r' and buf[pos + 1] == '\n') return pos + 2;
            return null;
        }
        if (pos + size + 2 > buf.len) return null;
        pos += size + 2; // chunk data + CRLF
    }
}

/// True when `buf` looks like a Cloudflare `/cdn-cgi/trace` body.
/// Used to reject generic HTTP 400/empty pages from REALITY dest fallback.
pub fn looksLikeCloudflareTrace(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "visit_scheme=") != null;
}

/// True when the peer closed the tunnel (keep-alive second request often hits this).
pub fn isPeerClosed(err: anyerror) bool {
    return switch (err) {
        error.EndOfStream,
        error.UnexpectedEndOfStream,
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.TlsConnectionTruncated,
        error.SocketNotConnected,
        error.NotOpenForReading,
        error.NotOpenForWriting,
        => true,
        else => false,
    };
}

pub fn writeSocksAddrDomain(buf: []u8, domain: []const u8, port: u16) error{BufferTooSmall}!usize {
    if (buf.len < 1 + 1 + domain.len + 2) return error.BufferTooSmall;
    buf[0] = 0x03;
    buf[1] = @intCast(domain.len);
    @memcpy(buf[2..][0..domain.len], domain);
    std.mem.writeInt(u16, buf[2 + domain.len ..][0..2], port, .big);
    return 1 + 1 + domain.len + 2;
}

test "looksLikeTlsHandshakeRecord" {
    try std.testing.expect(looksLikeTlsHandshakeRecord(&[_]u8{ 0x16, 0x03, 0x03, 0x00, 0x01 }));
    try std.testing.expect(!looksLikeTlsHandshakeRecord("HTTP/1.1 400"));
    try std.testing.expect(!looksLikeTlsHandshakeRecord(&[_]u8{ 0x17, 0x03, 0x03 }));
}

test "isTlsServerHelloRecord" {
    // typ=0x16 ver=0x0303 len=4; hs=ServerHello(0x02) + 3-byte len 0
    const sh = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00 };
    try std.testing.expect(isTlsServerHelloRecord(&sh));
    const not_sh = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 }; // ClientHello
    try std.testing.expect(!isTlsServerHelloRecord(&not_sh));
}

test "writeProbeClientHello has handshake record and SNI" {
    var buf: [512]u8 = undefined;
    const n = try writeProbeClientHello(&buf, probe_domain);
    try std.testing.expect(n > 50);
    try std.testing.expect(looksLikeTlsHandshakeRecord(buf[0..n]));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], probe_domain) != null);
}

test "looksLikeCloudflareTrace" {
    try std.testing.expect(looksLikeCloudflareTrace("fl=1\nh=cp.cloudflare.com\nvisit_scheme=http\n"));
    try std.testing.expect(!looksLikeCloudflareTrace("HTTP/1.1 400 Bad Request\r\n\r\n"));
    try std.testing.expect(!looksLikeCloudflareTrace("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
}

test "urlDecode percent and plus" {
    const gpa = std.testing.allocator;
    const got = try urlDecode(gpa, "a%20b+c%2Fd");
    defer gpa.free(got);
    try std.testing.expectEqualStrings("a b c/d", got);
}

test "urlDecodeStrict keeps plus" {
    const gpa = std.testing.allocator;
    const got = try urlDecodeStrict(gpa, "a%20b+c");
    defer gpa.free(got);
    try std.testing.expectEqualStrings("a b+c", got);
}

test "decodeBase64Url hello and url-safe" {
    const gpa = std.testing.allocator;
    const hello = try decodeBase64Url(gpa, "aGVsbG8=", false);
    defer gpa.free(hello);
    try std.testing.expectEqualStrings("hello", hello);
    // ">>>" as standard base64 is "Pj4+" / url-safe "Pj4-"
    const gt = try decodeBase64Url(gpa, "Pj4-", false);
    defer gpa.free(gt);
    try std.testing.expectEqualStrings(">>>", gt);
}

test "decodeBase64Url skips whitespace" {
    const gpa = std.testing.allocator;
    const got = try decodeBase64Url(gpa, "aGVs\nbG8=", true);
    defer gpa.free(got);
    try std.testing.expectEqualStrings("hello", got);
}

test "getQueryParam" {
    try std.testing.expectEqualStrings("tcp", getQueryParam("type=tcp&sni=x", "type").?);
    try std.testing.expect(getQueryParam("type=tcp", "missing") == null);
}

test "queryParamTruthy" {
    try std.testing.expect(queryParamTruthy("allowInsecure=1", "allowInsecure"));
    try std.testing.expect(queryParamTruthy("allowInsecure=true", "allowInsecure"));
    try std.testing.expect(queryParamTruthy("allowInsecure=YES", "allowInsecure"));
    try std.testing.expect(queryParamTruthy("allowInsecure", "allowInsecure"));
    try std.testing.expect(!queryParamTruthy("allowInsecure=0", "allowInsecure"));
    try std.testing.expect(!queryParamTruthy("allowInsecure=false", "allowInsecure"));
    try std.testing.expect(!queryParamTruthy("type=tcp", "allowInsecure"));
}

test "splitHostPort" {
    const hp = try splitHostPort("192.0.2.10:8444");
    try std.testing.expectEqualStrings("192.0.2.10", hp.host);
    try std.testing.expectEqual(@as(u16, 8444), hp.port);
}

test "splitHostPort ipv6 bracket" {
    const hp = try splitHostPort("[2001:db8::1]:443");
    try std.testing.expectEqualStrings("2001:db8::1", hp.host);
    try std.testing.expectEqual(@as(u16, 443), hp.port);
}

test "splitHostPort rejects bare ipv6" {
    try std.testing.expectError(error.InvalidAddress, splitHostPort("2001:db8::1"));
}

test "splitHostPortOrDefault" {
    const hp = try splitHostPortOrDefault("example.com", 443);
    try std.testing.expectEqualStrings("example.com", hp.host);
    try std.testing.expectEqual(@as(u16, 443), hp.port);
}

test "httpResponseTotalLen needs Content-Length body" {
    const partial = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab";
    try std.testing.expect(httpResponseTotalLen(partial) == null);
    const full = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(@as(usize, full.len), httpResponseTotalLen(full).?);
}

test "httpResponseTotalLen HTTP/1.1 empty body without framing" {
    const empty = "HTTP/1.1 200 OK\r\n\r\n";
    try std.testing.expectEqual(@as(usize, empty.len), httpResponseTotalLen(empty).?);
    // HTTP/1.0 without CL/chunked stays open until peer close.
    try std.testing.expect(httpResponseTotalLen("HTTP/1.0 200 OK\r\n\r\n") == null);
    try std.testing.expect(httpHeadersComplete("HTTP/1.0 200 OK\r\n\r\n"));
}

test "httpResponseTotalLen chunked body" {
    const partial = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    try std.testing.expect(httpResponseTotalLen(partial) == null);
    const full = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(@as(usize, full.len), httpResponseTotalLen(full).?);
}
