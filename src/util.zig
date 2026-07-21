const std = @import("std");

/// Decode percent-encoding without treating `+` as space (RFC 3986 fragment/userinfo).
pub fn urlDecodeStrict(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '%' and i + 2 < input.len) {
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

const HostPort = struct {
    host: []const u8,
    port: u16,
};

/// Split `host:port`, `[ipv6]:port`. Bare IPv6 without brackets → error.
fn splitHostPort(address: []const u8) error{InvalidAddress}!HostPort {
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

/// Distinct UAs so Cloudflare `/cdn-cgi/trace` echoes them in `uag=` — proves the
/// steady-state reply is not a duplicate of the warmup response (all probe paths).
pub const probe_ua_warmup = "hydec-warmup";
pub const probe_ua_steady = "hydec-steady";

/// Keep-alive so the tunnel stays open for a second (steady-state) request.
pub const probe_http =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ probe_domain ++ "\r\nUser-Agent: " ++ probe_ua_warmup ++ "\r\nConnection: keep-alive\r\n\r\n";

/// Second (steady-state) request — distinct UA from `probe_http`.
pub const probe_http_steady =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ probe_domain ++ "\r\nUser-Agent: " ++ probe_ua_steady ++ "\r\nConnection: keep-alive\r\n\r\n";

/// True when headers are complete and the body is HTTP/1.0 close-delimited
/// (no `Content-Length` / `Transfer-Encoding: chunked`). Peer close then ends the response.
/// Truncated CL/chunked bodies must not be treated as ready on peer close alone.
pub fn httpCloseDelimitedReady(buf: []const u8) bool {
    const sep = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return false;
    const headers = buf[0..sep];
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    const status = lines.next() orelse return false;
    if (!std.mem.startsWith(u8, status, "HTTP/1.0")) return false;
    while (lines.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "transfer-encoding:")) {
            const v = std.mem.trim(u8, line["transfer-encoding:".len..], " \t");
            if (std.ascii.indexOfIgnoreCase(v, "chunked") != null) return false;
        } else if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
            return false;
        }
    }
    return true;
}

/// If `buf` holds a complete HTTP/1.x response, return its total size; otherwise `null`.
/// Supports `Content-Length`, `Transfer-Encoding: chunked`, and HTTP/1.1 empty body
/// when neither is present (RFC 7230 §3.3.3). HTTP/1.0 without framing stays
/// incomplete until the peer closes (see warmup loops + `httpCloseDelimitedReady`).
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

/// Like `looksLikeCloudflareTrace`, but also requires the echoed `uag=` line.
pub fn looksLikeCloudflareTraceUag(buf: []const u8, uag: []const u8) bool {
    if (!looksLikeCloudflareTrace(buf)) return false;
    var needle_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "uag={s}", .{uag}) catch return false;
    return std.mem.indexOf(u8, buf, needle) != null;
}

/// True when the peer closed the tunnel (warmup may complete via close-delimited HTTP/1.0).
pub fn isPeerClosed(err: anyerror) bool {
    return switch (err) {
        error.EndOfStream,
        error.UnexpectedEndOfStream,
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.TlsConnectionTruncated,
        error.SocketUnconnected,
        error.NotOpenForReading,
        error.NotOpenForWriting,
        => true,
        else => false,
    };
}

pub fn writeSocksAddrDomain(buf: []u8, domain: []const u8, port: u16) error{ BufferTooSmall, DomainTooLong }!usize {
    if (domain.len > 255) return error.DomainTooLong;
    if (buf.len < 1 + 1 + domain.len + 2) return error.BufferTooSmall;
    buf[0] = 0x03;
    buf[1] = @intCast(domain.len);
    @memcpy(buf[2..][0..domain.len], domain);
    std.mem.writeInt(u16, buf[2 + domain.len ..][0..2], port, .big);
    return 1 + 1 + domain.len + 2;
}

test "writeSocksAddrDomain rejects domain longer than 255" {
    var buf: [512]u8 = undefined;
    const long = [_]u8{'a'} ** 256;
    try std.testing.expectError(error.DomainTooLong, writeSocksAddrDomain(&buf, &long, 80));
}

test "looksLikeCloudflareTrace" {
    try std.testing.expect(looksLikeCloudflareTrace("fl=1\nh=cp.cloudflare.com\nvisit_scheme=http\n"));
    try std.testing.expect(!looksLikeCloudflareTrace("HTTP/1.1 400 Bad Request\r\n\r\n"));
    try std.testing.expect(!looksLikeCloudflareTrace("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
}

test "looksLikeCloudflareTraceUag matches echoed UA" {
    const body = "fl=1\nvisit_scheme=http\nuag=hydec-steady\n";
    try std.testing.expect(looksLikeCloudflareTraceUag(body, probe_ua_steady));
    try std.testing.expect(!looksLikeCloudflareTraceUag(body, probe_ua_warmup));
    try std.testing.expect(!looksLikeCloudflareTraceUag("fl=1\nvisit_scheme=http\nuag=curl\n", probe_ua_steady));
}

test "urlDecodeStrict keeps plus" {
    const gpa = std.testing.allocator;
    const got = try urlDecodeStrict(gpa, "a%20b+c%2Fd");
    defer gpa.free(got);
    try std.testing.expectEqualStrings("a b+c/d", got);
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
}

test "httpCloseDelimitedReady only HTTP/1.0 without framing" {
    try std.testing.expect(httpCloseDelimitedReady("HTTP/1.0 200 OK\r\n\r\nbody"));
    try std.testing.expect(httpCloseDelimitedReady("HTTP/1.0 200 OK\r\nServer: x\r\n\r\n"));
    // Incomplete headers.
    try std.testing.expect(!httpCloseDelimitedReady("HTTP/1.0 200 OK\r\n"));
    // HTTP/1.1 empty body is length-complete via httpResponseTotalLen, not close-delimited.
    try std.testing.expect(!httpCloseDelimitedReady("HTTP/1.1 200 OK\r\n\r\n"));
    // Framed bodies must not treat peer-close as completion while still short.
    try std.testing.expect(!httpCloseDelimitedReady("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nab"));
    try std.testing.expect(!httpCloseDelimitedReady(
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
    ));
}

test "httpResponseTotalLen chunked body" {
    const partial = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    try std.testing.expect(httpResponseTotalLen(partial) == null);
    const full = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(@as(usize, full.len), httpResponseTotalLen(full).?);
}
