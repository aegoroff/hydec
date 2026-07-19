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

/// Keep-alive so the tunnel stays open for a second (steady-state) request.
pub const probe_http =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ probe_domain ++ "\r\nConnection: keep-alive\r\n\r\n";

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

test "getQueryParam" {
    try std.testing.expectEqualStrings("tcp", getQueryParam("type=tcp&sni=x", "type").?);
    try std.testing.expect(getQueryParam("type=tcp", "missing") == null);
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
