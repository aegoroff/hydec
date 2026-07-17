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

pub const probe_ip = [_]u8{ 1, 1, 1, 1 };
pub const probe_port: u16 = 443;

/// SOCKS5 ATYP domain for a fixed well-known host (reachable from most VPS).
pub const probe_domain = "cp.cloudflare.com";

pub fn writeSocksAddrIp4(buf: []u8, ip: *const [4]u8, port: u16) usize {
    buf[0] = 0x01; // ATYP IPv4
    @memcpy(buf[1..5], ip);
    std.mem.writeInt(u16, buf[5..7], port, .big);
    return 7;
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
