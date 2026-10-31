const std = @import("std");

/// What Xray-family clients advertise when a share link carries no `alpn=`.
/// hydec mirrors it so a probe fails wherever the real client would.
const DEFAULT_ALPN: []const []const u8 = &.{ "h2", "http/1.1" };

/// ws transports fill an empty ALPN with `http/1.1` before any generic default:
/// Xray `WithNextProto("http/1.1")` (websocket/dialer.go), sing-box
/// `SetNextProtos` (v2raywebsocket/client.go). podkop passes a missing `alpn=`
/// through as unset, so ws never offers h2 unless the link asks for it.
const WS_DEFAULT_ALPN: []const []const u8 = &.{"http/1.1"};

/// Share links carry one or two protocols; the cap only keeps the list on the stack.
pub const MAX_PROTOCOLS: usize = 8;

/// Split a decoded `alpn=` value on commas into `storage`. An absent or empty value
/// falls back to the client default for the transport (`transport_ws`), matching how
/// those clients treat a blank setting.
/// More than `storage.len` protocols is rejected rather than silently truncated —
/// a probe must not negotiate a different list than the URI asked for.
pub fn parseList(decoded: ?[]const u8, storage: [][]const u8, transport_ws: bool) ![]const []const u8 {
    const fallback = if (transport_ws) WS_DEFAULT_ALPN else DEFAULT_ALPN;
    const raw = decoded orelse return fallback;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const p = std.mem.trim(u8, part, " \t");
        if (p.len == 0) continue;
        if (p.len > 255) return error.InvalidAlpnProtocol;
        if (n == storage.len) return error.TooManyAlpnProtocols;
        storage[n] = p;
        n += 1;
    }
    return if (n == 0) fallback else storage[0..n];
}

test "parseList splits and trims the URI value" {
    var storage: [4][]const u8 = undefined;
    const got = try parseList("h2, http/1.1", &storage, false);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("h2", got[0]);
    try std.testing.expectEqualStrings("http/1.1", got[1]);

    const one = try parseList("http/1.1", &storage, false);
    try std.testing.expectEqual(@as(usize, 1), one.len);
    try std.testing.expectEqualStrings("http/1.1", one[0]);
}

test "parseList falls back to the Xray default when absent or blank" {
    var storage: [4][]const u8 = undefined;
    for ([_]?[]const u8{ null, "", " , " }) |value| {
        const got = try parseList(value, &storage, false);
        try std.testing.expectEqual(@as(usize, 2), got.len);
        try std.testing.expectEqualStrings("h2", got[0]);
        try std.testing.expectEqualStrings("http/1.1", got[1]);
    }
}

test "parseList ws default never offers h2, explicit h2 still does" {
    var storage: [4][]const u8 = undefined;
    // HyNet Trojan ws links carry no `alpn=`; Xray / sing-box dial them with http/1.1.
    for ([_]?[]const u8{ null, "", " , " }) |value| {
        const got = try parseList(value, &storage, true);
        try std.testing.expectEqual(@as(usize, 1), got.len);
        try std.testing.expectEqualStrings("http/1.1", got[0]);
    }
    const explicit = try parseList("h2,http/1.1", &storage, true);
    try std.testing.expectEqualStrings("h2", explicit[0]);
}

test "parseList rejects a list it cannot carry" {
    var storage: [2][]const u8 = undefined;
    try std.testing.expectError(error.TooManyAlpnProtocols, parseList("h2,http/1.1,h3", &storage, false));

    // Exactly filling storage is fine; only the overflow is an error.
    const full = try parseList("h2,http/1.1", &storage, false);
    try std.testing.expectEqual(@as(usize, 2), full.len);
}

test "parseList enforces the TLS protocol-name length" {
    var storage: [1][]const u8 = undefined;
    const longest: [255]u8 = @splat('a');
    const got = try parseList(&longest, &storage, false);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqualStrings(&longest, got[0]);

    const too_long: [256]u8 = @splat('a');
    try std.testing.expectError(error.InvalidAlpnProtocol, parseList(&too_long, &storage, false));
}
