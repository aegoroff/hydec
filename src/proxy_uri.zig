const std = @import("std");
const util = @import("util.zig");

pub const Kind = enum {
    vless,
    trojan,
    shadowsocks,
    vmess,
    unsupported,
};

pub const Transport = enum {
    tcp,
    ws,
    grpc,
    other,
};

pub const Security = enum {
    none,
    tls,
    reality,
    other,
};

pub const Proxy = struct {
    kind: Kind,
    /// Original subscription line (not owned).
    raw: []const u8,
    host: []const u8,
    owns_host: bool = false,
    port: u16,
    /// Userinfo (uuid / password / etc.), URL-decoded when applicable. Owned if `owns_userinfo`.
    userinfo: []const u8,
    owns_userinfo: bool = false,
    query: []const u8,
    transport: Transport = .tcp,
    security: Security = .none,
    /// Optional owned decoded fields
    method: ?[]const u8 = null,
    password: ?[]const u8 = null,
    owns_method_password: bool = false,
    /// Decoded `#fragment` remark (flag + country name), owned if non-null.
    name: ?[]const u8 = null,

    pub fn deinit(self: *Proxy, gpa: std.mem.Allocator) void {
        if (self.owns_host) gpa.free(self.host);
        if (self.owns_userinfo) gpa.free(self.userinfo);
        if (self.owns_method_password) {
            if (self.method) |m| gpa.free(m);
            if (self.password) |p| gpa.free(p);
        }
        if (self.name) |n| gpa.free(n);
        self.* = undefined;
    }

    pub fn getParam(self: Proxy, key: []const u8) ?[]const u8 {
        return util.getQueryParam(self.query, key);
    }
};

fn startsWithScheme(line: []const u8, scheme: []const u8) bool {
    if (line.len < scheme.len + 3) return false;
    if (!std.ascii.eqlIgnoreCase(line[0..scheme.len], scheme)) return false;
    return std.mem.eql(u8, line[scheme.len .. scheme.len + 3], "://");
}

fn afterScheme(line: []const u8) []const u8 {
    const sep = std.mem.indexOf(u8, line, "://") orelse return line;
    return line[sep + 3 ..];
}

pub fn classify(line: []const u8) Kind {
    if (startsWithScheme(line, "vless")) return .vless;
    if (startsWithScheme(line, "trojan")) return .trojan;
    if (startsWithScheme(line, "ss")) return .shadowsocks;
    if (startsWithScheme(line, "vmess")) return .vmess;
    return .unsupported;
}

fn parseTransport(type_param: ?[]const u8) Transport {
    const t = type_param orelse return .tcp;
    if (std.ascii.eqlIgnoreCase(t, "tcp") or t.len == 0) return .tcp;
    if (std.ascii.eqlIgnoreCase(t, "ws")) return .ws;
    if (std.ascii.eqlIgnoreCase(t, "grpc")) return .grpc;
    return .other;
}

fn parseSecurity(sec: ?[]const u8) Security {
    const s = sec orelse return .none;
    if (std.ascii.eqlIgnoreCase(s, "none") or s.len == 0) return .none;
    if (std.ascii.eqlIgnoreCase(s, "tls")) return .tls;
    if (std.ascii.eqlIgnoreCase(s, "reality")) return .reality;
    return .other;
}

fn stripFragment(s: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, s, '#')) |i| return s[0..i];
    return s;
}

/// URL-decoded `#remark` from a subscription line, or null if absent/empty.
pub fn parseName(gpa: std.mem.Allocator, line: []const u8) !?[]const u8 {
    const hash = std.mem.indexOfScalar(u8, line, '#') orelse return null;
    const frag = line[hash + 1 ..];
    if (frag.len == 0) return null;
    const name = try util.urlDecodeStrict(gpa, frag);
    if (name.len == 0) {
        gpa.free(name);
        return null;
    }
    return name;
}

fn parseUserAtHost(gpa: std.mem.Allocator, rest: []const u8, default_port: u16) !struct {
    userinfo: []const u8,
    owns_userinfo: bool,
    host: []const u8,
    port: u16,
    query: []const u8,
} {
    const no_frag = stripFragment(rest);
    var query: []const u8 = "";
    var address_part = no_frag;
    if (std.mem.indexOfScalar(u8, no_frag, '?')) |q| {
        address_part = no_frag[0..q];
        query = no_frag[q + 1 ..];
    }

    const at = std.mem.indexOfScalar(u8, address_part, '@') orelse return error.InvalidProxyUri;
    const raw_user = address_part[0..at];
    const hostport = address_part[at + 1 ..];
    const hp = try util.splitHostPortOrDefault(hostport, default_port);
    const userinfo = try util.urlDecodeStrict(gpa, raw_user);
    return .{
        .userinfo = userinfo,
        .owns_userinfo = true,
        .host = hp.host,
        .port = hp.port,
        .query = query,
    };
}

pub fn parse(gpa: std.mem.Allocator, line: []const u8) !Proxy {
    const kind = classify(line);
    return switch (kind) {
        .vless => try parseVless(gpa, line),
        .trojan => try parseTrojan(gpa, line),
        .shadowsocks => try parseSs(gpa, line),
        .vmess => .{
            .kind = .vmess,
            .raw = line,
            .host = "",
            .port = 0,
            .userinfo = "",
            .query = "",
        },
        .unsupported => error.UnsupportedProtocol,
    };
}

fn parseVless(gpa: std.mem.Allocator, line: []const u8) !Proxy {
    const rest = afterScheme(line);
    const parts = try parseUserAtHost(gpa, rest, 443);
    errdefer if (parts.owns_userinfo) gpa.free(parts.userinfo);
    const name = try parseName(gpa, line);
    return .{
        .kind = .vless,
        .raw = line,
        .host = parts.host,
        .port = parts.port,
        .userinfo = parts.userinfo,
        .owns_userinfo = parts.owns_userinfo,
        .query = parts.query,
        .transport = parseTransport(util.getQueryParam(parts.query, "type")),
        .security = parseSecurity(util.getQueryParam(parts.query, "security")),
        .name = name,
    };
}

fn parseTrojan(gpa: std.mem.Allocator, line: []const u8) !Proxy {
    const rest = afterScheme(line);
    const parts = try parseUserAtHost(gpa, rest, 443);
    errdefer if (parts.owns_userinfo) gpa.free(parts.userinfo);
    const name = try parseName(gpa, line);
    return .{
        .kind = .trojan,
        .raw = line,
        .host = parts.host,
        .port = parts.port,
        .userinfo = parts.userinfo,
        .owns_userinfo = parts.owns_userinfo,
        .query = parts.query,
        .transport = parseTransport(util.getQueryParam(parts.query, "type")),
        .security = parseSecurity(util.getQueryParam(parts.query, "security") orelse "tls"),
        .name = name,
    };
}

fn parseSs(gpa: std.mem.Allocator, line: []const u8) !Proxy {
    const rest0 = stripFragment(afterScheme(line));
    // SIP002: base64(method:password)@host:port
    if (std.mem.indexOfScalar(u8, rest0, '@')) |at| {
        const encoded_user = rest0[0..at];
        var hostport = rest0[at + 1 ..];
        if (std.mem.indexOfScalar(u8, hostport, '?')) |q| hostport = hostport[0..q];
        const hp = try util.splitHostPortOrDefault(hostport, 8388);

        const decoded = try decodeUserinfo(gpa, encoded_user);
        defer gpa.free(decoded);
        const colon = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidProxyUri;
        const method = try gpa.dupe(u8, decoded[0..colon]);
        errdefer gpa.free(method);
        const password = try gpa.dupe(u8, decoded[colon + 1 ..]);
        errdefer gpa.free(password);
        const name = try parseName(gpa, line);
        errdefer if (name) |n| gpa.free(n);

        return .{
            .kind = .shadowsocks,
            .raw = line,
            .host = hp.host,
            .port = hp.port,
            .userinfo = "",
            .query = "",
            .method = method,
            .password = password,
            .owns_method_password = true,
            .name = name,
        };
    }

    // Legacy: entire rest is base64(method:password@host:port)
    const decoded = try decodeUserinfo(gpa, rest0);
    defer gpa.free(decoded);
    // Last '@' separates userinfo from host — passwords may contain '@'.
    const at = std.mem.lastIndexOfScalar(u8, decoded, '@') orelse return error.InvalidProxyUri;
    const userinfo = decoded[0..at];
    const hostport = decoded[at + 1 ..];
    const hp = try util.splitHostPortOrDefault(hostport, 8388);
    const colon = std.mem.indexOfScalar(u8, userinfo, ':') orelse return error.InvalidProxyUri;
    const method = try gpa.dupe(u8, userinfo[0..colon]);
    errdefer gpa.free(method);
    const password = try gpa.dupe(u8, userinfo[colon + 1 ..]);
    errdefer gpa.free(password);
    const host = try gpa.dupe(u8, hp.host);
    errdefer gpa.free(host);
    const name = try parseName(gpa, line);
    errdefer if (name) |n| gpa.free(n);

    return .{
        .kind = .shadowsocks,
        .raw = line,
        .host = host,
        .owns_host = true,
        .port = hp.port,
        .userinfo = "",
        .query = "",
        .method = method,
        .password = password,
        .owns_method_password = true,
        .name = name,
    };
}

fn decodeUserinfo(gpa: std.mem.Allocator, encoded: []const u8) ![]u8 {
    // SIP002: userinfo may percent-encode `+` `/` `=` before base64(method:password).
    const pct = try util.urlDecodeStrict(gpa, encoded);
    defer gpa.free(pct);
    return util.decodeBase64Url(gpa, pct, false);
}

test "parse vless" {
    const gpa = std.testing.allocator;
    const line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:8444?security=reality&type=tcp&flow=xtls-rprx-vision&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.kind == .vless);
    try std.testing.expectEqualStrings("192.0.2.10", p.host);
    try std.testing.expectEqual(@as(u16, 8444), p.port);
    try std.testing.expect(p.security == .reality);
    try std.testing.expect(p.transport == .tcp);
    try std.testing.expectEqualStrings("00000000-1111-2222-3333-444444444444", p.userinfo);
    try std.testing.expectEqualStrings("tag", p.name.?);
}

test "classify case-insensitive scheme" {
    try std.testing.expect(classify("VLESS://x") == .vless);
    try std.testing.expect(classify("SS://x") == .shadowsocks);
    try std.testing.expect(classify("Trojan://x") == .trojan);
}

test "parse type security case-insensitive" {
    const gpa = std.testing.allocator;
    const line =
        \\vless://00000000-1111-2222-3333-444444444444@192.0.2.10:8444?security=Reality&type=TCP&flow=xtls-rprx-vision&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.transport == .tcp);
    try std.testing.expect(p.security == .reality);
}

test "parse ss sip002" {
    const gpa = std.testing.allocator;
    // userinfo = base64(chacha20-ietf-poly1305:test-password)
    const line =
        \\ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.10:2060#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.kind == .shadowsocks);
    try std.testing.expectEqualStrings("chacha20-ietf-poly1305", p.method.?);
    try std.testing.expectEqualStrings("test-password", p.password.?);
    try std.testing.expectEqual(@as(u16, 2060), p.port);
    try std.testing.expectEqualStrings("tag", p.name.?);
}

test "parse ss sip002 percent-encoded userinfo" {
    const gpa = std.testing.allocator;
    // base64(aes-256-gcm:p@ss/word!) with padding as %3D (SIP002)
    const line =
        \\ss://YWVzLTI1Ni1nY206cEBzcy93b3JkIQ%3D%3D@192.0.2.10:2060#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expectEqualStrings("aes-256-gcm", p.method.?);
    try std.testing.expectEqualStrings("p@ss/word!", p.password.?);
    try std.testing.expectEqual(@as(u16, 2060), p.port);
}

test "parse ss legacy owns host" {
    const gpa = std.testing.allocator;
    // base64(chacha20-ietf-poly1305:test-password@192.0.2.10:2060)
    const line =
        \\ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3JkQDE5Mi4wLjIuMTA6MjA2MA#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.kind == .shadowsocks);
    try std.testing.expect(p.owns_host);
    try std.testing.expectEqualStrings("192.0.2.10", p.host);
    try std.testing.expectEqual(@as(u16, 2060), p.port);
    try std.testing.expectEqualStrings("chacha20-ietf-poly1305", p.method.?);
}

test "parse ss legacy password with at-sign" {
    const gpa = std.testing.allocator;
    // base64(chacha20-ietf-poly1305:pass@word@192.0.2.10:2060)
    const line =
        \\ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQHdvcmRAMTkyLjAuMi4xMDoyMDYw#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.owns_host);
    try std.testing.expectEqualStrings("192.0.2.10", p.host);
    try std.testing.expectEqualStrings("pass@word", p.password.?);
}

test "parse trojan ws" {
    const gpa = std.testing.allocator;
    const line =
        \\trojan://test-password@192.0.2.10:2058?security=tls&type=ws&path=%2F&sni=example.com#tag
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expect(p.kind == .trojan);
    try std.testing.expectEqualStrings("192.0.2.10", p.host);
    try std.testing.expectEqual(@as(u16, 2058), p.port);
    try std.testing.expect(p.transport == .ws);
    try std.testing.expect(p.security == .tls);
    try std.testing.expectEqualStrings("test-password", p.userinfo);
    try std.testing.expectEqualStrings("example.com", p.getParam("sni").?);
    try std.testing.expectEqualStrings("%2F", p.getParam("path").?);
    try std.testing.expectEqualStrings("tag", p.name.?);
}

test "parseName percent-decoded remark" {
    const gpa = std.testing.allocator;
    const line =
        \\ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LXBhc3N3b3Jk@192.0.2.10:2060#%F0%9F%87%B8%F0%9F%87%AA%20SHADOWSOCKS%20-%20%D0%A8%D0%B2%D0%B5%D1%86%D0%B8%D1%8F
    ;
    var p = try parse(gpa, line);
    defer p.deinit(gpa);
    try std.testing.expectEqualStrings("🇸🇪 SHADOWSOCKS - Швеция", p.name.?);
}

test "parseName keeps plus in fragment" {
    const gpa = std.testing.allocator;
    const name = try parseName(gpa, "ss://x#foo+bar");
    defer if (name) |n| gpa.free(n);
    try std.testing.expectEqualStrings("foo+bar", name.?);
}
