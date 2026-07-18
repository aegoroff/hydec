const std = @import("std");
const util = @import("util.zig");

/// Encode VLESS request (version 0) targeting a domain name.
/// Address type 0x02 = domain (VLESS), unlike SOCKS5 where domain is 0x03.
pub fn encodeRequestDomain(
    out: []u8,
    uuid: *const [16]u8,
    domain: []const u8,
    dest_port: u16,
    flow: []const u8,
) error{BufferTooSmall}!usize {
    var i: usize = 0;
    // protobuf Addons { string Flow = 1; } when flow is set
    const addon_len: usize = if (flow.len == 0) 0 else 1 + 1 + flow.len;
    const need = 1 + 16 + 1 + addon_len + 1 + 2 + 1 + 1 + domain.len;
    if (out.len < need) return error.BufferTooSmall;

    out[i] = 0;
    i += 1;
    @memcpy(out[i..][0..16], uuid);
    i += 16;
    out[i] = @intCast(addon_len);
    i += 1;
    if (flow.len > 0) {
        out[i] = 0x0a; // field 1, length-delimited
        i += 1;
        out[i] = @intCast(flow.len);
        i += 1;
        @memcpy(out[i..][0..flow.len], flow);
        i += flow.len;
    }
    out[i] = 0x01; // TCP command
    i += 1;
    std.mem.writeInt(u16, out[i..][0..2], dest_port, .big);
    i += 2;
    out[i] = 0x02; // domain
    i += 1;
    out[i] = @intCast(domain.len);
    i += 1;
    @memcpy(out[i..][0..domain.len], domain);
    i += domain.len;
    return i;
}

pub fn parseUuid(text: []const u8, out: *[16]u8) error{InvalidUuid}!void {
    var hex_buf: [32]u8 = undefined;
    var hi: usize = 0;
    for (text) |c| {
        if (c == '-') continue;
        if (hi >= 32) return error.InvalidUuid;
        hex_buf[hi] = c;
        hi += 1;
    }
    if (hi != 32) return error.InvalidUuid;
    _ = std.fmt.hexToBytes(out, hex_buf[0..32]) catch return error.InvalidUuid;
}

/// VLESS response: ver(1) + addon_len(1) + addon.
pub fn responseHeaderLen(buf: []const u8) error{ NeedMore, InvalidVlessResponse }!usize {
    if (buf.len < 2) return error.NeedMore;
    if (buf[0] != 0) return error.InvalidVlessResponse;
    const addon_len = buf[1];
    // HTTP/2 SETTINGS: 00 00 xx 04 ... (VLESS empty header is only 00 00)
    if (addon_len == 0 and buf.len >= 4 and buf[3] == 0x04) return error.InvalidVlessResponse;
    const total = 2 + @as(usize, addon_len);
    if (buf.len < total) return error.NeedMore;
    return total;
}

/// Success requires a valid response header plus ≥1 byte of tunneled payload
/// (parity with Trojan TCP and Shadowsocks AEAD open).
pub fn requireTunneledByte(buf: []const u8) error{ NeedMore, InvalidVlessResponse, EmptyTunnelResponse }!void {
    const hdr = try responseHeaderLen(buf);
    if (buf.len <= hdr) return error.EmptyTunnelResponse;
}

const probe_http =
    "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " ++ util.probe_domain ++ "\r\nConnection: close\r\n\r\n";

/// Encode a VLESS probe: TCP CONNECT to probe host:80 + HTTP GET (matches ss probe).
pub fn encodeProbeRequest(out: []u8, uuid_text: []const u8, flow: []const u8) !usize {
    var uuid: [16]u8 = undefined;
    try parseUuid(uuid_text, &uuid);
    // Port 80 + HTTP GET so the remote answers without a TLS handshake hang.
    var n = try encodeRequestDomain(out, &uuid, util.probe_domain, 80, flow);
    if (std.mem.indexOf(u8, flow, "vision") != null) {
        n += try appendVisionPaddingEnd(out[n..], &uuid, probe_http);
    } else {
        if (out.len < n + probe_http.len) return error.BufferTooSmall;
        @memcpy(out[n..][0..probe_http.len], probe_http);
        n += probe_http.len;
    }
    return n;
}

/// First Vision frame: UUID + command + contentLen + paddingLen + padding [+ content].
/// command 0x01 = PaddingEnd (enough for a connectivity probe).
pub fn appendVisionPaddingEnd(out: []u8, uuid: *const [16]u8, content: []const u8) error{BufferTooSmall}!usize {
    const padding_len: u16 = 64;
    const need = 16 + 1 + 2 + 2 + padding_len + content.len;
    if (out.len < need) return error.BufferTooSmall;
    @memcpy(out[0..16], uuid);
    out[16] = 0x01; // CommandPaddingEnd
    std.mem.writeInt(u16, out[17..19], @intCast(content.len), .big);
    std.mem.writeInt(u16, out[19..21], padding_len, .big);
    @memset(out[21 .. 21 + padding_len], 0);
    if (content.len > 0) @memcpy(out[21 + padding_len ..][0..content.len], content);
    return need;
}

/// If buf looks like a Vision frame, return the content slice; else return buf.
pub fn maybeUnwrapVision(buf: []const u8, uuid: *const [16]u8) []const u8 {
    if (buf.len < 21) return buf;
    if (!std.mem.eql(u8, buf[0..16], uuid)) return buf;
    const content_len = std.mem.readInt(u16, buf[17..19], .big);
    const padding_len = std.mem.readInt(u16, buf[19..21], .big);
    const content_off = 21 + @as(usize, padding_len);
    if (content_off + content_len > buf.len) return buf;
    return buf[content_off .. content_off + content_len];
}

test "parseUuid" {
    var u: [16]u8 = undefined;
    try parseUuid("00000000-1111-2222-3333-444444444444", &u);
    try std.testing.expectEqual(@as(u8, 0x00), u[0]);
    try std.testing.expectEqual(@as(u8, 0x44), u[15]);
}

test "encodeRequestDomain size" {
    var buf: [64]u8 = undefined;
    var uuid: [16]u8 = [_]u8{0} ** 16;
    const n = try encodeRequestDomain(&buf, &uuid, "x.com", 443, "");
    try std.testing.expectEqual(@as(usize, 1 + 16 + 1 + 1 + 2 + 1 + 1 + 5), n);
}

test "encodeRequestDomain with flow addon" {
    var buf: [128]u8 = undefined;
    var uuid: [16]u8 = [_]u8{0} ** 16;
    const flow = "xtls-rprx-vision";
    const n = try encodeRequestDomain(&buf, &uuid, "x.com", 443, flow);
    try std.testing.expectEqual(@as(usize, 1 + 16 + 1 + (1 + 1 + flow.len) + 1 + 2 + 1 + 1 + 5), n);
    try std.testing.expectEqual(@as(u8, @intCast(1 + 1 + flow.len)), buf[17]);
    try std.testing.expectEqual(@as(u8, 0x0a), buf[18]);
}

test "requireTunneledByte needs payload after header" {
    try std.testing.expectError(error.EmptyTunnelResponse, requireTunneledByte(&[_]u8{ 0, 0 }));
    try requireTunneledByte(&[_]u8{ 0, 0, 'H' });
    try std.testing.expectError(error.NeedMore, requireTunneledByte(&[_]u8{0}));
}
