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

const probe_http = util.probe_http;

/// Encode a VLESS probe: TCP CONNECT to probe host:80 + HTTP GET (matches ss probe).
pub fn encodeProbeRequest(out: []u8, uuid_text: []const u8, flow: []const u8) !usize {
    var uuid: [16]u8 = undefined;
    try parseUuid(uuid_text, &uuid);
    // Port 80 + HTTP GET so the remote answers without a TLS handshake hang.
    var n = try encodeRequestDomain(out, &uuid, util.probe_domain, util.probe_http_port, flow);
    if (std.mem.indexOf(u8, flow, "vision") != null) {
        n += try appendVisionPaddingEnd(out[n..], &uuid, probe_http);
    } else {
        if (out.len < n + probe_http.len) return error.BufferTooSmall;
        @memcpy(out[n..][0..probe_http.len], probe_http);
        n += probe_http.len;
    }
    return n;
}

/// Vision padding commands (xray / sing-box).
pub const vision_cmd_end: u8 = 0x01;
pub const vision_cmd_direct: u8 = 0x02;

/// First Vision frame: UUID + command + contentLen + paddingLen + content + padding.
/// Layout matches xray `XtlsPadding` / `XtlsUnpadding` (content before padding).
/// command 0x01 = PaddingEnd (enough for a connectivity probe).
pub fn appendVisionPaddingEnd(out: []u8, uuid: *const [16]u8, content: []const u8) error{BufferTooSmall}!usize {
    const padding_len: u16 = 64;
    const need = 16 + 1 + 2 + 2 + content.len + padding_len;
    if (out.len < need) return error.BufferTooSmall;
    @memcpy(out[0..16], uuid);
    out[16] = vision_cmd_end;
    std.mem.writeInt(u16, out[17..19], @intCast(content.len), .big);
    std.mem.writeInt(u16, out[19..21], padding_len, .big);
    if (content.len > 0) @memcpy(out[21..][0..content.len], content);
    @memset(out[21 + content.len ..][0..padding_len], 0);
    return need;
}

pub const VisionFrame = struct {
    /// Total bytes consumed from the front of the buffer (header + content + padding).
    consumed: usize,
    content: []const u8,
    /// PaddingEnd / PaddingDirect — further downlink is raw application data.
    switch_to_raw: bool,
};

/// Parse one Vision frame at the front of `buf`.
/// `NeedMore` if the header/payload is incomplete; `NotVision` if it does not start with `uuid`.
pub fn consumeVisionFrame(buf: []const u8, uuid: *const [16]u8) error{ NeedMore, NotVision }!VisionFrame {
    if (buf.len < 16) return error.NeedMore;
    if (!std.mem.eql(u8, buf[0..16], uuid)) return error.NotVision;
    if (buf.len < 21) return error.NeedMore;
    const cmd = buf[16];
    const content_len: usize = std.mem.readInt(u16, buf[17..19], .big);
    const padding_len: usize = std.mem.readInt(u16, buf[19..21], .big);
    const total = 21 + content_len + padding_len;
    if (buf.len < total) return error.NeedMore;
    return .{
        .consumed = total,
        .content = buf[21 .. 21 + content_len],
        .switch_to_raw = cmd == vision_cmd_end or cmd == vision_cmd_direct,
    };
}

/// If buf looks like a complete Vision frame, return the content slice; else return buf.
pub fn maybeUnwrapVision(buf: []const u8, uuid: *const [16]u8) []const u8 {
    const frame = consumeVisionFrame(buf, uuid) catch return buf;
    return frame.content;
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

test "consumeVisionFrame NeedMore and content before padding" {
    var uuid: [16]u8 = [_]u8{0xab} ** 16;
    var frame_buf: [128]u8 = undefined;
    const http = "HTTP/1.1 200 OK\r\n\r\n";
    const n = try appendVisionPaddingEnd(&frame_buf, &uuid, http);

    // Wire layout: header then content immediately (xray order).
    try std.testing.expectEqualStrings(http, frame_buf[21 .. 21 + http.len]);
    try std.testing.expectError(error.NeedMore, consumeVisionFrame(frame_buf[0..20], &uuid));

    const frame = try consumeVisionFrame(frame_buf[0..n], &uuid);
    try std.testing.expectEqual(n, frame.consumed);
    try std.testing.expectEqualStrings(http, frame.content);
    try std.testing.expect(frame.switch_to_raw);
}

test "consumeVisionFrame rejects non-uuid prefix" {
    var uuid: [16]u8 = [_]u8{0xab} ** 16;
    // VLESS empty response header + HTTP must not be mistaken for Vision.
    const raw = "\x00\x00HTTP/1.1 200 OK\r\n\r\n";
    try std.testing.expectError(error.NotVision, consumeVisionFrame(raw, &uuid));
}
