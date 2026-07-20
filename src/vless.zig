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

/// Encode a gRPC VLESS probe: CONNECT to probe host:80 + HTTP GET (no Vision framing).
/// Vision TCP uses an inner HTTPS client instead (`probeVlessTcpHttps`).
pub fn encodeProbeRequest(out: []u8, uuid_text: []const u8) !usize {
    var uuid: [16]u8 = undefined;
    try parseUuid(uuid_text, &uuid);
    var n = try encodeRequestDomain(out, &uuid, util.probe_domain, util.probe_http_port, "");
    const http = util.probe_http;
    if (out.len < n + http.len) return error.BufferTooSmall;
    @memcpy(out[n..][0..http.len], http);
    n += http.len;
    return n;
}

/// Vision padding commands (xray / sing-box).
pub const vision_cmd_continue: u8 = 0x00;
pub const vision_cmd_end: u8 = 0x01;
pub const vision_cmd_direct: u8 = 0x02;

/// Decoder state for xray `XtlsUnpadding`: UUID only on the first padded block;
/// subsequent `CommandPaddingContinue` blocks use a 5-byte header.
pub const VisionUnpadState = struct {
    expect_uuid: bool = true,
};

/// First Vision frame: UUID + command + contentLen + paddingLen + content + padding.
/// Layout matches xray `XtlsPadding` / `XtlsUnpadding` (content before padding).
/// command 0x01 = PaddingEnd (tests / downlink peers that still emit End).
pub fn appendVisionPaddingEnd(out: []u8, uuid: *const [16]u8, content: []const u8) error{BufferTooSmall}!usize {
    return appendVisionFrame(out, vision_cmd_end, uuid, content, 64);
}

/// Continuation Vision frame (no UUID) — used by tests / multi-block peers.
pub fn appendVisionPaddingContinue(out: []u8, content: []const u8) error{BufferTooSmall}!usize {
    return appendVisionFrame(out, vision_cmd_continue, null, content, 16);
}

pub fn appendVisionFrame(
    out: []u8,
    cmd: u8,
    uuid: ?*const [16]u8,
    content: []const u8,
    padding_len: u16,
) error{BufferTooSmall}!usize {
    const hdr: usize = if (uuid != null) 16 + 5 else 5;
    const need = hdr + content.len + padding_len;
    if (out.len < need) return error.BufferTooSmall;
    var i: usize = 0;
    if (uuid) |u| {
        @memcpy(out[0..16], u);
        i = 16;
    }
    out[i] = cmd;
    std.mem.writeInt(u16, out[i + 1 ..][0..2], @intCast(content.len), .big);
    std.mem.writeInt(u16, out[i + 3 ..][0..2], padding_len, .big);
    i += 5;
    if (content.len > 0) @memcpy(out[i..][0..content.len], content);
    i += content.len;
    @memset(out[i .. i + padding_len], 0);
    return need;
}

const VisionFrame = struct {
    /// Total bytes consumed from the front of the buffer (header + content + padding).
    consumed: usize,
    content: []const u8,
    /// PaddingEnd / PaddingDirect — further bytes are not Vision-framed.
    switch_to_raw: bool,
    /// PaddingDirect — peer may send further inner TLS on the raw TCP under Reality.
    switch_to_xtls: bool,
};

/// Parse one Vision frame at the front of `buf`.
/// First block (`state.expect_uuid`): requires leading `uuid`. Later Continue blocks omit UUID.
/// `NeedMore` if incomplete; `NotVision` when the expected framing is absent.
pub fn consumeVisionFrame(
    buf: []const u8,
    uuid: *const [16]u8,
    state: *VisionUnpadState,
) error{ NeedMore, NotVision }!VisionFrame {
    var hdr_off: usize = 0;
    if (state.expect_uuid) {
        if (buf.len < 16) return error.NeedMore;
        if (!std.mem.eql(u8, buf[0..16], uuid)) return error.NotVision;
        hdr_off = 16;
    } else if (buf.len >= 3 and
        buf[0] >= 0x14 and buf[0] <= 0x17 and
        buf[1] == 0x03 and
        buf[2] >= 0x01 and buf[2] <= 0x04)
    {
        // Peer already left Vision framing (PaddingEnd content path, or XTLS raw).
        return error.NotVision;
    }
    if (buf.len < hdr_off + 5) return error.NeedMore;
    const cmd = buf[hdr_off];
    const content_len: usize = std.mem.readInt(u16, buf[hdr_off + 1 ..][0..2], .big);
    const padding_len: usize = std.mem.readInt(u16, buf[hdr_off + 3 ..][0..2], .big);
    const content_off = hdr_off + 5;
    const total = content_off + content_len + padding_len;
    if (buf.len < total) return error.NeedMore;

    // Commit after a complete frame is available (matches xray clearing UserUUID).
    state.expect_uuid = false;

    return .{
        .consumed = total,
        .content = buf[content_off .. content_off + content_len],
        .switch_to_raw = cmd == vision_cmd_end or cmd == vision_cmd_direct,
        .switch_to_xtls = cmd == vision_cmd_direct,
    };
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

test "encodeProbeRequest is cleartext HTTP without Vision" {
    var buf: [512]u8 = undefined;
    const n = try encodeProbeRequest(&buf, "00000000-1111-2222-3333-444444444444");
    // No Vision UUID frame after the VLESS header — raw HTTP follows.
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], util.probe_http) != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "xtls-rprx-vision") == null);
}

test "consumeVisionFrame NeedMore and content before padding" {
    var uuid: [16]u8 = [_]u8{0xab} ** 16;
    var frame_buf: [128]u8 = undefined;
    const http = "HTTP/1.1 200 OK\r\n\r\n";
    const n = try appendVisionPaddingEnd(&frame_buf, &uuid, http);

    // Wire layout: header then content immediately (xray order).
    try std.testing.expectEqualStrings(http, frame_buf[21 .. 21 + http.len]);
    var state: VisionUnpadState = .{};
    try std.testing.expectError(error.NeedMore, consumeVisionFrame(frame_buf[0..20], &uuid, &state));
    try std.testing.expect(state.expect_uuid);

    const frame = try consumeVisionFrame(frame_buf[0..n], &uuid, &state);
    try std.testing.expectEqual(n, frame.consumed);
    try std.testing.expectEqualStrings(http, frame.content);
    try std.testing.expect(frame.switch_to_raw);
    try std.testing.expect(!frame.switch_to_xtls); // End ≠ Direct/XTLS splice
    try std.testing.expect(!state.expect_uuid);
}

test "consumeVisionFrame Direct sets switch_to_xtls" {
    var uuid: [16]u8 = [_]u8{0x55} ** 16;
    const payload = "\x17\x03\x03\x00\x01\x00";
    var frame_buf: [128]u8 = undefined;
    const n = try appendVisionFrame(&frame_buf, vision_cmd_direct, &uuid, payload, 8);
    var state: VisionUnpadState = .{};
    const frame = try consumeVisionFrame(frame_buf[0..n], &uuid, &state);
    try std.testing.expect(frame.switch_to_raw);
    try std.testing.expect(frame.switch_to_xtls);
    try std.testing.expectEqualStrings(payload, frame.content);
}

test "consumeVisionFrame rejects non-uuid prefix" {
    var uuid: [16]u8 = [_]u8{0xab} ** 16;
    // VLESS empty response header + HTTP must not be mistaken for Vision.
    const raw = "\x00\x00HTTP/1.1 200 OK\r\n\r\n";
    var state: VisionUnpadState = .{};
    try std.testing.expectError(error.NotVision, consumeVisionFrame(raw, &uuid, &state));
}

test "consumeVisionFrame continue block omits UUID" {
    var uuid: [16]u8 = [_]u8{0xcd} ** 16;
    const part1 = "HTTP/1.1 200 OK\r\n";
    const part2 = "Content-Length: 0\r\n\r\n";

    var first: [128]u8 = undefined;
    // First block: UUID + Continue (not End).
    const n1 = try appendVisionFrame(&first, vision_cmd_continue, &uuid, part1, 8);

    var cont: [128]u8 = undefined;
    const n2 = try appendVisionPaddingContinue(&cont, part2);

    var state: VisionUnpadState = .{};
    const f1 = try consumeVisionFrame(first[0..n1], &uuid, &state);
    try std.testing.expectEqualStrings(part1, f1.content);
    try std.testing.expect(!f1.switch_to_raw);
    try std.testing.expect(!state.expect_uuid);

    const f2 = try consumeVisionFrame(cont[0..n2], &uuid, &state);
    try std.testing.expectEqualStrings(part2, f2.content);
    try std.testing.expect(!f2.switch_to_raw);
}

test "consumeVisionFrame recognizes raw TLS after UUID phase" {
    var uuid: [16]u8 = [_]u8{0xcd} ** 16;
    var state: VisionUnpadState = .{ .expect_uuid = false };
    const tls_record = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x2a };
    try std.testing.expectError(error.NotVision, consumeVisionFrame(&tls_record, &uuid, &state));
}
