const std = @import("std");

/// Encode gRPC data frame: compressed flag (0) + big-endian length + message.
pub fn wrapGrpc(out: []u8, message: []const u8) error{BufferTooSmall}!usize {
    if (out.len < 5 + message.len) return error.BufferTooSmall;
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(message.len), .big);
    @memcpy(out[5..][0..message.len], message);
    return 5 + message.len;
}

pub fn unwrapGrpc(frame: []const u8) error{InvalidGrpcFrame}![]const u8 {
    if (frame.len < 5) return error.InvalidGrpcFrame;
    const len = std.mem.readInt(u32, frame[1..5], .big);
    if (5 + len > frame.len) return error.InvalidGrpcFrame;
    return frame[5 .. 5 + len];
}

/// xray/sing-box gun: `message Hunk { bytes data = 1; }`
pub fn wrapHunk(out: []u8, data: []const u8) error{BufferTooSmall}!usize {
    const varint_len = varintSize(data.len);
    const need = 1 + varint_len + data.len;
    if (out.len < need) return error.BufferTooSmall;
    out[0] = 0x0a;
    const n = writeVarint(out[1..], data.len);
    @memcpy(out[1 + n ..][0..data.len], data);
    return 1 + n + data.len;
}

pub fn unwrapHunk(msg: []const u8) error{InvalidHunk}![]const u8 {
    if (msg.len < 2 or msg[0] != 0x0a) return error.InvalidHunk;
    var pos: usize = 1;
    const len, const varint_bytes = readVarint(msg[pos..]) catch return error.InvalidHunk;
    pos += varint_bytes;
    if (pos + len > msg.len) return error.InvalidHunk;
    return msg[pos .. pos + len];
}

fn varintSize(v: usize) usize {
    var x = v;
    var n: usize = 1;
    while (x >= 0x80) : (n += 1) x >>= 7;
    return n;
}

fn writeVarint(out: []u8, v: usize) usize {
    var x = v;
    var i: usize = 0;
    while (true) {
        const b: u8 = @truncate(x);
        if (x < 0x80) {
            out[i] = b;
            return i + 1;
        }
        out[i] = b | 0x80;
        x >>= 7;
        i += 1;
    }
}

fn readVarint(buf: []const u8) error{InvalidVarint}!struct { usize, usize } {
    var result: usize = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < buf.len and i < 10) : (i += 1) {
        const b = buf[i];
        result |= @as(usize, b & 0x7f) << shift;
        if ((b & 0x80) == 0) return .{ result, i + 1 };
        shift += 7;
    }
    return error.InvalidVarint;
}

fn writeFrameHeader(out: []u8, length: u24, typ: u8, flags: u8, stream_id: u31) void {
    out[0] = @intCast((length >> 16) & 0xff);
    out[1] = @intCast((length >> 8) & 0xff);
    out[2] = @intCast(length & 0xff);
    out[3] = typ;
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], stream_id, .big);
}

fn writeLiteralHeader(out: []u8, name: []const u8, value: []const u8) error{BufferTooSmall}!usize {
    if (out.len < 1 + 1 + name.len + 1 + value.len) return error.BufferTooSmall;
    var i: usize = 0;
    out[i] = 0x00;
    i += 1;
    out[i] = @intCast(name.len);
    i += 1;
    @memcpy(out[i..][0..name.len], name);
    i += name.len;
    out[i] = @intCast(value.len);
    i += 1;
    @memcpy(out[i..][0..value.len], value);
    i += value.len;
    return i;
}

fn writeLiteralIndexedName(out: []u8, index: u8, value: []const u8) error{BufferTooSmall}!usize {
    // Literal Header Field without Indexing — Indexed Name (0000xxxx)
    if (index == 0 or index >= 15) return error.BufferTooSmall;
    if (out.len < 1 + 1 + value.len) return error.BufferTooSmall;
    out[0] = index;
    out[1] = @intCast(value.len);
    @memcpy(out[2..][0..value.len], value);
    return 2 + value.len;
}

pub fn buildClientPrefaceSettings(out: []u8) error{BufferTooSmall}!usize {
    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // ENABLE_PUSH=0 — required by many gRPC/gun peers
    const settings_payload = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
    };
    if (out.len < preface.len + 9 + settings_payload.len) return error.BufferTooSmall;
    @memcpy(out[0..preface.len], preface);
    writeFrameHeader(out[preface.len..][0..9], @intCast(settings_payload.len), 0x04, 0, 0);
    @memcpy(out[preface.len + 9 ..][0..settings_payload.len], &settings_payload);
    return preface.len + 9 + settings_payload.len;
}

pub fn buildGunHeaders(out: []u8, service_name: []const u8, authority: []const u8) !usize {
    var path_buf: [256]u8 = undefined;
    const path = if (service_name.len == 0)
        "/GunService/Tun"
    else
        try std.fmt.bufPrint(&path_buf, "/{s}/Tun", .{service_name});

    const auth = if (authority.len > 0) authority else "localhost";

    var hpack: [512]u8 = undefined;
    var hp: usize = 0;
    // All-literal HPACK — avoids static-table index mistakes.
    hp += try writeLiteralHeader(hpack[hp..], ":method", "POST");
    // sing-box gun-lite uses https even over REALITY/TLS.
    hp += try writeLiteralHeader(hpack[hp..], ":scheme", "https");
    hp += try writeLiteralHeader(hpack[hp..], ":path", path);
    hp += try writeLiteralHeader(hpack[hp..], ":authority", auth);
    hp += try writeLiteralHeader(hpack[hp..], "content-type", "application/grpc");
    hp += try writeLiteralHeader(hpack[hp..], "user-agent", "grpc-go/1.48.0");
    hp += try writeLiteralHeader(hpack[hp..], "te", "trailers");

    if (out.len < 9 + hp) return error.BufferTooSmall;
    writeFrameHeader(out[0..9], @intCast(hp), 0x01, 0x04, 1);
    @memcpy(out[9..][0..hp], hpack[0..hp]);
    return 9 + hp;
}

pub fn buildGunRequest(out: []u8, service_name: []const u8, authority: []const u8, vless_payload: []const u8) !usize {
    var n: usize = 0;
    n += try buildGunHeaders(out[n..], service_name, authority);
    var hunk: [320]u8 = undefined;
    const hunk_len = try wrapHunk(&hunk, vless_payload);
    var grpc_msg: [384]u8 = undefined;
    const glen = try wrapGrpc(&grpc_msg, hunk[0..hunk_len]);
    n += try buildDataFrame(out[n..], 1, grpc_msg[0..glen], false);
    return n;
}

/// Build a single application-data blob: preface+SETTINGS+HEADERS+DATA (gun).
pub fn buildGunClientFlight(
    out: []u8,
    service_name: []const u8,
    authority: []const u8,
    vless_payload: []const u8,
) !usize {
    var n: usize = 0;
    n += try buildClientPrefaceSettings(out[n..]);
    n += try buildGunRequest(out[n..], service_name, authority, vless_payload);
    return n;
}

pub fn buildDataFrame(out: []u8, stream_id: u31, payload: []const u8, end_stream: bool) error{BufferTooSmall}!usize {
    if (out.len < 9 + payload.len) return error.BufferTooSmall;
    const flags: u8 = if (end_stream) 0x01 else 0;
    writeFrameHeader(out[0..9], @intCast(payload.len), 0x00, flags, stream_id);
    @memcpy(out[9..][0..payload.len], payload);
    return 9 + payload.len;
}

pub fn buildPingAck(out: []u8, payload: *const [8]u8) error{BufferTooSmall}!usize {
    if (out.len < 17) return error.BufferTooSmall;
    writeFrameHeader(out[0..9], 8, 0x06, 0x01, 0);
    @memcpy(out[9..17], payload);
    return 17;
}

pub fn buildSettingsAck(out: []u8) error{BufferTooSmall}!usize {
    if (out.len < 9) return error.BufferTooSmall;
    writeFrameHeader(out[0..9], 0, 0x04, 0x01, 0);
    return 9;
}

pub fn buildWindowUpdate(out: []u8, stream_id: u31, increment: u32) error{BufferTooSmall}!usize {
    if (out.len < 13) return error.BufferTooSmall;
    writeFrameHeader(out[0..9], 4, 0x08, 0, stream_id);
    std.mem.writeInt(u32, out[9..13], increment & 0x7fffffff, .big);
    return 13;
}

pub fn formatAuthority(buf: []u8, sni: []const u8, port: u16, explicit: []const u8) ![]const u8 {
    if (explicit.len > 0) return explicit;
    // Match sing-box v2raygrpclite: Host = SNI:port
    if (port == 443) return sni;
    return std.fmt.bufPrint(buf, "{s}:{d}", .{ sni, port });
}

pub fn vlessFromGrpcData(payload: []const u8) ![]const u8 {
    const grpc_payload = try unwrapGrpc(payload);
    return unwrapHunk(grpc_payload) catch grpc_payload;
}

test "wrapGrpc roundtrip" {
    var buf: [64]u8 = undefined;
    const n = try wrapGrpc(&buf, "hello");
    try std.testing.expectEqualStrings("hello", try unwrapGrpc(buf[0..n]));
}

test "preface starts correctly" {
    var out: [128]u8 = undefined;
    const n = try buildClientPrefaceSettings(&out);
    try std.testing.expect(std.mem.startsWith(u8, out[0..n], "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
}
