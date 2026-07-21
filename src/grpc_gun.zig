const std = @import("std");

/// Encode gRPC data frame: compressed flag (0) + big-endian length + message.
pub fn wrapGrpc(out: []u8, message: []const u8) error{BufferTooSmall}!usize {
    if (out.len < 5 + message.len) return error.BufferTooSmall;
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(message.len), .big);
    @memcpy(out[5..][0..message.len], message);
    return 5 + message.len;
}

fn unwrapGrpc(frame: []const u8) error{InvalidGrpcFrame}![]const u8 {
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

fn unwrapHunk(msg: []const u8) error{InvalidHunk}![]const u8 {
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
    var shift: u8 = 0;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        if (i >= 10) return error.InvalidVarint;
        const b = buf[i];
        if (shift >= @bitSizeOf(usize)) return error.InvalidVarint;
        // Last partial group (e.g. 10th byte of u64: only bit 0 allowed).
        const bits_left = @as(u8, @bitSizeOf(usize)) - shift;
        if (bits_left < 7 and ((b & 0x7f) >> @intCast(bits_left)) != 0)
            return error.InvalidVarint;
        result |= @as(usize, b & 0x7f) << @intCast(shift);
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

fn writeLiteralHeader(out: []u8, name: []const u8, value: []const u8) error{ BufferTooSmall, HeaderFieldTooLong }!usize {
    // Single-byte HPACK string lengths (no 0x7f extended form).
    if (name.len > 255 or value.len > 255) return error.HeaderFieldTooLong;
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

/// True if an HTTP/2 HEADERS block indicates `:status: 200`.
/// Accepts indexed static-table form (`0x88`) and literal forms with indexed or
/// literal `:status` name and raw value `200`. Skips PADDED / PRIORITY framing.
pub fn headersIndicateStatus200(payload: []const u8, flags: u8) bool {
    var p = payload;
    if ((flags & 0x08) != 0) { // PADDED
        if (p.len < 1) return false;
        const pad: usize = p[0];
        p = p[1..];
        if (p.len < pad) return false;
        p = p[0 .. p.len - pad];
    }
    if ((flags & 0x20) != 0) { // PRIORITY
        if (p.len < 5) return false;
        p = p[5..];
    }
    return hpackHasStatus200(p);
}

fn hpackHasStatus200(block: []const u8) bool {
    var p = block;
    while (p.len > 0) {
        const b = p[0];
        if ((b & 0x80) != 0) {
            // Indexed header field representation.
            const idx = b & 0x7f;
            if (idx == 0) return false;
            if (idx == 8) return true; // static :status 200
            p = p[1..];
            continue;
        }
        if ((b & 0xc0) == 0x40) {
            // Literal with incremental indexing.
            const name_idx = b & 0x3f;
            p = p[1..];
            const is_status = blk: {
                if (name_idx == 8) break :blk true;
                if (name_idx != 0) break :blk false;
                break :blk hpackMatchLiteralName(&p, ":status") catch return false;
            };
            if (!is_status) {
                if (!hpackSkipString(&p)) return false;
                continue;
            }
            return hpackConsumeRawValue(&p, "200");
        }
        if ((b & 0xf0) == 0x00 or (b & 0xf0) == 0x10) {
            // Without indexing / never indexed — 4-bit name index.
            const name_idx = b & 0x0f;
            p = p[1..];
            const is_status = blk: {
                if (name_idx == 8) break :blk true;
                if (name_idx != 0) break :blk false;
                break :blk hpackMatchLiteralName(&p, ":status") catch return false;
            };
            if (!is_status) {
                if (!hpackSkipString(&p)) return false;
                continue;
            }
            return hpackConsumeRawValue(&p, "200");
        }
        // Dynamic table size update (0x20) or unknown — stop.
        return false;
    }
    return false;
}

fn hpackSkipString(p: *[]const u8) bool {
    const s = p.*;
    if (s.len < 1) return false;
    const len: usize = s[0] & 0x7f;
    if (len == 0x7f) return false; // overlong; status values are tiny
    if (1 + len > s.len) return false;
    p.* = s[1 + len ..];
    return true;
}

fn hpackMatchLiteralName(p: *[]const u8, want: []const u8) error{InvalidHpack}!bool {
    const s = p.*;
    if (s.len < 1) return error.InvalidHpack;
    if ((s[0] & 0x80) != 0) return error.InvalidHpack; // Huffman name unused for :status
    const len: usize = s[0] & 0x7f;
    if (len == 0x7f or 1 + len > s.len) return error.InvalidHpack;
    const matched = std.mem.eql(u8, s[1 .. 1 + len], want);
    p.* = s[1 + len ..];
    return matched;
}

fn hpackConsumeRawValue(p: *[]const u8, want: []const u8) bool {
    const s = p.*;
    if (s.len < 1) return false;
    if ((s[0] & 0x80) != 0) return false; // Huffman — uncommon for "200"
    const len: usize = s[0] & 0x7f;
    if (len == 0x7f or 1 + len > s.len) return false;
    return std.mem.eql(u8, s[1 .. 1 + len], want);
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

test "writeLiteralHeader rejects fields longer than 255" {
    var buf: [512]u8 = undefined;
    const long = [_]u8{'a'} ** 256;
    try std.testing.expectError(error.HeaderFieldTooLong, writeLiteralHeader(&buf, &long, "x"));
    try std.testing.expectError(error.HeaderFieldTooLong, writeLiteralHeader(&buf, "x", &long));
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

test "headersIndicateStatus200 skips padding" {
    // PADDED + indexed :status 200
    const payload = [_]u8{ 2, 0x88, 0xaa, 0xbb };
    try std.testing.expect(headersIndicateStatus200(&payload, 0x08));
    // 0x88 buried in value must not match without a real :status field
    const noise = [_]u8{ 0x00, 0x88 };
    try std.testing.expect(!headersIndicateStatus200(&noise, 0));
    try std.testing.expect(headersIndicateStatus200(&[_]u8{0x88}, 0));
}

test "headersIndicateStatus200 accepts literal :status 200" {
    // Literal without indexing, name index 8, raw "200"
    const indexed_name = [_]u8{ 0x08, 0x03, '2', '0', '0' };
    try std.testing.expect(headersIndicateStatus200(&indexed_name, 0));
    // Incremental indexing, name index 8
    const incr = [_]u8{ 0x48, 0x03, '2', '0', '0' };
    try std.testing.expect(headersIndicateStatus200(&incr, 0));
    // Literal name ":status" + "200" after an unrelated field
    const lit_name = [_]u8{
        0x00, 0x04, 'h', 'o', 's', 't', 0x01, 'x',
        0x00, 0x07, ':', 's', 't', 'a', 't',  'u',
        's',  0x03, '2', '0', '0',
    };
    try std.testing.expect(headersIndicateStatus200(&lit_name, 0));
    // Wrong status
    const not_ok = [_]u8{ 0x08, 0x03, '4', '0', '4' };
    try std.testing.expect(!headersIndicateStatus200(&not_ok, 0));
}

test "readVarint rejects overlong continuation" {
    const crafted = [_]u8{0xff} ** 10;
    try std.testing.expectError(error.InvalidVarint, readVarint(&crafted));
}

test "readVarint rejects overflow past usize" {
    // 9 continuation bytes + terminating 0x02 would set bit 64 (u64) / overflow.
    const crafted = [_]u8{0xff} ** 9 ++ [_]u8{0x02};
    try std.testing.expectError(error.InvalidVarint, readVarint(&crafted));
    // Max usize: 9×0xff then 0x01 (bit 63 only) is valid on 64-bit.
    if (@bitSizeOf(usize) == 64) {
        const max_u64 = [_]u8{0xff} ** 9 ++ [_]u8{0x01};
        const v, const n = try readVarint(&max_u64);
        try std.testing.expectEqual(@as(usize, std.math.maxInt(usize)), v);
        try std.testing.expectEqual(@as(usize, 10), n);
    }
}
