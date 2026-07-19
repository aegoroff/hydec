const std = @import("std");
const util = @import("util.zig");
const Io = std.Io;

const ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn expectAccept(key_b64: []const u8, out: *[28]u8) []const u8 {
    var digest: [20]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key_b64);
    hasher.update(ws_guid);
    hasher.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

fn headerValue(response: []const u8, name: []const u8) ?[]const u8 {
    var rest = response;
    // Skip status line
    if (std.mem.indexOf(u8, rest, "\r\n")) |nl| {
        rest = rest[nl + 2 ..];
    } else return null;

    while (std.mem.indexOf(u8, rest, "\r\n")) |nl| {
        const line = rest[0..nl];
        rest = rest[nl + 2 ..];
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(key, name)) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}

fn headerContainsToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, value, ", \t");
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(part, token)) return true;
    }
    return false;
}

fn validateUpgradeResponse(hdr: []const u8, key_b64: []const u8) !void {
    if (!std.mem.startsWith(u8, hdr, "HTTP/1.1 101") and
        !std.mem.startsWith(u8, hdr, "HTTP/1.0 101"))
    {
        return error.WebSocketUpgradeFailed;
    }

    const upgrade = headerValue(hdr, "Upgrade") orelse return error.WebSocketUpgradeFailed;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.WebSocketUpgradeFailed;

    const connection = headerValue(hdr, "Connection") orelse return error.WebSocketUpgradeFailed;
    if (!headerContainsToken(connection, "Upgrade")) return error.WebSocketUpgradeFailed;

    const accept = headerValue(hdr, "Sec-WebSocket-Accept") orelse return error.WebSocketUpgradeFailed;
    var expect_buf: [28]u8 = undefined;
    const expected = expectAccept(key_b64, &expect_buf);
    if (!std.mem.eql(u8, accept, expected)) return error.WebSocketAcceptMismatch;
}

const max_upgrade_headers: usize = 2048;

/// Consume the HTTP 101 upgrade response from `reader`, leaving any bytes past
/// `\r\n\r\n` buffered for subsequent WebSocket frame reads.
fn consumeUpgradeResponse(reader: *Io.Reader, key_b64: []const u8) !void {
    while (true) {
        const buffered = reader.buffered();
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |end| {
            const hdr_end = end + 4;
            try validateUpgradeResponse(buffered[0..hdr_end], key_b64);
            reader.toss(hdr_end);
            return;
        }
        if (buffered.len >= max_upgrade_headers) return error.WebSocketHeadersTooLarge;
        reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedEndOfStream,
            else => |e| return e,
        };
    }
}

pub fn performUpgrade(
    reader: *Io.Reader,
    writer: *Io.Writer,
    io: Io,
    path: []const u8,
    host_header: []const u8,
) !void {
    if (std.mem.indexOfAny(u8, path, "\r\n") != null) return error.InvalidWsPath;
    if (std.mem.indexOfAny(u8, host_header, "\r\n") != null) return error.InvalidWsHost;

    var key_raw: [16]u8 = undefined;
    io.random(&key_raw);

    var key_b64_buf: [32]u8 = undefined;
    const key_b64 = std.base64.standard.Encoder.encode(&key_b64_buf, &key_raw);

    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        .{ path, host_header, key_b64 },
    );
    try writer.writeAll(req);
    try writer.flush();

    try consumeUpgradeResponse(reader, key_b64);
}

fn writeControlFrame(writer: *Io.Writer, io: Io, opcode: u8, payload: []const u8) !void {
    if (payload.len > 125) return error.PayloadTooLarge;
    var mask: [4]u8 = undefined;
    io.random(&mask);

    var header: [6]u8 = undefined;
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 0x80 | @as(u8, @intCast(payload.len));
    @memcpy(header[2..6], &mask);
    try writer.writeAll(header[0..6]);
    var i: usize = 0;
    while (i < payload.len) : (i += 1) {
        try writer.writeByte(payload[i] ^ mask[i % 4]);
    }
    try writer.flush();
}

pub fn writeBinaryFrame(writer: *Io.Writer, io: Io, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    io.random(&mask);

    var header: [14]u8 = undefined;
    header[0] = 0x82;
    var hlen: usize = 2;
    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= 65535) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        hlen = 4;
    } else {
        return error.PayloadTooLarge;
    }
    @memcpy(header[hlen..][0..4], &mask);
    hlen += 4;
    try writer.writeAll(header[0..hlen]);

    var i: usize = 0;
    while (i < payload.len) : (i += 1) {
        try writer.writeByte(payload[i] ^ mask[i % 4]);
    }
    try writer.flush();
}

/// Read the next complete binary data frame (FIN), answering ping and ignoring pong.
/// Empty or text frames are rejected so Trojan-over-WS matches TCP's ≥1-byte bar.
pub fn readBinaryFrame(reader: *Io.Reader, writer: *Io.Writer, io: Io, out: []u8) !usize {
    while (true) {
        var hdr: [2]u8 = undefined;
        try reader.readSliceAll(&hdr);
        const fin = (hdr[0] & 0x80) != 0;
        const opcode = hdr[0] & 0x0f;
        const masked = (hdr[1] & 0x80) != 0;
        var len: usize = hdr[1] & 0x7f;
        if (len == 126) {
            var ext: [2]u8 = undefined;
            try reader.readSliceAll(&ext);
            len = std.mem.readInt(u16, &ext, .big);
        } else if (len == 127) {
            // Drain the 8-byte extended length so the stream stays aligned if the caller retries.
            var ext: [8]u8 = undefined;
            try reader.readSliceAll(&ext);
            return error.PayloadTooLarge;
        }
        var mask: [4]u8 = .{ 0, 0, 0, 0 };
        if (masked) try reader.readSliceAll(&mask);
        if (len > out.len) {
            // Drain payload so the stream stays aligned if the caller retries.
            try reader.discardAll(len);
            return error.BufferTooSmall;
        }
        try reader.readSliceAll(out[0..len]);
        if (masked) {
            for (out[0..len], 0..) |*b, i| b.* ^= mask[i % 4];
        }
        switch (opcode) {
            0x8 => return error.WebSocketClosed,
            0x9 => {
                try writeControlFrame(writer, io, 0xA, out[0..len]);
                continue;
            },
            0xA => continue,
            0x2 => {
                if (!fin) return error.WsFragmentUnsupported;
                if (len == 0) return error.EmptyWsFrame;
                return len;
            },
            0x1 => return error.UnexpectedWsOpcode,
            else => return error.UnexpectedWsOpcode,
        }
    }
}

test "expectAccept matches RFC 6455 example" {
    // RFC 6455 §1.3 example key → accept
    var out: [28]u8 = undefined;
    const accept = expectAccept("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "validateUpgradeResponse requires accept" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const hdr =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    try validateUpgradeResponse(hdr, key);

    const bad =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: wrong\r\n" ++
        "\r\n";
    try std.testing.expectError(error.WebSocketAcceptMismatch, validateUpgradeResponse(bad, key));
}

test "consumeUpgradeResponse keeps post-header bytes" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const wire =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n" ++
        "LEFTOVER";
    var reader: Io.Reader = .fixed(wire);
    try consumeUpgradeResponse(&reader, key);
    try std.testing.expectEqualStrings("LEFTOVER", reader.buffered());
}

test "readBinaryFrame BufferTooSmall drains payload" {
    // Unmasked binary frames (server→client): oversized then 1-byte.
    const wire = [_]u8{
        0x82, 0x05, 'a', 'b', 'c', 'd', 'e', // len=5
        0x82, 0x01, 'Z',
    };
    var reader: Io.Reader = .fixed(&wire);
    var sink_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&sink_buf);
    const io = std.Io.Threaded.global_single_threaded.io();

    var small: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, readBinaryFrame(&reader, &writer, io, &small));
    var out: [8]u8 = undefined;
    const n = try readBinaryFrame(&reader, &writer, io, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

test "ws module loads" {
    _ = util;
    try std.testing.expect(true);
}
