const std = @import("std");
const util = @import("util.zig");
const Io = std.Io;

pub fn performUpgrade(
    reader: *Io.Reader,
    writer: *Io.Writer,
    io: Io,
    path: []const u8,
    host_header: []const u8,
) !void {
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

    var hdr: [2048]u8 = undefined;
    var hdr_len: usize = 0;
    while (hdr_len < hdr.len) {
        const n = try reader.readSliceShort(hdr[hdr_len..]);
        if (n == 0) return error.UnexpectedEndOfStream;
        hdr_len += n;
        if (std.mem.indexOf(u8, hdr[0..hdr_len], "\r\n\r\n")) |_| break;
    }
    if (!std.mem.startsWith(u8, hdr[0..hdr_len], "HTTP/1.1 101") and
        !std.mem.startsWith(u8, hdr[0..hdr_len], "HTTP/1.0 101"))
    {
        return error.WebSocketUpgradeFailed;
    }
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

/// Read the next data frame, answering ping and ignoring pong.
pub fn readBinaryFrame(reader: *Io.Reader, writer: *Io.Writer, io: Io, out: []u8) !usize {
    while (true) {
        var hdr: [2]u8 = undefined;
        try reader.readSliceAll(&hdr);
        const opcode = hdr[0] & 0x0f;
        const masked = (hdr[1] & 0x80) != 0;
        var len: usize = hdr[1] & 0x7f;
        if (len == 126) {
            var ext: [2]u8 = undefined;
            try reader.readSliceAll(&ext);
            len = std.mem.readInt(u16, &ext, .big);
        } else if (len == 127) {
            return error.PayloadTooLarge;
        }
        var mask: [4]u8 = .{ 0, 0, 0, 0 };
        if (masked) try reader.readSliceAll(&mask);
        if (len > out.len) return error.BufferTooSmall;
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
            0x1, 0x2 => return len,
            else => return error.UnexpectedWsOpcode,
        }
    }
}

test "ws module loads" {
    _ = util;
    try std.testing.expect(true);
}
