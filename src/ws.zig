const std = @import("std");
const netutil = @import("netutil.zig");
const Io = std.Io;

/// One TLS-backed WebSocket: `tls` encrypts, `socket` puts the ciphertext on the wire.
/// They travel together because every write has to reach both — Zig's TLS client only
/// advances the socket writer's buffer.
pub const Conn = struct {
    reader: *Io.Reader,
    tls: *Io.Writer,
    socket: *Io.Writer,

    fn flush(self: Conn) !void {
        return netutil.flushTls(self.tls, self.socket);
    }
};

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn expectAccept(key_b64: []const u8, out: *[28]u8) []const u8 {
    var digest: [20]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key_b64);
    hasher.update(WS_GUID);
    hasher.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

fn headerValue(response: []const u8, name: []const u8) ?[]const u8 {
    var rest = response;
    // Skip status line
    if (std.mem.find(u8, rest, "\r\n")) |nl| {
        rest = rest[nl + 2 ..];
    } else return null;

    while (std.mem.find(u8, rest, "\r\n")) |nl| {
        const line = rest[0..nl];
        rest = rest[nl + 2 ..];
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(key, name)) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}

fn valueContainsToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, value, ", \t");
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(part, token)) return true;
    }
    return false;
}

fn headerContainsToken(response: []const u8, name: []const u8, token: []const u8) bool {
    var rest = response;
    if (std.mem.find(u8, rest, "\r\n")) |nl| {
        rest = rest[nl + 2 ..];
    } else return false;

    while (std.mem.find(u8, rest, "\r\n")) |nl| {
        const line = rest[0..nl];
        rest = rest[nl + 2 ..];
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(key, name) and
            valueContainsToken(std.mem.trim(u8, line[colon + 1 ..], " \t"), token)) return true;
    }
    return false;
}

fn validateUpgradeResponse(hdr: []const u8, key_b64: []const u8) !void {
    const status_prefix_len = "HTTP/1.1 101".len;
    const valid_version = std.mem.startsWith(u8, hdr, "HTTP/1.1 101") or
        std.mem.startsWith(u8, hdr, "HTTP/1.0 101");
    const status_end = std.mem.find(u8, hdr, "\r\n") orelse return error.WebSocketUpgradeFailed;
    const status_line = hdr[0..status_end];
    const valid_delimiter = status_line.len == status_prefix_len or
        (status_line.len > status_prefix_len and status_line[status_prefix_len] == ' ');
    if (!valid_version or !valid_delimiter) return error.WebSocketUpgradeFailed;

    const upgrade = headerValue(hdr, "Upgrade") orelse return error.WebSocketUpgradeFailed;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.WebSocketUpgradeFailed;

    if (!headerContainsToken(hdr, "Connection", "Upgrade")) return error.WebSocketUpgradeFailed;

    const accept = headerValue(hdr, "Sec-WebSocket-Accept") orelse return error.WebSocketUpgradeFailed;
    var expect_buf: [28]u8 = undefined;
    const expected = expectAccept(key_b64, &expect_buf);
    if (!std.mem.eql(u8, accept, expected)) return error.WebSocketAcceptMismatch;
}

const MAX_UPGRADE_HEADERS: usize = 2048;

/// Consume the HTTP 101 upgrade response from `reader`, leaving any bytes past
/// `\r\n\r\n` buffered for subsequent WebSocket frame reads.
fn consumeUpgradeResponse(reader: *Io.Reader, key_b64: []const u8) !void {
    while (true) {
        const buffered = reader.buffered();
        if (std.mem.find(u8, buffered, "\r\n\r\n")) |end| {
            const hdr_end = end + 4;
            try validateUpgradeResponse(buffered[0..hdr_end], key_b64);
            reader.toss(hdr_end);
            return;
        }
        if (buffered.len >= MAX_UPGRADE_HEADERS) return error.WebSocketHeadersTooLarge;
        reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedEndOfStream,
            else => |e| return e,
        };
    }
}

fn isRequestTargetByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/', '?' => true,
        else => false,
    };
}

fn writeRequestTarget(writer: *Io.Writer, path: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (path) |c| {
        if (isRequestTargetByte(c)) {
            try writer.writeByte(c);
        } else {
            const escaped = [3]u8{ '%', hex[c >> 4], hex[c & 0x0f] };
            try writer.writeAll(&escaped);
        }
    }
}

fn writeUpgradeRequest(writer: *Io.Writer, path: []const u8, host_header: []const u8, key_b64: []const u8) !void {
    try writer.writeAll("GET ");
    try writeRequestTarget(writer, path);
    try writer.print(
        " HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        .{ host_header, key_b64 },
    );
}

pub fn performUpgrade(
    conn: Conn,
    io: Io,
    path: []const u8,
    host_header: []const u8,
) !void {
    if (std.mem.findAny(u8, path, "\r\n") != null) return error.InvalidWsPath;
    if (std.mem.findAny(u8, host_header, "\r\n") != null) return error.InvalidWsHost;

    var key_raw: [16]u8 = undefined;
    io.random(&key_raw);

    var key_b64_buf: [32]u8 = undefined;
    const key_b64 = std.base64.standard.Encoder.encode(&key_b64_buf, &key_raw);

    try writeUpgradeRequest(conn.tls, path, host_header, key_b64);
    try conn.flush();

    try consumeUpgradeResponse(conn.reader, key_b64);
}

fn writeControlFrame(conn: Conn, io: Io, opcode: u8, payload: []const u8) !void {
    const writer = conn.tls;
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
    try conn.flush();
}

pub fn writeBinaryFrame(conn: Conn, io: Io, payload: []const u8) !void {
    const writer = conn.tls;
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
    try conn.flush();
}

/// Read the next complete binary message, answering ping and ignoring pong.
/// Empty messages are skipped so the caller still gets TCP-like ≥1-byte reads.
pub fn readBinaryFrame(conn: Conn, io: Io, out: []u8) !usize {
    const reader = conn.reader;
    var message_len: usize = 0;
    var fragmented = false;
    var control_buf: [125]u8 = undefined;
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
            // 64-bit extended length. Frames this large never occur in Trojan-over-WS,
            // but drain mask+payload so a caller retry reads the next frame (mirrors the
            // len > out.len path). `discardAll` of a huge length will block until the
            // probe deadline (DeadlineShutdown) on a live socket.
            var ext: [8]u8 = undefined;
            try reader.readSliceAll(&ext);
            const big = std.mem.readInt(u64, &ext, .big);
            if (big > std.math.maxInt(usize)) return error.PayloadTooLarge; // cannot represent/drain on this platform
            if (masked) {
                var discard_mask: [4]u8 = undefined;
                try reader.readSliceAll(&discard_mask);
            }
            try reader.discardAll(@intCast(big));
            return error.PayloadTooLarge;
        }
        var mask: [4]u8 = .{ 0, 0, 0, 0 };
        if (masked) try reader.readSliceAll(&mask);

        const data_frame = opcode == 0x2 or (opcode == 0x0 and fragmented);
        const control_frame = (opcode & 0x8) != 0;
        const dest = if (data_frame)
            out[message_len..]
        else if (control_frame)
            control_buf[0..]
        else
            out;
        if (len > dest.len) {
            // Drain payload so the stream stays aligned if the caller retries.
            try reader.discardAll(len);
            return error.BufferTooSmall;
        }
        try reader.readSliceAll(dest[0..len]);
        if (masked) {
            for (dest[0..len], 0..) |*b, i| b.* ^= mask[i % 4];
        }
        switch (opcode) {
            0x8 => return error.WebSocketClosed,
            0x9 => {
                try writeControlFrame(conn, io, 0xA, dest[0..len]);
                continue;
            },
            0xA => continue,
            0x2 => {
                if (fragmented) return error.UnexpectedWsOpcode;
                if (fin) {
                    if (len == 0) continue;
                    return len;
                }
                fragmented = true;
                message_len = len;
            },
            0x0 => {
                if (!fragmented) return error.UnexpectedWsOpcode;
                message_len += len;
                if (fin) {
                    fragmented = false;
                    if (message_len == 0) continue;
                    return message_len;
                }
            },
            0x1 => return error.UnexpectedWsOpcode,
            else => return error.UnexpectedWsOpcode,
        }
    }
}

test "writeUpgradeRequest serializes a decoded path as exact request bytes" {
    var buf: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeUpgradeRequest(
        &writer,
        "/chat room/100%/caf\u{00e9}?x=a b&y=/ok#frag\r\n\x00",
        "example.com",
        "dGhlIHNhbXBsZSBub25jZQ==",
    );
    try std.testing.expectEqualStrings(
        "GET /chat%20room/100%25/caf%C3%A9?x=a%20b&y=/ok%23frag%0D%0A%00 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
        writer.buffered(),
    );
}

test "writeUpgradeRequest handles long paths and hosts" {
    var long_path_buf: [701]u8 = undefined;
    long_path_buf[0] = '/';
    @memset(long_path_buf[1..], 'a');
    var long_host_buf: [608]u8 = undefined;
    @memset(long_host_buf[0..600], 'b');
    @memcpy(long_host_buf[600..], ".example");

    var buf: [2048]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeUpgradeRequest(&writer, &long_path_buf, &long_host_buf, "dGhlIHNhbXBsZSBub25jZQ==");

    const req = writer.buffered();
    const path_end = "GET ".len + long_path_buf.len;
    const host_start = path_end + " HTTP/1.1\r\nHost: ".len;
    try std.testing.expect(req.len > 512);
    try std.testing.expectEqualStrings("GET ", req[0..4]);
    try std.testing.expectEqualStrings(&long_path_buf, req[4..path_end]);
    try std.testing.expectEqualStrings(" HTTP/1.1\r\nHost: ", req[path_end..host_start]);
    try std.testing.expectEqualStrings(&long_host_buf, req[host_start..][0..long_host_buf.len]);
    try std.testing.expect(std.mem.endsWith(u8, req, "Sec-WebSocket-Version: 13\r\n\r\n"));
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

    const repeated_connection =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    try validateUpgradeResponse(repeated_connection, key);

    const bad =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: wrong\r\n" ++
        "\r\n";
    try std.testing.expectError(error.WebSocketAcceptMismatch, validateUpgradeResponse(bad, key));
}

test "validateUpgradeResponse rejects malformed 101 statuses" {
    const hdr_1010 =
        "HTTP/1.1 1010 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    const hdr_garbage =
        "HTTP/1.1 101garbage\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    const hdr_bad_cr =
        "HTTP/1.1 101\rX\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    const headers = [_][]const u8{ hdr_1010, hdr_garbage, hdr_bad_cr };
    for (headers) |hdr| {
        try std.testing.expectError(
            error.WebSocketUpgradeFailed,
            validateUpgradeResponse(hdr, "dGhlIHNhbXBsZSBub25jZQ=="),
        );
    }
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

test "readBinaryFrame assembles fragments around a ping" {
    const wire = [_]u8{
        0x02, 0x02, 'a', 'b', // binary, FIN=0
        0x89, 0x01, 'x', // ping
        0x80, 0x02, 'c', 'd', // continuation, FIN=1
        0x82, 0x01, 'Z',
    };
    var reader: Io.Reader = .fixed(&wire);
    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &writer };
    const io = std.Io.Threaded.global_single_threaded.io();

    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try readBinaryFrame(conn, io, &out));
    try std.testing.expectEqualStrings("abcd", out[0..4]);
    try std.testing.expectEqual(@as(usize, 1), try readBinaryFrame(conn, io, &out));
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

test "readBinaryFrame skips empty binary messages" {
    const wire = [_]u8{ 0x82, 0x00, 0x82, 0x01, 'Z' };
    var reader: Io.Reader = .fixed(&wire);
    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &writer };
    const io = std.Io.Threaded.global_single_threaded.io();

    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try readBinaryFrame(conn, io, &out));
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

test "readBinaryFrame BufferTooSmall drains payload" {
    // Unmasked binary frames (server→client): oversized then 1-byte.
    const wire = [_]u8{
        0x82, 0x05, 'a', 'b', 'c', 'd', 'e', // len=5
        0x82, 0x01, 'Z',
    };
    var reader: Io.Reader = .fixed(&wire);
    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &writer };
    const io = std.Io.Threaded.global_single_threaded.io();

    var small: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, readBinaryFrame(conn, io, &small));
    var out: [8]u8 = undefined;
    const n = try readBinaryFrame(conn, io, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

test "readBinaryFrame drains 64-bit length frame for alignment" {
    const wire = [_]u8{
        0x82, 0x7f, // FIN binary, 64-bit length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // length 3
        'a',  'b',  'c',  0x82, 0x01, 'Z',
    };
    var reader: Io.Reader = .fixed(&wire);
    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &writer };
    const io = std.Io.Threaded.global_single_threaded.io();

    var out: [8]u8 = undefined;
    try std.testing.expectError(error.PayloadTooLarge, readBinaryFrame(conn, io, &out));
    const n = try readBinaryFrame(conn, io, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

test "readBinaryFrame drains masked 64-bit length frame" {
    const wire = [_]u8{
        0x82, 0xff, // FIN binary, masked, 64-bit length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // length 3
        0xaa, 0xbb, 0xcc, 0xdd, // mask
        'a',  'b',  'c', // masked payload (drained, not decoded)
        0x82, 0x01, 'Z',
    };
    var reader: Io.Reader = .fixed(&wire);
    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &writer };
    const io = std.Io.Threaded.global_single_threaded.io();

    var out: [8]u8 = undefined;
    try std.testing.expectError(error.PayloadTooLarge, readBinaryFrame(conn, io, &out));
    const n = try readBinaryFrame(conn, io, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 'Z'), out[0]);
}

/// Stands in for the socket writer beneath the TLS writer, recording `flush`.
const FlushSpy = struct {
    interface: Io.Writer = .{ .buffer = &.{}, .vtable = &vtable },
    flushes: usize = 0,

    const vtable: Io.Writer.VTable = .{ .drain = drain, .flush = flush };

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        _ = splat;
        w.end = 0;
        var n: usize = 0;
        for (data) |d| n += d.len;
        return n;
    }

    fn flush(w: *Io.Writer) Io.Writer.Error!void {
        const spy: *FlushSpy = @alignCast(@fieldParentPtr("interface", w));
        spy.flushes += 1;
    }
};

test "writeBinaryFrame flushes through to the socket writer" {
    // Regression: Zig's TLS writer only encrypts into the socket writer's buffer,
    // so without the socket flush the frame never leaves the process.
    var spy: FlushSpy = .{};
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    const io = std.Io.Threaded.global_single_threaded.io();

    const conn: Conn = .{ .reader = undefined, .tls = &writer, .socket = &spy.interface };
    try writeBinaryFrame(conn, io, "hi");

    try std.testing.expectEqual(@as(usize, 1), spy.flushes);
}

test "performUpgrade flushes through to the socket writer before reading" {
    var spy: FlushSpy = .{};
    var buf: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    var reader: Io.Reader = .fixed("");
    const io = std.Io.Threaded.global_single_threaded.io();

    // Empty response: the read fails, but only after the request was pushed out.
    const conn: Conn = .{ .reader = &reader, .tls = &writer, .socket = &spy.interface };
    try std.testing.expectError(
        error.UnexpectedEndOfStream,
        performUpgrade(conn, io, "/", "example.com"),
    );

    try std.testing.expectEqual(@as(usize, 1), spy.flushes);
}
