const std = @import("std");
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const Io = std.Io;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_ietf_poly1305,

    pub fn fromName(name: []const u8) ?Method {
        if (std.mem.eql(u8, name, "aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, name, "aes-256-gcm")) return .aes_256_gcm;
        if (std.mem.eql(u8, name, "chacha20-ietf-poly1305")) return .chacha20_ietf_poly1305;
        return null;
    }

    pub fn keyLen(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_ietf_poly1305 => 32,
        };
    }

    pub fn saltLen(self: Method) usize {
        return self.keyLen();
    }
};

/// OpenSSL EVP_BytesToKey with MD5, count=1.
pub fn evpBytesToKey(password: []const u8, key_len: usize, out: []u8) void {
    std.debug.assert(out.len >= key_len);
    var produced: usize = 0;
    var prev: [16]u8 = undefined;
    var prev_len: usize = 0;
    while (produced < key_len) {
        var hasher = std.crypto.hash.Md5.init(.{});
        if (prev_len > 0) hasher.update(prev[0..prev_len]);
        hasher.update(password);
        hasher.final(&prev);
        prev_len = 16;
        const take = @min(16, key_len - produced);
        @memcpy(out[produced..][0..take], prev[0..take]);
        produced += take;
    }
}

fn hkdfSha1(master_key: []const u8, salt: []const u8, out_key: []u8) void {
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.HmacSha1);
    const prk = Hkdf.extract(salt, master_key);
    Hkdf.expand(out_key, "ss-subkey", prk);
}

const AeadCtx = struct {
    method: Method,
    key: [32]u8,
    nonce: [12]u8 = [_]u8{0} ** 12,

    /// SIP004 / shadowsocks.org AEAD: increment as unsigned little-endian (byte 0 first).
    /// Matches libsodium `sodium_increment` used by shadowsocks-libev, rust, go, sing-box.
    fn bumpNonce(self: *AeadCtx) void {
        var i: usize = 0;
        while (i < self.nonce.len) : (i += 1) {
            const v = self.nonce[i] +% 1;
            self.nonce[i] = v;
            if (v != 0) break;
        }
    }

    fn seal(self: *AeadCtx, ciphertext: []u8, tag: *[16]u8, plaintext: []const u8) void {
        const ad = &[_]u8{};
        switch (self.method) {
            .aes_128_gcm => {
                var key: [16]u8 = undefined;
                @memcpy(&key, self.key[0..16]);
                Aes128Gcm.encrypt(ciphertext, tag, plaintext, ad, self.nonce, key);
            },
            .aes_256_gcm => {
                var key: [32]u8 = undefined;
                @memcpy(&key, self.key[0..32]);
                Aes256Gcm.encrypt(ciphertext, tag, plaintext, ad, self.nonce, key);
            },
            .chacha20_ietf_poly1305 => {
                var key: [32]u8 = undefined;
                @memcpy(&key, self.key[0..32]);
                ChaCha20Poly1305.encrypt(ciphertext, tag, plaintext, ad, self.nonce, key);
            },
        }
        self.bumpNonce();
    }

    fn open(self: *AeadCtx, plaintext: []u8, ciphertext: []const u8, tag: *const [16]u8) error{AuthenticationFailed}!void {
        const ad = &[_]u8{};
        switch (self.method) {
            .aes_128_gcm => {
                var key: [16]u8 = undefined;
                @memcpy(&key, self.key[0..16]);
                try Aes128Gcm.decrypt(plaintext, ciphertext, tag.*, ad, self.nonce, key);
            },
            .aes_256_gcm => {
                var key: [32]u8 = undefined;
                @memcpy(&key, self.key[0..32]);
                try Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, ad, self.nonce, key);
            },
            .chacha20_ietf_poly1305 => {
                var key: [32]u8 = undefined;
                @memcpy(&key, self.key[0..32]);
                try ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag.*, ad, self.nonce, key);
            },
        }
        self.bumpNonce();
    }
};

/// Shadowsocks AEAD max payload length (SIP004).
const max_chunk_payload: u16 = 0x3FFF;

fn sealChunk(ctx: *AeadCtx, out: []u8, plaintext: []const u8) error{BufferTooSmall}!usize {
    // [len_ct(2)][len_tag(16)][payload_ct][payload_tag(16)]
    const need = 2 + 16 + plaintext.len + 16;
    if (out.len < need) return error.BufferTooSmall;

    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(plaintext.len), .big);

    var len_ct: [2]u8 = undefined;
    var len_tag: [16]u8 = undefined;
    ctx.seal(&len_ct, &len_tag, &len_be);

    var payload_ct: [512]u8 = undefined;
    if (plaintext.len > payload_ct.len) return error.BufferTooSmall;
    var payload_tag: [16]u8 = undefined;
    ctx.seal(payload_ct[0..plaintext.len], &payload_tag, plaintext);

    var off: usize = 0;
    @memcpy(out[off..][0..2], &len_ct);
    off += 2;
    @memcpy(out[off..][0..16], &len_tag);
    off += 16;
    @memcpy(out[off..][0..plaintext.len], payload_ct[0..plaintext.len]);
    off += plaintext.len;
    @memcpy(out[off..][0..16], &payload_tag);
    off += 16;
    return off;
}

/// Decrypt length header and validate SIP004 payload size against `out_capacity`.
fn openLength(
    ctx: *AeadCtx,
    len_ct: *const [2]u8,
    len_tag: *const [16]u8,
    out_capacity: usize,
) error{ AuthenticationFailed, InvalidSsChunk, BufferTooSmall }!usize {
    var len_be: [2]u8 = undefined;
    try ctx.open(&len_be, len_ct, len_tag);
    const payload_len = std.mem.readInt(u16, &len_be, .big);
    if (payload_len == 0 or payload_len > max_chunk_payload) return error.InvalidSsChunk;
    if (payload_len > out_capacity) return error.BufferTooSmall;
    return payload_len;
}

/// Decrypt one AEAD chunk from `in` into `out`. Returns plaintext length.
fn openChunk(ctx: *AeadCtx, in: []const u8, out: []u8) error{ AuthenticationFailed, InvalidSsChunk, BufferTooSmall }!usize {
    if (in.len < 2 + 16) return error.InvalidSsChunk;

    const payload_len = try openLength(ctx, in[0..2][0..2], in[2..18][0..16], out.len);

    const need = 2 + 16 + payload_len + 16;
    if (in.len < need) return error.InvalidSsChunk;

    const payload_ct = in[18 .. 18 + payload_len];
    const payload_tag = in[18 + payload_len ..][0..16];
    try ctx.open(out[0..payload_len], payload_ct, payload_tag);
    return payload_len;
}

/// Read and decrypt one AEAD chunk from the stream (matches Trojan: first tunneled bytes).
fn readOpenChunk(gpa: std.mem.Allocator, ctx: *AeadCtx, reader: *Io.Reader, out: []u8) !usize {
    var len_ct: [2]u8 = undefined;
    var len_tag: [16]u8 = undefined;
    try reader.readSliceAll(&len_ct);
    try reader.readSliceAll(&len_tag);

    const payload_len = try openLength(ctx, &len_ct, &len_tag, out.len);

    const payload_ct = try gpa.alloc(u8, payload_len);
    defer gpa.free(payload_ct);
    var payload_tag: [16]u8 = undefined;
    try reader.readSliceAll(payload_ct);
    try reader.readSliceAll(&payload_tag);
    try ctx.open(out[0..payload_len], payload_ct, &payload_tag);
    return payload_len;
}

/// Probe SS AEAD: dial, warmup HTTP, then time a second request (steady-state).
pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    method_name: []const u8,
    password: []const u8,
    timeout_secs: u32,
) !u64 {
    const method = Method.fromName(method_name) orelse return error.UnsupportedSsMethod;

    var master: [32]u8 = undefined;
    @memset(&master, 0);
    evpBytesToKey(password, method.keyLen(), master[0..method.keyLen()]);

    const start = netutil.monoNow(io);
    const stream = try netutil.connectHostPort(io, host, port, timeout_secs);
    defer stream.close(io);

    const deadline = netutil.deadlineNs(io, timeout_secs);

    var wbuf: [2048]u8 = undefined;
    var rbuf: [2048]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var r = stream.reader(io, &rbuf);

    var salt: [32]u8 = undefined;
    io.random(salt[0..method.saltLen()]);

    var subkey: [32]u8 = undefined;
    @memset(&subkey, 0);
    hkdfSha1(master[0..method.keyLen()], salt[0..method.saltLen()], subkey[0..method.keyLen()]);

    var ctx: AeadCtx = .{
        .method = method,
        .key = subkey,
    };

    var addr_buf: [64]u8 = undefined;
    const addr_len = try util.writeSocksAddrDomain(&addr_buf, util.probe_domain, util.probe_http_port);

    var packet: [1024]u8 = undefined;
    var off: usize = 0;
    @memcpy(packet[off..][0..method.saltLen()], salt[0..method.saltLen()]);
    off += method.saltLen();
    off += try sealChunk(&ctx, packet[off..], addr_buf[0..addr_len]);
    // Server only emits its salt once it has remote payload; push an HTTP request.
    off += try sealChunk(&ctx, packet[off..], util.probe_http);

    const first_start = netutil.monoNow(io);
    try w.interface.writeAll(packet[0..off]);
    try w.interface.flush();

    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(stream.socket.handle, remain, &done, &fired);
    defer guard.disarm();

    netutil.waitReadableUntil(stream, io, deadline) catch |err| return netutil.classifyDeadlineErr(err, fired.load(.acquire));
    var server_salt: [32]u8 = undefined;
    r.interface.readSliceAll(server_salt[0..method.saltLen()]) catch |err| return netutil.classifyDeadlineErr(err, fired.load(.acquire));

    var server_subkey: [32]u8 = undefined;
    @memset(&server_subkey, 0);
    hkdfSha1(master[0..method.keyLen()], server_salt[0..method.saltLen()], server_subkey[0..method.keyLen()]);
    var server_ctx: AeadCtx = .{
        .method = method,
        .key = server_subkey,
    };

    const chunk_buf = try gpa.alloc(u8, max_chunk_payload);
    defer gpa.free(chunk_buf);
    const http_buf = try gpa.alloc(u8, max_chunk_payload);
    defer gpa.free(http_buf);
    var http_len: usize = 0;

    // Warmup: drain first HTTP response so the second request is clean.
    while (util.httpResponseTotalLen(http_buf[0..http_len]) == null) {
        const n = readOpenChunk(gpa, &server_ctx, &r.interface, chunk_buf) catch |err| return netutil.classifyDeadlineErr(err, fired.load(.acquire));
        if (http_len + n > http_buf.len) return error.BufferTooSmall;
        @memcpy(http_buf[http_len..][0..n], chunk_buf[0..n]);
        http_len += n;
    }
    const first_ms = netutil.elapsedMs(first_start, io);

    const steady_start = netutil.monoNow(io);
    var second: [512]u8 = undefined;
    const second_len = try sealChunk(&ctx, &second, util.probe_http);
    w.interface.writeAll(second[0..second_len]) catch |err| {
        const e = netutil.classifyDeadlineErr(err, fired.load(.acquire));
        return if (util.isPeerClosed(e)) first_ms else e;
    };
    w.interface.flush() catch |err| {
        const e = netutil.classifyDeadlineErr(err, fired.load(.acquire));
        return if (util.isPeerClosed(e)) first_ms else e;
    };
    _ = readOpenChunk(gpa, &server_ctx, &r.interface, chunk_buf) catch |err| {
        const e = netutil.classifyDeadlineErr(err, fired.load(.acquire));
        return if (util.isPeerClosed(e)) first_ms else e;
    };

    return netutil.elapsedMs(steady_start, io);
}

test "evpBytesToKey chacha length" {
    var key: [32]u8 = undefined;
    evpBytesToKey("test-password", 32, &key);
    // Non-zero key material
    try std.testing.expect(key[0] != 0 or key[31] != 0);
}

test "aead seal/open chunk roundtrip" {
    var seal_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = [_]u8{0x11} ** 32,
    };
    const plain = "HTTP/1.1 200";
    var sealed: [128]u8 = undefined;
    const n = try sealChunk(&seal_ctx, &sealed, plain);

    var open_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = [_]u8{0x11} ** 32,
    };
    var out: [64]u8 = undefined;
    const got = try openChunk(&open_ctx, sealed[0..n], &out);
    try std.testing.expectEqualStrings(plain, out[0..got]);
}

test "bumpNonce is little-endian per SIP004" {
    var ctx: AeadCtx = .{
        .method = .aes_128_gcm,
        .key = [_]u8{0} ** 32,
    };
    ctx.bumpNonce();
    try std.testing.expectEqual(@as(u8, 1), ctx.nonce[0]);
    try std.testing.expectEqual(@as(u8, 0), ctx.nonce[11]);
    ctx.nonce[0] = 0xff;
    ctx.bumpNonce();
    try std.testing.expectEqual(@as(u8, 0), ctx.nonce[0]);
    try std.testing.expectEqual(@as(u8, 1), ctx.nonce[1]);
}

test "aead open rejects bad tag" {
    var seal_ctx: AeadCtx = .{
        .method = .aes_128_gcm,
        .key = [_]u8{0x22} ** 32,
    };
    const plain = "ok";
    var sealed: [64]u8 = undefined;
    const n = try sealChunk(&seal_ctx, &sealed, plain);
    sealed[n - 1] ^= 0xff;

    var open_ctx: AeadCtx = .{
        .method = .aes_128_gcm,
        .key = [_]u8{0x22} ** 32,
    };
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, openChunk(&open_ctx, sealed[0..n], &out));
}

test "method from name" {
    try std.testing.expect(Method.fromName("chacha20-ietf-poly1305") == .chacha20_ietf_poly1305);
}
