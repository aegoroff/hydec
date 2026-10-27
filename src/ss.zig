const std = @import("std");
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const Io = std.Io;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Method = enum {
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
fn evpBytesToKey(password: []const u8, key_len: usize, out: []u8) void {
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
    nonce: [12]u8 = @splat(0),

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
const MAX_CHUNK_PAYLOAD: u16 = 0x3FFF;

/// Probe response buffer. One maximal chunk of headroom on top of the largest response:
/// `takeResponse` carries pipelined leftovers at the front, and without the headroom
/// that leftover would shrink the destination below one full chunk and turn the next
/// `readOpenChunk` into `error.BufferTooSmall`.
const HTTP_BUF_LEN: usize = util.PROBE_HTTP_BUF_LEN + MAX_CHUNK_PAYLOAD;

fn sealChunk(ctx: *AeadCtx, out: []u8, plaintext: []const u8) error{ BufferTooSmall, InvalidSsChunk }!usize {
    // [len_ct(2)][len_tag(16)][payload_ct][payload_tag(16)]
    if (plaintext.len == 0 or plaintext.len > MAX_CHUNK_PAYLOAD) return error.InvalidSsChunk;
    const need = 2 + 16 + plaintext.len + 16;
    if (out.len < need) return error.BufferTooSmall;

    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(plaintext.len), .big);

    ctx.seal(out[0..2], out[2..][0..16], &len_be);
    ctx.seal(out[18..][0..plaintext.len], out[18 + plaintext.len ..][0..16], plaintext);
    return need;
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
    if (payload_len == 0 or payload_len > MAX_CHUNK_PAYLOAD) return error.InvalidSsChunk;
    if (payload_len > out_capacity) return error.BufferTooSmall;
    return payload_len;
}

/// Read and decrypt one AEAD chunk from the stream (matches Trojan: first tunneled bytes).
/// `scratch` holds ciphertext; plaintext is written to `out`.
fn readOpenChunk(ctx: *AeadCtx, reader: *Io.Reader, out: []u8, scratch: []u8) !usize {
    var len_ct: [2]u8 = undefined;
    var len_tag: [16]u8 = undefined;
    try reader.readSliceAll(&len_ct);
    try reader.readSliceAll(&len_tag);

    const payload_len = try openLength(ctx, &len_ct, &len_tag, @min(out.len, scratch.len));

    var payload_tag: [16]u8 = undefined;
    try reader.readSliceAll(scratch[0..payload_len]);
    try reader.readSliceAll(&payload_tag);
    try ctx.open(out[0..payload_len], scratch[0..payload_len], &payload_tag);
    return payload_len;
}

/// Consume one complete HTTP response from the front of `http_buf`.
///
/// Returns false while the response is still short. On completion the echoed UA is
/// checked against that response only (not the whole buffer, which may already hold
/// the pipelined next one), and any leftover bytes are shifted down to offset 0 so
/// the following call continues from them.
fn takeResponse(http_buf: []u8, http_len: *usize, expect: util.ProbeReply) error{ ProbeResponseMismatch, VolumeRefused }!bool {
    const total = util.httpResponseTotalLen(http_buf[0..http_len.*]) orelse return false;
    try expect.check(http_buf[0..total]);
    const remain = http_len.* - total;
    if (remain > 0) std.mem.copyForwards(u8, http_buf[0..remain], http_buf[total..http_len.*]);
    http_len.* = remain;
    return true;
}

/// Read AEAD chunks until `takeResponse` consumes one response matching `expect`.
fn readProbeResponse(
    server_ctx: *AeadCtx,
    sr: *Io.net.Stream.Reader,
    fired: *const std.atomic.Value(bool),
    http_buf: []u8,
    http_len: *usize,
    chunk_buf: []u8,
    expect: util.ProbeReply,
) !void {
    while (!try takeResponse(http_buf, http_len, expect)) {
        const n = readOpenChunk(server_ctx, &sr.interface, http_buf[http_len.*..], chunk_buf) catch |err| {
            const e = netutil.classifyIoErr(err, null, sr.err, fired.load(.acquire));
            // HTTP/1.0 close-delimited only — truncated CL/chunked must fail.
            if (util.isPeerClosed(e) and util.httpCloseDelimitedReady(http_buf[0..http_len.*])) {
                try expect.check(http_buf[0..http_len.*]);
                http_len.* = 0;
                return;
            }
            return e;
        };
        http_len.* += n;
    }
}

/// Probe SS AEAD: warmup + pipelined steady HTTP to `target`.
pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    method_name: []const u8,
    password: []const u8,
    target: util.Target,
    timeout_secs: u32,
    bind: ?[]const u8,
    stage: *util.Stage,
) !u64 {
    const method = Method.fromName(method_name) orelse return error.UnsupportedSsMethod;

    var master: [32]u8 = undefined;
    @memset(&master, 0);
    evpBytesToKey(password, method.keyLen(), master[0..method.keyLen()]);

    const start = netutil.monoNow(io);
    stage.* = .connect;
    const stream = try netutil.connectHostPort(io, host, port, timeout_secs, bind);
    defer stream.close(io);
    stage.* = .handshake;

    const read_deadline_ns = start + @as(i128, timeout_secs) * std.time.ns_per_s;

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
    const addr_len = try util.writeSocksAddrDomain(&addr_buf, target.domain, util.PROBE_HTTP_PORT);

    var packet: [1024]u8 = undefined;
    var off: usize = 0;
    @memcpy(packet[off..][0..method.saltLen()], salt[0..method.saltLen()]);
    off += method.saltLen();
    off += try sealChunk(&ctx, packet[off..], addr_buf[0..addr_len]);
    // Server only emits its salt once it has remote payload; push an HTTP request.
    off += try sealChunk(&ctx, packet[off..], target.warmup);

    // Arm before the first write: a stuck peer / full window can block forever
    // on a blocking socket if the watchdog is not yet running.
    const remain = netutil.remainingTimeoutNs(start, io, timeout_secs);
    if (remain == 0) return error.Timeout;
    var done = std.atomic.Value(bool).init(false);
    var fired = std.atomic.Value(bool).init(false);
    var guard = try netutil.DeadlineShutdown.arm(io, stream, remain, &done, &fired);
    defer guard.disarm();

    w.interface.writeAll(packet[0..off]) catch |err| return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));
    w.interface.flush() catch |err| return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));

    netutil.waitReadableUntil(stream, io, read_deadline_ns) catch |err| return netutil.classifyDeadlineErr(err, fired.load(.acquire));
    var server_salt: [32]u8 = undefined;
    r.interface.readSliceAll(server_salt[0..method.saltLen()]) catch |err| return netutil.classifyIoErr(err, null, r.err, fired.load(.acquire));
    stage.* = .reply;

    var server_subkey: [32]u8 = undefined;
    @memset(&server_subkey, 0);
    hkdfSha1(master[0..method.keyLen()], server_salt[0..method.saltLen()], server_subkey[0..method.keyLen()]);
    var server_ctx: AeadCtx = .{
        .method = method,
        .key = server_subkey,
    };

    // Pipeline steady before reading warmup: some peers close keep-alive after the
    // first Cloudflare response if the second request is not already in flight.
    var steady_pkt: [512]u8 = undefined;
    const steady_len = try sealChunk(&ctx, &steady_pkt, target.steady);
    w.interface.writeAll(steady_pkt[0..steady_len]) catch |err| return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));
    w.interface.flush() catch |err| return netutil.classifyIoErr(err, w.err, null, fired.load(.acquire));

    const chunk_buf = try gpa.alloc(u8, MAX_CHUNK_PAYLOAD);
    defer gpa.free(chunk_buf);
    const http_buf = try gpa.alloc(u8, HTTP_BUF_LEN);
    defer gpa.free(http_buf);
    var http_len: usize = 0;

    // Warmup response (request was in the initial flight), then the steady response.
    // The steady request is pipelined above, so one AEAD chunk may carry the tail of
    // the warmup response together with the head of the steady one — `takeResponse`
    // keeps that leftover instead of dropping it.
    try readProbeResponse(&server_ctx, &r, &fired, http_buf, &http_len, chunk_buf, .{ .trace = util.PROBE_UA_WARMUP });
    try readProbeResponse(&server_ctx, &r, &fired, http_buf, &http_len, chunk_buf, target.steady_reply);

    // Full attempt: dial, salt exchange and both requests.
    return netutil.elapsedMs(start, io);
}

test "evpBytesToKey matches OpenSSL EVP_BytesToKey(MD5)" {
    // Reference: `openssl enc -aes-{128,256}-cbc -md md5 -nosalt -k password -P`.
    var key16: [16]u8 = undefined;
    evpBytesToKey("password", 16, &key16);
    try std.testing.expectEqualSlices(u8, &.{
        0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82, 0xcf, 0x99,
    }, &key16);

    // 32 bytes needs the second MD5 block, chained over the first.
    var key32: [32]u8 = undefined;
    evpBytesToKey("password", 32, &key32);
    try std.testing.expectEqualSlices(u8, &.{
        0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82, 0xcf, 0x99,
        0x2b, 0x95, 0x99, 0x0a, 0x91, 0x51, 0x37, 0x4a, 0xbd, 0x8f, 0xf8, 0xc5, 0xa7, 0xa0, 0xfe, 0x08,
    }, &key32);
}

test "aead seal/open chunk roundtrip" {
    var seal_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = @splat(0x11),
    };
    const plain = "HTTP/1.1 200";
    var sealed: [128]u8 = undefined;
    const n = try sealChunk(&seal_ctx, &sealed, plain);

    var open_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = @splat(0x11),
    };
    var out: [64]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var in: Io.Reader = .fixed(sealed[0..n]);
    const got = try readOpenChunk(&open_ctx, &in, &out, &scratch);
    try std.testing.expectEqualStrings(plain, out[0..got]);
}

test "aead sealChunk accepts payload larger than 512" {
    var seal_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = @splat(0x33),
    };
    var plain: [600]u8 = undefined;
    @memset(&plain, 0xab);
    var sealed: [2 + 16 + 600 + 16]u8 = undefined;
    const n = try sealChunk(&seal_ctx, &sealed, &plain);

    var open_ctx: AeadCtx = .{
        .method = .chacha20_ietf_poly1305,
        .key = @splat(0x33),
    };
    var out: [600]u8 = undefined;
    var scratch: [600]u8 = undefined;
    var in: Io.Reader = .fixed(sealed[0..n]);
    const got = try readOpenChunk(&open_ctx, &in, &out, &scratch);
    try std.testing.expectEqual(@as(usize, 600), got);
    try std.testing.expectEqualSlices(u8, &plain, out[0..got]);
}

test "bumpNonce is little-endian per SIP004" {
    var ctx: AeadCtx = .{
        .method = .aes_128_gcm,
        .key = @splat(0),
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
        .key = @splat(0x22),
    };
    const plain = "ok";
    var sealed: [64]u8 = undefined;
    const n = try sealChunk(&seal_ctx, &sealed, plain);
    sealed[n - 1] ^= 0xff;

    var open_ctx: AeadCtx = .{
        .method = .aes_128_gcm,
        .key = @splat(0x22),
    };
    var out: [16]u8 = undefined;
    var scratch: [16]u8 = undefined;
    var in: Io.Reader = .fixed(sealed[0..n]);
    try std.testing.expectError(error.AuthenticationFailed, readOpenChunk(&open_ctx, &in, &out, &scratch));
}

test "method from name" {
    try std.testing.expect(Method.fromName("chacha20-ietf-poly1305") == .chacha20_ietf_poly1305);
}

const TEST_WARM_RESP =
    "HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nvisit_scheme=http\nuag=hydec-warmup\n";
const TEST_STEADY_RESP =
    "HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nvisit_scheme=http\nuag=hydec-steady\n";

test "takeResponse keeps bytes of the pipelined next response" {
    var buf: [512]u8 = undefined;
    // One read delivered the whole warmup response plus the head of the steady one.
    const head = TEST_STEADY_RESP[0..20];
    @memcpy(buf[0..TEST_WARM_RESP.len], TEST_WARM_RESP);
    @memcpy(buf[TEST_WARM_RESP.len..][0..head.len], head);
    var len: usize = TEST_WARM_RESP.len + head.len;

    try std.testing.expect(try takeResponse(&buf, &len, .{ .trace = util.PROBE_UA_WARMUP }));
    // Steady head survives at offset 0 instead of being dropped.
    try std.testing.expectEqual(head.len, len);
    try std.testing.expectEqualStrings(head, buf[0..len]);
    try std.testing.expect(!try takeResponse(&buf, &len, .{ .trace = util.PROBE_UA_STEADY }));

    const tail = TEST_STEADY_RESP[20..];
    @memcpy(buf[len..][0..tail.len], tail);
    len += tail.len;
    try std.testing.expect(try takeResponse(&buf, &len, .{ .trace = util.PROBE_UA_STEADY }));
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "takeResponse validates the UA of the response, not of trailing bytes" {
    var buf: [512]u8 = undefined;
    // Steady response first, warmup pipelined behind it: asking for the warmup UA
    // must fail rather than match the buffer tail.
    @memcpy(buf[0..TEST_STEADY_RESP.len], TEST_STEADY_RESP);
    @memcpy(buf[TEST_STEADY_RESP.len..][0..TEST_WARM_RESP.len], TEST_WARM_RESP);
    var len: usize = TEST_STEADY_RESP.len + TEST_WARM_RESP.len;
    try std.testing.expectError(error.ProbeResponseMismatch, takeResponse(&buf, &len, .{ .trace = util.PROBE_UA_WARMUP }));
}

test "one AEAD chunk straddling both responses yields both" {
    const key: [32]u8 = @splat(0x44);
    var seal_ctx: AeadCtx = .{ .method = .chacha20_ietf_poly1305, .key = key };

    // Chunk boundary deliberately falls inside the steady response's *body*, so the
    // trailing fragment alone cannot be mistaken for a complete response.
    const split = 60;
    var first: [256]u8 = undefined;
    @memcpy(first[0..TEST_WARM_RESP.len], TEST_WARM_RESP);
    @memcpy(first[TEST_WARM_RESP.len..][0..split], TEST_STEADY_RESP[0..split]);

    var wire: [1024]u8 = undefined;
    var off: usize = 0;
    off += try sealChunk(&seal_ctx, wire[off..], first[0 .. TEST_WARM_RESP.len + split]);
    off += try sealChunk(&seal_ctx, wire[off..], TEST_STEADY_RESP[split..]);

    var open_ctx: AeadCtx = .{ .method = .chacha20_ietf_poly1305, .key = key };
    var reader: Io.Reader = .fixed(wire[0..off]);
    var http: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var http_len: usize = 0;

    // Mirrors readProbeResponse's loop; only the socket error mapping is left out.
    while (!try takeResponse(&http, &http_len, .{ .trace = util.PROBE_UA_WARMUP })) {
        http_len += try readOpenChunk(&open_ctx, &reader, http[http_len..], &scratch);
    }
    while (!try takeResponse(&http, &http_len, .{ .trace = util.PROBE_UA_STEADY })) {
        http_len += try readOpenChunk(&open_ctx, &reader, http[http_len..], &scratch);
    }
    // Both responses recovered from the two chunks, nothing left over.
    try std.testing.expectEqual(@as(usize, 0), http_len);
}

test "a volume download split into maximal chunks fits HTTP_BUF_LEN" {
    const gpa = std.testing.allocator;
    const key: [32]u8 = @splat(0x55);
    const head = std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{util.VOLUME_BYTES});
    const resp = try gpa.alloc(u8, head.len + util.VOLUME_BYTES);
    defer gpa.free(resp);
    @memcpy(resp[0..head.len], head);
    @memset(resp[head.len..], 'x');

    // Arrange: the server sends the response as full SIP004 chunks.
    var seal_ctx: AeadCtx = .{ .method = .chacha20_ietf_poly1305, .key = key };
    const wire = try gpa.alloc(u8, resp.len + 64 * 18);
    defer gpa.free(wire);
    var off: usize = 0;
    var pos: usize = 0;
    while (pos < resp.len) {
        const end = @min(pos + MAX_CHUNK_PAYLOAD, resp.len);
        off += try sealChunk(&seal_ctx, wire[off..], resp[pos..end]);
        pos = end;
    }

    // Act: the same loop as `readProbeResponse`, with the real buffer sizes.
    var open_ctx: AeadCtx = .{ .method = .chacha20_ietf_poly1305, .key = key };
    var reader: Io.Reader = .fixed(wire[0..off]);
    const http = try gpa.alloc(u8, HTTP_BUF_LEN);
    defer gpa.free(http);
    const scratch = try gpa.alloc(u8, MAX_CHUNK_PAYLOAD);
    defer gpa.free(scratch);
    var http_len: usize = 0;
    while (!try takeResponse(http, &http_len, util.VOLUME_TARGET.steady_reply)) {
        http_len += try readOpenChunk(&open_ctx, &reader, http[http_len..], scratch);
    }

    // Assert
    try std.testing.expectEqual(@as(usize, 0), http_len);
}

test "HTTP_BUF_LEN leaves room for a full chunk behind a carried leftover" {
    // Bound check, not behaviour: `takeResponse` may leave up to `MAX_CHUNK_PAYLOAD`
    // bytes at the front of `http_buf`, and `openLength` rejects a chunk that does not
    // fit in what remains. Shrinking `HTTP_BUF_LEN` back to one chunk reintroduces that.
    try std.testing.expect(HTTP_BUF_LEN - MAX_CHUNK_PAYLOAD >= MAX_CHUNK_PAYLOAD);
}

test "probe reports the stage it failed at" {
    // Arrange: a loopback peer that accepts and hangs up without sending a salt. It only
    // half-closes, then drains until the client leaves: closing with the first flight
    // still unread makes the kernel send RST, and the probe sees a reset instead.
    const io = std.testing.io;
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    const Peer = struct {
        fn run(s: *Io.net.Server) void {
            const io_peer = std.testing.io;
            const conn = s.accept(io_peer) catch return;
            defer conn.close(io_peer);
            conn.shutdown(io_peer, .send) catch return;
            var buf: [256]u8 = undefined;
            var r = conn.reader(io_peer, &buf);
            _ = r.interface.discardRemaining() catch {};
        }
    };
    const peer = try std.Thread.spawn(.{}, Peer.run, .{&server});

    // Act
    var stage: util.Stage = .setup;
    const result = probe(std.testing.allocator, io, "127.0.0.1", port, "aes-128-gcm", "pw", util.LATENCY_TARGET, 2, null, &stage);
    peer.join();

    // Assert: TCP came up, the first flight went unanswered.
    try std.testing.expectError(error.EndOfStream, result);
    try std.testing.expectEqual(util.Stage.handshake, stage);
}
