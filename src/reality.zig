const std = @import("std");
const tls = std.crypto.tls;
const util = @import("util.zig");
const netutil = @import("netutil.zig");
const vless = @import("vless.zig");
const grpc_gun = @import("grpc_gun.zig");
const Io = std.Io;

const X25519 = std.crypto.dh.X25519;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.Hkdf(HmacSha256);

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const named_group_x25519: u16 = 0x001d;

fn putU16(buf: []u8, v: u16) void {
    std.mem.writeInt(u16, buf[0..2], v, .big);
}

fn putU24(buf: []u8, v: u24) void {
    buf[0] = @intCast((v >> 16) & 0xff);
    buf[1] = @intCast((v >> 8) & 0xff);
    buf[2] = @intCast(v & 0xff);
}

fn readU16(buf: []const u8) u16 {
    return std.mem.readInt(u16, buf[0..2], .big);
}

fn readU24(buf: []const u8) u24 {
    return (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2];
}

/// Post-handshake TLS 1.3 messages (typ 22). NewSessionTicket is ignorable;
/// KeyUpdate would require traffic-secret rotation we do not keep — fail closed.
fn rejectPostHandshakeKeyUpdate(plaintext: []const u8) !void {
    var off: usize = 0;
    while (off + 4 <= plaintext.len) {
        const ht = plaintext[off];
        const hl = readU24(plaintext[off + 1 ..][0..3]);
        if (off + 4 + hl > plaintext.len) break;
        if (ht == 24) return error.TlsKeyUpdateUnsupported;
        off += 4 + hl;
    }
}

pub fn decodePublicKey(pbk_b64: []const u8, out: *[32]u8) !void {
    // sing-box uses RawURLEncoding (no padding)
    var cleaned: [64]u8 = undefined;
    const normalized = util.normalizeBase64Url(&cleaned, pbk_b64, false) catch return error.InvalidPublicKey;
    var tmp: [48]u8 = undefined;
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(normalized) catch return error.InvalidPublicKey;
    if (decoded_len != 32) return error.InvalidPublicKey;
    std.base64.standard.Decoder.decode(tmp[0..32], normalized) catch return error.InvalidPublicKey;
    @memcpy(out, tmp[0..32]);
}

pub fn decodeShortId(sid_hex: []const u8, out: *[8]u8) !void {
    @memset(out, 0);
    if (sid_hex.len == 0) return;
    if (sid_hex.len > 16 or sid_hex.len % 2 != 0) return error.InvalidShortId;
    var bytes: [8]u8 = undefined;
    const blen = sid_hex.len / 2;
    _ = try std.fmt.hexToBytes(bytes[0..blen], sid_hex);
    @memcpy(out[0..blen], bytes[0..blen]);
}

/// Derive REALITY auth key and encrypt session_id in-place (32 bytes).
/// AAD is the ClientHello with the 32-byte session_id field zeroed (xray/sing-box).
pub fn sealSessionId(
    session_id: *[32]u8,
    hello_raw: []u8,
    client_random: *const [32]u8,
    our_priv: *const [32]u8,
    server_pub: *const [32]u8,
) !void {
    var auth_key = try X25519.scalarmult(our_priv.*, server_pub.*);

    // Go hkdf.New(hash, secret=authKey, salt=random[:20], info="REALITY")
    const prk = HkdfSha256.extract(client_random[0..20], &auth_key);
    var new_key: [32]u8 = undefined;
    HkdfSha256.expand(&new_key, "REALITY", prk);
    auth_key = new_key;

    // AAD must contain zeros at the session_id slot (raw[39..71]), matching
    // xray/sing-box: copy zeros into Raw, Seal(plaintext), then copy ciphertext.
    if (hello_raw.len < 39 + 32) return error.BufferTooSmall;
    var plaintext: [16]u8 = undefined;
    @memcpy(&plaintext, session_id[0..16]);
    @memset(hello_raw[39..][0..32], 0);

    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, client_random[20..32]);

    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    var sealed: [32]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(sealed[0..16], &tag, &plaintext, hello_raw, nonce, auth_key);
    @memcpy(sealed[16..32], &tag);
    @memcpy(session_id, &sealed);
    @memcpy(hello_raw[39..][0..32], session_id);
}

/// Xray core version embedded in the REALITY session_id (bytes 0..2).
/// xray-core ≥26.7.11 defaults inbound `minClientVer` to 26.3.27 when unset; reporting
/// the old sing-box 1.8.1 triple fails auth and the peer falls through to the dest
/// (often visible here as `TlsAlert` after we write VLESS).
const reality_client_ver: [3]u8 = .{ 26, 7, 11 };

fn fillSessionIdPlain(session_id: *[32]u8, short_id: *const [8]u8, unix_secs: u32) void {
    @memset(session_id, 0);
    session_id[0] = reality_client_ver[0];
    session_id[1] = reality_client_ver[1];
    session_id[2] = reality_client_ver[2];
    session_id[3] = 0; // reserved
    std.mem.writeInt(u32, session_id[4..8], unix_secs, .big);
    @memcpy(session_id[8..16], short_id);
}

const TlsRecord = struct { typ: u8, len: usize };

const RecordConn = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    // application traffic
    client_key: [16]u8 = undefined,
    server_key: [16]u8 = undefined,
    client_iv: [12]u8 = undefined,
    server_iv: [12]u8 = undefined,
    // handshake traffic
    hs_client_key: [16]u8 = undefined,
    hs_server_key: [16]u8 = undefined,
    hs_client_iv: [12]u8 = undefined,
    hs_server_iv: [12]u8 = undefined,
    read_seq: u64 = 0,
    write_seq: u64 = 0,
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    app_phase: bool = false,

    fn xorNonce(iv: *const [12]u8, seq: u64) [12]u8 {
        var nonce: [12]u8 = iv.*;
        var s = seq;
        var i: usize = 11;
        while (true) : (i -= 1) {
            nonce[i] ^= @truncate(s);
            s >>= 8;
            if (i == 0) break;
        }
        return nonce;
    }

    fn writeRecord(self: *RecordConn, content_type: u8, plaintext: []const u8, handshake_keys: bool) !void {
        // Inner plaintext: content || content_type || zeros padding (none)
        var inner: [16384 + 1]u8 = undefined;
        if (plaintext.len + 1 > inner.len) return error.RecordTooLarge;
        @memcpy(inner[0..plaintext.len], plaintext);
        inner[plaintext.len] = content_type;
        const inner_len = plaintext.len + 1;

        var ciphertext: [16384 + 1 + 16]u8 = undefined;
        var tag: [16]u8 = undefined;

        const key = if (handshake_keys) self.hs_client_key else self.client_key;
        const iv = if (handshake_keys) self.hs_client_iv else self.client_iv;
        const seq = if (handshake_keys) self.hs_write_seq else self.write_seq;
        const nonce = xorNonce(&iv, seq);

        // AAD = TLSCiphertext header: type=23, version=0x0303, length=inner_len+16
        var aad: [5]u8 = .{ 23, 0x03, 0x03, 0, 0 };
        putU16(aad[3..5], @intCast(inner_len + 16));
        Aes128Gcm.encrypt(ciphertext[0..inner_len], &tag, inner[0..inner_len], &aad, nonce, key);
        @memcpy(ciphertext[inner_len..][0..16], &tag);

        var hdr: [5]u8 = .{ 23, 0x03, 0x03, 0, 0 };
        putU16(hdr[3..5], @intCast(inner_len + 16));
        try self.writer.writeAll(&hdr);
        try self.writer.writeAll(ciphertext[0 .. inner_len + 16]);
        try self.writer.flush();

        if (handshake_keys) self.hs_write_seq += 1 else self.write_seq += 1;
    }

    fn writeClear(self: *RecordConn, content_type: u8, data: []const u8) !void {
        var hdr: [5]u8 = .{ content_type, 0x03, 0x01, 0, 0 };
        putU16(hdr[3..5], @intCast(data.len));
        try self.writer.writeAll(&hdr);
        try self.writer.writeAll(data);
        try self.writer.flush();
    }

    /// TLS peers send at most one CCS; bound skips so a flood cannot recurse/stack-DoS.
    const max_ccs_skip: usize = 8;

    fn readRecord(self: *RecordConn, out: []u8, handshake_keys: bool) !TlsRecord {
        var ccs_skipped: usize = 0;
        while (true) {
            var hdr: [5]u8 = undefined;
            try self.reader.readSliceAll(&hdr);
            const content_type = hdr[0];
            const length = readU16(hdr[3..5]);
            if (length > 16640) return error.TlsRecordOverflow;

            var payload: [16640]u8 = undefined;
            try self.reader.readSliceAll(payload[0..length]);

            if (content_type == 20) {
                ccs_skipped += 1;
                if (ccs_skipped > max_ccs_skip) return error.TlsUnexpectedMessage;
                continue;
            }
            if (content_type == 23) {
                // decrypt
                if (length < 16) return error.TlsBadLength;
                const ct_len = length - 16;
                const key = if (handshake_keys) self.hs_server_key else self.server_key;
                const iv = if (handshake_keys) self.hs_server_iv else self.server_iv;
                const seq = if (handshake_keys) self.hs_read_seq else self.read_seq;
                const nonce = xorNonce(&iv, seq);
                var aad: [5]u8 = .{ 23, 0x03, 0x03, 0, 0 };
                putU16(aad[3..5], length);
                var plain: [16640]u8 = undefined;
                var tag: [16]u8 = undefined;
                @memcpy(&tag, payload[ct_len..][0..16]);
                try Aes128Gcm.decrypt(plain[0..ct_len], payload[0..ct_len], tag, &aad, nonce, key);
                if (handshake_keys) self.hs_read_seq += 1 else self.read_seq += 1;

                // strip trailing content type and padding zeros
                var end = ct_len;
                while (end > 0 and plain[end - 1] == 0) end -= 1;
                if (end == 0) return error.TlsDecodeError;
                const inner_type = plain[end - 1];
                const msg_len = end - 1;
                if (msg_len > out.len) return error.BufferTooSmall;
                @memcpy(out[0..msg_len], plain[0..msg_len]);
                return .{ .typ = inner_type, .len = msg_len };
            }
            if (content_type == 21) return error.TlsAlert;
            if (length > out.len) return error.BufferTooSmall;
            @memcpy(out[0..length], payload[0..length]);
            return .{ .typ = content_type, .len = length };
        }
    }
};

fn hkdfExpandLabel(comptime len: usize, secret: *const [32]u8, label: []const u8, context: []const u8) [len]u8 {
    return tls.hkdfExpandLabel(HkdfSha256, secret.*, label, context, len);
}

fn deriveAppKeys(conn: *RecordConn, master: *const [32]u8, handshake_hash: *const [32]u8) void {
    const client_app = hkdfExpandLabel(32, master, "c ap traffic", handshake_hash);
    const server_app = hkdfExpandLabel(32, master, "s ap traffic", handshake_hash);
    conn.client_key = hkdfExpandLabel(16, &client_app, "key", &.{});
    conn.server_key = hkdfExpandLabel(16, &server_app, "key", &.{});
    conn.client_iv = hkdfExpandLabel(12, &client_app, "iv", &.{});
    conn.server_iv = hkdfExpandLabel(12, &server_app, "iv", &.{});
    conn.read_seq = 0;
    conn.write_seq = 0;
    conn.app_phase = true;
}

/// Extract the peer X25519 key_share from a ServerHello body (no handshake header).
fn parseServerHelloX25519(sh_body: []const u8) ![32]u8 {
    if (sh_body.len < 2 + 32 + 1) return error.TlsDecodeError;
    // Detect Hello Retry Request (unsupported in v1)
    if (std.mem.eql(u8, sh_body[2..34], &tls.hello_retry_request_sequence)) {
        return error.HelloRetryRequestUnsupported;
    }
    var pos: usize = 2 + 32; // version + random
    const sid_echo_len = sh_body[pos];
    pos += 1 + sid_echo_len;
    if (pos + 3 > sh_body.len) return error.TlsDecodeError;
    const suite = readU16(sh_body[pos..][0..2]);
    pos += 2;
    pos += 1; // compression
    if (suite != TLS_AES_128_GCM_SHA256) return error.UnsupportedCipherSuite;

    if (pos + 2 > sh_body.len) return error.TlsDecodeError;
    const ext_len = readU16(sh_body[pos..][0..2]);
    pos += 2;
    if (pos + ext_len > sh_body.len) return error.TlsDecodeError;
    const ext_end = pos + ext_len;

    var server_x25519: ?[32]u8 = null;
    while (pos + 4 <= ext_end) {
        const et = readU16(sh_body[pos..][0..2]);
        const el = readU16(sh_body[pos + 2 ..][0..2]);
        pos += 4;
        if (pos + el > ext_end) return error.TlsDecodeError;
        if (et == 51 and el >= 4 + 32) { // key_share
            const group = readU16(sh_body[pos..][0..2]);
            const klen = readU16(sh_body[pos + 2 ..][0..2]);
            if (group == named_group_x25519 and klen == 32) {
                var pubk: [32]u8 = undefined;
                @memcpy(&pubk, sh_body[pos + 4 ..][0..32]);
                server_x25519 = pubk;
            }
        }
        pos += el;
    }
    return server_x25519 orelse error.MissingKeyShare;
}

fn buildClientHello(
    out: []u8,
    sni: []const u8,
    client_random: *const [32]u8,
    session_id: *const [32]u8,
    x25519_pub: *const [32]u8,
) !usize {
    var body: [2048]u8 = undefined;
    var i: usize = 0;

    putU16(body[i..][0..2], 0x0303);
    i += 2;
    @memcpy(body[i..][0..32], client_random);
    i += 32;
    body[i] = 32;
    i += 1;
    @memcpy(body[i..][0..32], session_id);
    i += 32;

    // TLS_AES_128_GCM_SHA256 only (keeps record AEAD key length at 16)
    putU16(body[i..][0..2], 2);
    i += 2;
    putU16(body[i..][0..2], TLS_AES_128_GCM_SHA256);
    i += 2;

    body[i] = 1;
    i += 1;
    body[i] = 0;
    i += 1;

    const ext_len_at = i;
    i += 2;
    const ext_start = i;

    // supported_versions: TLS 1.3 only
    putU16(body[i..][0..2], 43);
    i += 2;
    putU16(body[i..][0..2], 3);
    i += 2;
    body[i] = 2;
    i += 1;
    putU16(body[i..][0..2], 0x0304);
    i += 2;

    // psk_key_exchange_modes: psk_dhe_ke
    putU16(body[i..][0..2], 45);
    i += 2;
    putU16(body[i..][0..2], 2);
    i += 2;
    body[i] = 1;
    i += 1;
    body[i] = 1;
    i += 1;

    // supported_groups: x25519
    putU16(body[i..][0..2], 10);
    i += 2;
    putU16(body[i..][0..2], 4);
    i += 2;
    putU16(body[i..][0..2], 2);
    i += 2;
    putU16(body[i..][0..2], named_group_x25519);
    i += 2;

    // key_share: x25519
    putU16(body[i..][0..2], 51);
    i += 2;
    putU16(body[i..][0..2], 38);
    i += 2;
    putU16(body[i..][0..2], 36);
    i += 2;
    putU16(body[i..][0..2], named_group_x25519);
    i += 2;
    putU16(body[i..][0..2], 32);
    i += 2;
    @memcpy(body[i..][0..32], x25519_pub);
    i += 32;

    // signature_algorithms
    putU16(body[i..][0..2], 13);
    i += 2;
    putU16(body[i..][0..2], 12);
    i += 2;
    putU16(body[i..][0..2], 10);
    i += 2;
    inline for (.{ 0x0403, 0x0804, 0x0805, 0x0806, 0x0807 }) |scheme| {
        putU16(body[i..][0..2], scheme);
        i += 2;
    }

    if (sni.len > 0) {
        // RFC 6066 host_name is length-prefixed with a u8 / u16; keep within DNS max and body.
        if (sni.len > 255) return error.SniTooLong;
        const sni_need = 2 + 2 + 2 + 1 + 2 + sni.len;
        if (i + sni_need > body.len) return error.BufferTooSmall;
        putU16(body[i..][0..2], 0);
        i += 2;
        putU16(body[i..][0..2], @intCast(2 + 1 + 2 + sni.len));
        i += 2;
        putU16(body[i..][0..2], @intCast(1 + 2 + sni.len));
        i += 2;
        body[i] = 0;
        i += 1;
        putU16(body[i..][0..2], @intCast(sni.len));
        i += 2;
        @memcpy(body[i..][0..sni.len], sni);
        i += sni.len;
    }

    // Always advertise ALPN like chrome so TCP and gRPC ClientHellos match.
    {
        const p1 = "h2";
        const p2 = "http/1.1";
        const list_len: usize = (1 + p1.len) + (1 + p2.len);
        putU16(body[i..][0..2], 16);
        i += 2;
        putU16(body[i..][0..2], @intCast(2 + list_len));
        i += 2;
        putU16(body[i..][0..2], @intCast(list_len));
        i += 2;
        body[i] = @intCast(p1.len);
        i += 1;
        @memcpy(body[i..][0..p1.len], p1);
        i += p1.len;
        body[i] = @intCast(p2.len);
        i += 1;
        @memcpy(body[i..][0..p2.len], p2);
        i += p2.len;
    }

    putU16(body[ext_len_at..][0..2], @intCast(i - ext_start));

    const hs_len = i;
    if (out.len < 4 + hs_len) return error.BufferTooSmall;
    out[0] = 1;
    putU24(out[1..4], @intCast(hs_len));
    @memcpy(out[4..][0..hs_len], body[0..hs_len]);
    return 4 + hs_len;
}

pub const RealityConn = struct {
    stream: Io.net.Stream,
    io: Io,
    sock_rbuf: [tls.Client.min_buffer_len]u8 = undefined,
    sock_wbuf: [tls.Client.min_buffer_len]u8 = undefined,
    stream_reader: Io.net.Stream.Reader = undefined,
    stream_writer: Io.net.Stream.Writer = undefined,
    conn: RecordConn = undefined,
    transcript: Sha256 = undefined,
    open: bool = false,
    /// Absolute awake-clock deadline for subsequent reads; null = no limit.
    read_deadline_ns: ?i128 = null,
    deadline_done: std.atomic.Value(bool) = .init(false),
    deadline_fired: std.atomic.Value(bool) = .init(false),
    deadline_guard: ?netutil.DeadlineShutdown = null,

    fn deadlineFired(self: *const RealityConn) bool {
        return self.deadline_fired.load(.acquire);
    }

    pub fn deinit(self: *RealityConn) void {
        if (self.deadline_guard) |*g| {
            g.disarm();
            self.deadline_guard = null;
        }
        if (self.open) {
            self.stream.close(self.io);
            self.open = false;
        }
    }

    pub fn writeApp(self: *RealityConn, data: []const u8) !void {
        self.conn.writeRecord(23, data, false) catch |err| return netutil.classifyDeadlineErr(err, self.deadlineFired());
    }

    fn writeClear(self: *RealityConn, content_type: u8, data: []const u8) !void {
        self.conn.writeClear(content_type, data) catch |err| return netutil.classifyDeadlineErr(err, self.deadlineFired());
    }

    fn writeHandshake(self: *RealityConn, data: []const u8) !void {
        self.conn.writeRecord(22, data, true) catch |err| return netutil.classifyDeadlineErr(err, self.deadlineFired());
    }

    fn waitForReadable(self: *RealityConn) !void {
        // Only poll when Io.Reader has no buffered bytes; otherwise poll
        // falsely times out while TLS records sit in sock_rbuf.
        const r = self.conn.reader;
        if (r.seek >= r.end) {
            netutil.waitReadableUntil(self.stream, self.io, self.read_deadline_ns) catch |err|
                return netutil.classifyDeadlineErr(err, self.deadlineFired());
        }
    }

    fn readRecordDeadline(self: *RealityConn, out: []u8, handshake_keys: bool) !TlsRecord {
        try self.waitForReadable();
        return self.conn.readRecord(out, handshake_keys) catch |err| return netutil.classifyDeadlineErr(err, self.deadlineFired());
    }

    pub fn readApp(self: *RealityConn, out: []u8) !usize {
        var scratch: [16640]u8 = undefined;
        var attempts: usize = 0;
        while (attempts < 16) : (attempts += 1) {
            const dest = if (out.len >= scratch.len) out else scratch[0..];
            const rec = try self.readRecordDeadline(dest, false);
            switch (rec.typ) {
                23 => {
                    if (rec.len > out.len) return error.BufferTooSmall;
                    if (dest.ptr != out.ptr) @memcpy(out[0..rec.len], dest[0..rec.len]);
                    return rec.len;
                },
                22 => {
                    try rejectPostHandshakeKeyUpdate(dest[0..rec.len]);
                    continue; // NewSessionTicket etc.
                },
                20 => continue,
                21 => return error.TlsAlert,
                else => return error.TlsUnexpectedMessage,
            }
        }
        return error.TlsUnexpectedMessage;
    }
};

/// Handshake into caller-owned `rc`. Out-parameter is required: RealityConn is
/// self-referential (sock buffers, DeadlineShutdown atomics) and must not move
/// after arming — returning by value would rely on RLO alone.
pub fn connect(
    rc: *RealityConn,
    io: Io,
    host: []const u8,
    port: u16,
    sni: []const u8,
    pbk_b64: []const u8,
    sid_hex: []const u8,
    timeout_secs: u32,
) !void {
    var server_pub: [32]u8 = undefined;
    try decodePublicKey(pbk_b64, &server_pub);
    var short_id: [8]u8 = undefined;
    try decodeShortId(sid_hex, &short_id);

    var seed: [32]u8 = undefined;
    io.random(&seed);
    const kp = try X25519.KeyPair.generateDeterministic(seed);

    var client_random: [32]u8 = undefined;
    io.random(&client_random);

    const now = Io.Clock.real.now(io);
    const unix_secs: u32 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));

    var session_id: [32]u8 = undefined;
    fillSessionIdPlain(&session_id, &short_id, unix_secs);

    var hello_raw: [2048]u8 = undefined;
    const hello_len = try buildClientHello(&hello_raw, sni, &client_random, &session_id, &kp.public_key);

    // Seal session id (AAD = hello_raw)
    try sealSessionId(&session_id, hello_raw[0..hello_len], &client_random, &kp.secret_key, &server_pub);

    // Rebuild hello with sealed session id already patched by sealSessionId into hello_raw[39..]
    // sealSessionId already updated hello_raw session id bytes.

    const dial_start = netutil.monoNow(io);
    rc.* = .{
        .stream = try netutil.connectHostPort(io, host, port, timeout_secs),
        .io = io,
        .open = true,
        .read_deadline_ns = netutil.deadlineNs(io, timeout_secs),
    };
    errdefer rc.deinit();

    const remain = netutil.remainingTimeoutNs(dial_start, io, timeout_secs);
    if (remain == 0) return error.Timeout;
    rc.deadline_guard = try netutil.DeadlineShutdown.arm(rc.stream.socket.handle, remain, &rc.deadline_done, &rc.deadline_fired);

    rc.stream_reader = rc.stream.reader(io, &rc.sock_rbuf);
    rc.stream_writer = rc.stream.writer(io, &rc.sock_wbuf);
    rc.conn = .{
        .reader = &rc.stream_reader.interface,
        .writer = &rc.stream_writer.interface,
    };
    rc.transcript = Sha256.init(.{});
    rc.transcript.update(hello_raw[0..hello_len]);

    // Send ClientHello record
    try rc.writeClear(22, hello_raw[0..hello_len]);

    // Read ServerHello (cleartext); buffer sized for max TLS record
    var sh_buf: [16640]u8 = undefined;
    const sh_rec = try rc.readRecordDeadline(&sh_buf, false);
    if (sh_rec.typ != 22) return error.TlsUnexpectedMessage;
    rc.transcript.update(sh_buf[0..sh_rec.len]);

    // Parse ServerHello for key_share
    if (sh_rec.len < 4) return error.TlsDecodeError;
    if (sh_buf[0] != 2) return error.TlsUnexpectedMessage;
    const sh_body_len = readU24(sh_buf[1..4]);
    if (4 + sh_body_len > sh_rec.len) return error.TlsDecodeError;
    const sh_body = sh_buf[4 .. 4 + sh_body_len];
    const server_share = try parseServerHelloX25519(sh_body);
    const shared = try X25519.scalarmult(kp.secret_key, server_share);

    // Snapshot transcript for hello_hash; keep rc.transcript for later HS messages.
    var hello_hash: [32]u8 = undefined;
    {
        var hello_hasher = rc.transcript;
        hello_hasher.final(&hello_hash);
    }

    var client_fin_key: [32]u8 = undefined;
    var server_fin_key: [32]u8 = undefined;
    var master: [32]u8 = undefined;

    {
        const zeroes = [_]u8{0} ** 32;
        const early = HkdfSha256.extract(&[_]u8{0}, &zeroes);
        const empty_hash = tls.emptyHash(Sha256);
        const derived = hkdfExpandLabel(32, &early, "derived", &empty_hash);
        const hs_secret = HkdfSha256.extract(&derived, &shared);
        const client_hs = hkdfExpandLabel(32, &hs_secret, "c hs traffic", &hello_hash);
        const server_hs = hkdfExpandLabel(32, &hs_secret, "s hs traffic", &hello_hash);
        client_fin_key = hkdfExpandLabel(32, &client_hs, "finished", "");
        server_fin_key = hkdfExpandLabel(32, &server_hs, "finished", "");
        rc.conn.hs_client_key = hkdfExpandLabel(16, &client_hs, "key", "");
        rc.conn.hs_server_key = hkdfExpandLabel(16, &server_hs, "key", "");
        rc.conn.hs_client_iv = hkdfExpandLabel(12, &client_hs, "iv", "");
        rc.conn.hs_server_iv = hkdfExpandLabel(12, &server_hs, "iv", "");
        const derived2 = hkdfExpandLabel(32, &hs_secret, "derived", &empty_hash);
        master = HkdfSha256.extract(&derived2, &zeroes);
    }

    // Read encrypted handshake messages until Server Finished (reassemble across TLS records).
    // Transcript is updated per handshake message so Finished verify_data can be checked
    // against Hash(messages before Finished).
    var saw_finished = false;
    var hs_pending: [32768]u8 = undefined;
    var hs_pending_len: usize = 0;
    while (!saw_finished) {
        var buf: [16384]u8 = undefined;
        const rec = rc.readRecordDeadline(&buf, true) catch |err| switch (err) {
            error.AuthenticationFailed => return error.TlsHandshakeDecryptFailed,
            else => |e| return e,
        };
        if (rec.typ == 21) return error.TlsAlert;
        if (rec.typ != 22) continue;
        if (hs_pending_len + rec.len > hs_pending.len) return error.BufferTooSmall;
        @memcpy(hs_pending[hs_pending_len..][0..rec.len], buf[0..rec.len]);
        hs_pending_len += rec.len;

        var off: usize = 0;
        while (off + 4 <= hs_pending_len) {
            const ht = hs_pending[off];
            const hl = readU24(hs_pending[off + 1 ..][0..3]);
            // Bound claimed length so a hostile/corrupt peer cannot fill the pending buffer forever.
            if (hl > 16384) return error.TlsDecodeError;
            if (off + 4 + hl > hs_pending_len) break;
            const msg = hs_pending[off .. off + 4 + hl];
            if (ht == 20) {
                if (hl != 32) return error.TlsDecodeError;
                var pre_fin_hash: [32]u8 = undefined;
                {
                    var tc = rc.transcript;
                    tc.final(&pre_fin_hash);
                }
                const expected = tls.hmac(HmacSha256, &pre_fin_hash, server_fin_key);
                if (!std.mem.eql(u8, msg[4..], &expected)) return error.TlsFinishedVerifyFailed;
                rc.transcript.update(msg);
                saw_finished = true;
            } else {
                rc.transcript.update(msg);
            }
            off += 4 + hl;
        }
        if (off > 0) {
            const hs_remain = hs_pending_len - off;
            if (hs_remain > 0) std.mem.copyForwards(u8, hs_pending[0..hs_remain], hs_pending[off..][0..hs_remain]);
            hs_pending_len = hs_remain;
        }
    }

    // Client Finished + app secrets from transcript through Server Finished (not Client Finished)
    var hs_hash: [32]u8 = undefined;
    {
        var tc = rc.transcript;
        tc.final(&hs_hash);
    }
    const finished_verify = tls.hmac(HmacSha256, &hs_hash, client_fin_key);
    var fin_msg: [4 + 32]u8 = undefined;
    fin_msg[0] = 20;
    putU24(fin_msg[1..4], 32);
    @memcpy(fin_msg[4..], &finished_verify);
    try rc.writeHandshake(&fin_msg);

    deriveAppKeys(&rc.conn, &master, &hs_hash);
}

/// Append tunnel bytes into `buf`, stripping the VLESS response header once it is complete.
/// Handles `NeedMore` by leaving partial header bytes in `buf` until the next chunk arrives.
fn appendStripVlessHeader(buf: []u8, len: *usize, chunk: []const u8, stripped: *bool) !void {
    if (len.* + chunk.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[len.*..][0..chunk.len], chunk);
    len.* += chunk.len;
    if (stripped.*) return;
    const hdr = vless.responseHeaderLen(buf[0..len.*]) catch |err| switch (err) {
        error.NeedMore => return,
        else => |e| return e,
    };
    const body_len = len.* - hdr;
    if (body_len > 0) std.mem.copyForwards(u8, buf[0..body_len], buf[hdr..len.*]);
    len.* = body_len;
    stripped.* = true;
}

/// Probe VLESS over REALITY (TCP or gRPC gun).
/// Warmup HTTP proves the tunnel; returned latency is the second (steady-state) request.
pub fn probeVless(
    io: Io,
    host: []const u8,
    port: u16,
    uuid: []const u8,
    sni: []const u8,
    pbk: []const u8,
    sid: []const u8,
    flow: []const u8,
    grpc: bool,
    service_name: []const u8,
    authority_param: []const u8,
    timeout_secs: u32,
) !u64 {
    const sni_use = if (sni.len > 0) sni else host;

    var rc: RealityConn = undefined;
    try connect(&rc, io, host, port, sni_use, pbk, sid, timeout_secs);
    defer rc.deinit();

    var vless_buf: [512]u8 = undefined;
    const vless_len = try vless.encodeProbeRequest(&vless_buf, uuid, if (grpc) "" else flow);

    if (grpc) {
        var auth_buf: [256]u8 = undefined;
        const authority = try grpc_gun.formatAuthority(&auth_buf, sni_use, port, authority_param);

        // Match sing-box: preface+SETTINGS, then after peer SETTINGS: ACK + HEADERS + DATA (no END_STREAM).
        var preface: [64]u8 = undefined;
        const plen = try grpc_gun.buildClientPrefaceSettings(&preface);
        try rc.writeApp(preface[0..plen]);

        var app_buf: [16384]u8 = undefined;
        var gather: [32768]u8 = undefined;
        var gather_len: usize = 0;
        var settings_seen = false;
        var request_sent = false;
        var saw_headers_ok = false;
        var stripped_vless = false;
        var warmup_done = false;
        var steady_start: ?i128 = null;
        var first_start: ?i128 = null;
        var first_ms: ?u64 = null;
        var http_buf: [16384]u8 = undefined;
        var http_len: usize = 0;
        while (true) {
            const n = rc.readApp(app_buf[0..]) catch |err| {
                if (warmup_done and first_ms != null and util.isPeerClosed(err)) return first_ms.?;
                return err;
            };
            if (gather_len + n > gather.len) return error.BufferTooSmall;
            @memcpy(gather[gather_len..][0..n], app_buf[0..n]);
            gather_len += n;

            var off: usize = 0;
            while (off + 9 <= gather_len) {
                const frame_len: usize = (@as(usize, gather[off]) << 16) | (@as(usize, gather[off + 1]) << 8) | gather[off + 2];
                const ftyp = gather[off + 3];
                const fflags = gather[off + 4];
                if (off + 9 + frame_len > gather_len) break;

                const payload = gather[off + 9 .. off + 9 + frame_len];

                if (ftyp == 0x04 and (fflags & 0x01) == 0 and !settings_seen) {
                    settings_seen = true;
                    var flight: [1536]u8 = undefined;
                    var fl: usize = 0;
                    fl += try grpc_gun.buildSettingsAck(flight[fl..]);
                    // Open the flow-control window generously (some peers start at 0).
                    fl += try grpc_gun.buildWindowUpdate(flight[fl..], 0, 1 << 20);
                    fl += try grpc_gun.buildWindowUpdate(flight[fl..], 1, 1 << 20);
                    fl += try grpc_gun.buildGunHeaders(flight[fl..], service_name, authority);
                    var hunk: [640]u8 = undefined;
                    const hunk_len = try grpc_gun.wrapHunk(&hunk, vless_buf[0..vless_len]);
                    var grpc_msg: [704]u8 = undefined;
                    const glen = try grpc_gun.wrapGrpc(&grpc_msg, hunk[0..hunk_len]);
                    // Keep the stream open — gun-lite is bidirectional; END_STREAM yields empty 200s.
                    fl += try grpc_gun.buildDataFrame(flight[fl..], 1, grpc_msg[0..glen], false);
                    first_start = netutil.monoNow(io);
                    try rc.writeApp(flight[0..fl]);
                    request_sent = true;
                } else if (ftyp == 0x06 and (fflags & 0x01) == 0 and frame_len == 8) {
                    var pong: [17]u8 = undefined;
                    const pong_len = try grpc_gun.buildPingAck(&pong, payload[0..8]);
                    try rc.writeApp(pong[0..pong_len]);
                } else if (ftyp == 0x01 and request_sent) {
                    if (grpc_gun.headersIndicateStatus200(payload, fflags)) {
                        saw_headers_ok = true;
                    }
                    if ((fflags & 0x01) != 0 and !saw_headers_ok) return error.GrpcStreamEnded;
                    // END_STREAM on headers with 200 but no DATA: still failure for protocol probe
                    if ((fflags & 0x01) != 0 and saw_headers_ok) return error.GrpcEmptyResponse;
                } else if (ftyp == 0x00 and frame_len >= 5 and request_sent) {
                    const msg = try grpc_gun.vlessFromGrpcData(payload);
                    if (!warmup_done) {
                        // Accumulate into http_buf and strip VLESS header in-place (NeedMore-safe).
                        try appendStripVlessHeader(&http_buf, &http_len, msg, &stripped_vless);
                        if (util.httpResponseTotalLen(http_buf[0..http_len]) != null) {
                            warmup_done = true;
                            first_ms = netutil.elapsedMs(first_start.?, io);
                            var hunk: [256]u8 = undefined;
                            const hunk_len = try grpc_gun.wrapHunk(&hunk, util.probe_http);
                            var grpc_msg: [320]u8 = undefined;
                            const glen = try grpc_gun.wrapGrpc(&grpc_msg, hunk[0..hunk_len]);
                            var data_frame: [384]u8 = undefined;
                            const dlen = try grpc_gun.buildDataFrame(&data_frame, 1, grpc_msg[0..glen], false);
                            rc.writeApp(data_frame[0..dlen]) catch |err| {
                                if (util.isPeerClosed(err)) return first_ms.?;
                                return err;
                            };
                            steady_start = netutil.monoNow(io);
                        }
                    } else if (msg.len > 0) {
                        return netutil.elapsedMs(steady_start.?, io);
                    }
                } else if (ftyp == 0x03) {
                    if (frame_len >= 4) {
                        const code = std.mem.readInt(u32, payload[0..4], .big);
                        std.log.warn("gRPC RST_STREAM error_code={d}", .{code});
                    }
                    if (first_ms) |ms| return ms;
                    return error.GrpcRstStream;
                } else if (ftyp == 0x07) {
                    if (first_ms) |ms| return ms;
                    return error.GrpcGoAway;
                }

                off += 9 + frame_len;
            }
            if (off > 0) {
                const remain = gather_len - off;
                if (remain > 0) std.mem.copyForwards(u8, gather[0..remain], gather[off..][0..remain]);
                gather_len = remain;
            }
        }
    } else {
        const use_vision = std.mem.indexOf(u8, flow, "vision") != null;
        const first_start = netutil.monoNow(io);
        try rc.writeApp(vless_buf[0..vless_len]);
        var uuid_bytes: [16]u8 = undefined;
        try vless.parseUuid(uuid, &uuid_bytes);

        // Server writes the VLESS response header raw, then Vision-wraps the payload
        // (or sends raw if no vision). Header and first Vision frame often share one
        // TLS record — unwrap Vision only after stripping the header.
        var stream: [16384]u8 = undefined;
        var stream_len: usize = 0;
        var http_buf: [16384]u8 = undefined;
        var http_len: usize = 0;
        var stripped_header = false;
        var vision_raw = !use_vision;
        var vision_state: vless.VisionUnpadState = .{};
        var resp: [16384]u8 = undefined;

        while (util.httpResponseTotalLen(http_buf[0..http_len]) == null) {
            const n = rc.readApp(&resp) catch |err| {
                if (util.httpHeadersComplete(http_buf[0..http_len]) and util.isPeerClosed(err)) break;
                return err;
            };
            if (stream_len + n > stream.len) return error.BufferTooSmall;
            @memcpy(stream[stream_len..][0..n], resp[0..n]);
            stream_len += n;

            try drainVlessVisionStream(
                &stream,
                &stream_len,
                &http_buf,
                &http_len,
                &uuid_bytes,
                &stripped_header,
                &vision_raw,
                &vision_state,
            );
        }
        const first_ms = netutil.elapsedMs(first_start, io);

        // Second request is raw: client already sent Vision PaddingEnd on the first write.
        // Downlink may still be mid-Vision (Continue / NeedMore) — drain until we get
        // application bytes, same as SS/Trojan needing any non-empty second read.
        const steady_start = netutil.monoNow(io);
        rc.writeApp(util.probe_http) catch |err| {
            return if (util.isPeerClosed(err)) first_ms else err;
        };
        const http_before = http_len;
        while (http_len == http_before) {
            const n = rc.readApp(&resp) catch |err| {
                return if (util.isPeerClosed(err)) first_ms else err;
            };
            if (n == 0) return first_ms;
            if (stream_len + n > stream.len) return error.BufferTooSmall;
            @memcpy(stream[stream_len..][0..n], resp[0..n]);
            stream_len += n;
            try drainVlessVisionStream(
                &stream,
                &stream_len,
                &http_buf,
                &http_len,
                &uuid_bytes,
                &stripped_header,
                &vision_raw,
                &vision_state,
            );
        }
        return netutil.elapsedMs(steady_start, io);
    }
}

/// Move bytes from `stream` into `http` after stripping the VLESS response header
/// and (when still in Vision mode) decoding Vision frames.
fn drainVlessVisionStream(
    stream: []u8,
    stream_len: *usize,
    http: []u8,
    http_len: *usize,
    uuid: *const [16]u8,
    stripped: *bool,
    vision_raw: *bool,
    vision_state: *vless.VisionUnpadState,
) !void {
    if (!stripped.*) {
        const hdr = vless.responseHeaderLen(stream[0..stream_len.*]) catch |err| switch (err) {
            error.NeedMore => return,
            else => |e| return e,
        };
        shiftDown(stream, stream_len, hdr);
        stripped.* = true;
    }

    while (stream_len.* > 0) {
        if (!vision_raw.*) {
            const frame = vless.consumeVisionFrame(stream[0..stream_len.*], uuid, vision_state) catch |err| switch (err) {
                error.NeedMore => return,
                error.NotVision => {
                    // Peer already switched to raw (or never wrapped this chunk).
                    vision_raw.* = true;
                    continue;
                },
            };
            if (frame.content.len > 0) {
                if (http_len.* + frame.content.len > http.len) return error.BufferTooSmall;
                @memcpy(http[http_len.*..][0..frame.content.len], frame.content);
                http_len.* += frame.content.len;
            }
            shiftDown(stream, stream_len, frame.consumed);
            if (frame.switch_to_raw) vision_raw.* = true;
        } else {
            if (http_len.* + stream_len.* > http.len) return error.BufferTooSmall;
            @memcpy(http[http_len.*..][0..stream_len.*], stream[0..stream_len.*]);
            http_len.* += stream_len.*;
            stream_len.* = 0;
        }
    }
}

fn shiftDown(buf: []u8, len: *usize, n: usize) void {
    const remain = len.* - n;
    if (remain > 0) std.mem.copyForwards(u8, buf[0..remain], buf[n..len.*]);
    len.* = remain;
}

fn appendServerHelloMinimal(buf: []u8, key_share: *const [32]u8, ext_len_override: ?u16) !usize {
    var i: usize = 0;
    putU16(buf[i..][0..2], 0x0303);
    i += 2;
    @memset(buf[i..][0..32], 0xaa);
    i += 32;
    buf[i] = 0; // empty session id
    i += 1;
    putU16(buf[i..][0..2], TLS_AES_128_GCM_SHA256);
    i += 2;
    buf[i] = 0; // compression
    i += 1;

    const ext_payload_len: u16 = 4 + 4 + 32; // type+len + group+klen+key
    const ext_len = ext_len_override orelse ext_payload_len;
    putU16(buf[i..][0..2], ext_len);
    i += 2;
    putU16(buf[i..][0..2], 51); // key_share
    i += 2;
    putU16(buf[i..][0..2], 4 + 32);
    i += 2;
    putU16(buf[i..][0..2], named_group_x25519);
    i += 2;
    putU16(buf[i..][0..2], 32);
    i += 2;
    @memcpy(buf[i..][0..32], key_share);
    i += 32;
    return i;
}

test "appendStripVlessHeader handles NeedMore then body" {
    var buf: [256]u8 = undefined;
    var len: usize = 0;
    var stripped = false;
    // Partial header (ver only)
    try appendStripVlessHeader(&buf, &len, &[_]u8{0}, &stripped);
    try std.testing.expect(!stripped);
    try std.testing.expectEqual(@as(usize, 1), len);
    // Complete empty header + HTTP start in one chunk
    try appendStripVlessHeader(&buf, &len, "\x00HTTP/1.1 200 OK\r\n", &stripped);
    try std.testing.expect(stripped);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\n", buf[0..len]);
}

test "appendStripVlessHeader large first chunk" {
    var buf: [1024]u8 = undefined;
    var len: usize = 0;
    var stripped = false;
    var chunk: [600]u8 = undefined;
    chunk[0] = 0;
    chunk[1] = 0;
    @memset(chunk[2..], 'x');
    try appendStripVlessHeader(&buf, &len, &chunk, &stripped);
    try std.testing.expect(stripped);
    try std.testing.expectEqual(@as(usize, 598), len);
}

test "drainVlessVisionStream strips header before Vision unwrap" {
    var uuid: [16]u8 = [_]u8{0xcd} ** 16;
    const http = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    var vision: [256]u8 = undefined;
    const vn = try vless.appendVisionPaddingEnd(&vision, &uuid, http);

    var stream: [512]u8 = undefined;
    stream[0] = 0;
    stream[1] = 0;
    @memcpy(stream[2..][0..vn], vision[0..vn]);
    var stream_len: usize = 2 + vn;

    var http_buf: [512]u8 = undefined;
    var http_len: usize = 0;
    var stripped = false;
    var vision_raw = false;
    var vision_state: vless.VisionUnpadState = .{};

    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(stripped);
    try std.testing.expect(vision_raw);
    try std.testing.expectEqual(@as(usize, 0), stream_len);
    try std.testing.expectEqualStrings(http, http_buf[0..http_len]);
}

test "drainVlessVisionStream splits header then Vision across pushes" {
    var uuid: [16]u8 = [_]u8{0xef} ** 16;
    const http = "HTTP/1.1 200 OK\r\n\r\n";
    var vision: [256]u8 = undefined;
    const vn = try vless.appendVisionPaddingEnd(&vision, &uuid, http);

    var stream: [512]u8 = undefined;
    var stream_len: usize = 0;
    var http_buf: [512]u8 = undefined;
    var http_len: usize = 0;
    var stripped = false;
    var vision_raw = false;
    var vision_state: vless.VisionUnpadState = .{};

    stream[0] = 0;
    stream_len = 1;
    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(!stripped);

    stream[stream_len] = 0;
    stream_len += 1;
    @memcpy(stream[stream_len..][0..vn], vision[0..vn]);
    stream_len += vn;
    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(stripped);
    try std.testing.expectEqualStrings(http, http_buf[0..http_len]);
}

test "drainVlessVisionStream continues without UUID then End" {
    var uuid: [16]u8 = [_]u8{0x11} ** 16;
    const part1 = "HTTP/1.1 200 OK\r\n";
    const part2 = "Content-Length: 0\r\n\r\n";

    var first: [256]u8 = undefined;
    const n1 = try vless.appendVisionFrame(&first, vless.vision_cmd_continue, &uuid, part1, 8);
    var cont: [256]u8 = undefined;
    const n2 = try vless.appendVisionPaddingContinue(&cont, part2);
    var endf: [64]u8 = undefined;
    const n3 = try vless.appendVisionFrame(&endf, vless.vision_cmd_end, null, "", 8);

    var stream: [1024]u8 = undefined;
    stream[0] = 0;
    stream[1] = 0;
    @memcpy(stream[2..][0..n1], first[0..n1]);
    @memcpy(stream[2 + n1 ..][0..n2], cont[0..n2]);
    @memcpy(stream[2 + n1 + n2 ..][0..n3], endf[0..n3]);
    var stream_len: usize = 2 + n1 + n2 + n3;

    var http_buf: [512]u8 = undefined;
    var http_len: usize = 0;
    var stripped = false;
    var vision_raw = false;
    var vision_state: vless.VisionUnpadState = .{};

    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(stripped);
    try std.testing.expect(vision_raw);
    try std.testing.expect(!vision_state.expect_uuid);
    try std.testing.expectEqualStrings(part1 ++ part2, http_buf[0..http_len]);
}

test "drainVlessVisionStream steady raw after End grows http" {
    var uuid: [16]u8 = [_]u8{0x22} ** 16;
    const http = "HTTP/1.1 200 OK\r\n\r\n";
    var vision: [256]u8 = undefined;
    const vn = try vless.appendVisionPaddingEnd(&vision, &uuid, http);

    var stream: [512]u8 = undefined;
    stream[0] = 0;
    stream[1] = 0;
    @memcpy(stream[2..][0..vn], vision[0..vn]);
    var stream_len: usize = 2 + vn;
    var http_buf: [512]u8 = undefined;
    var http_len: usize = 0;
    var stripped = false;
    var vision_raw = false;
    var vision_state: vless.VisionUnpadState = .{};

    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(vision_raw);
    const before = http_len;

    const more = "HTTP/1.1 200 OK\r\n\r\n";
    @memcpy(stream[0..more.len], more);
    stream_len = more.len;
    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(http_len > before);
    try std.testing.expectEqualStrings(http ++ more, http_buf[0..http_len]);
}

test "drainVlessVisionStream incomplete Vision does not grow http" {
    var uuid: [16]u8 = [_]u8{0x33} ** 16;
    var vision: [256]u8 = undefined;
    const vn = try vless.appendVisionPaddingEnd(&vision, &uuid, "HTTP/1.1 200 OK\r\n\r\n");

    var stream: [512]u8 = undefined;
    stream[0] = 0;
    stream[1] = 0;
    // Only part of the Vision frame — decoder must wait (NeedMore).
    const partial = 2 + 20;
    @memcpy(stream[2..][0 .. partial - 2], vision[0 .. partial - 2]);
    var stream_len: usize = partial;
    var http_buf: [512]u8 = undefined;
    var http_len: usize = 0;
    var stripped = false;
    var vision_raw = false;
    var vision_state: vless.VisionUnpadState = .{};

    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(stripped);
    try std.testing.expect(!vision_raw);
    try std.testing.expectEqual(@as(usize, 0), http_len);
    try std.testing.expect(stream_len > 0);

    // Steady-style: feed the rest; http should grow only once the frame is complete.
    @memcpy(stream[stream_len..][0 .. vn - (partial - 2)], vision[partial - 2 .. vn]);
    stream_len += vn - (partial - 2);
    try drainVlessVisionStream(&stream, &stream_len, &http_buf, &http_len, &uuid, &stripped, &vision_raw, &vision_state);
    try std.testing.expect(http_len > 0);
    try std.testing.expect(vision_raw);
}

test "parseServerHelloX25519 accepts key_share" {
    var body: [128]u8 = undefined;
    const key = [_]u8{0x42} ** 32;
    const n = try appendServerHelloMinimal(&body, &key, null);
    const got = try parseServerHelloX25519(body[0..n]);
    try std.testing.expectEqualSlices(u8, &key, &got);
}

test "parseServerHelloX25519 rejects truncated extensions" {
    var body: [128]u8 = undefined;
    const key = [_]u8{0x42} ** 32;
    const n = try appendServerHelloMinimal(&body, &key, null);
    // Claim a huge extensions length past the real buffer.
    try std.testing.expectError(error.TlsDecodeError, parseServerHelloX25519(body[0 .. n - 1]));
    try std.testing.expectError(error.TlsDecodeError, parseServerHelloX25519(body[0..40]));
}

test "parseServerHelloX25519 rejects ext_len past body" {
    var body: [128]u8 = undefined;
    const key = [_]u8{0x42} ** 32;
    const n = try appendServerHelloMinimal(&body, &key, 0xffff);
    try std.testing.expectError(error.TlsDecodeError, parseServerHelloX25519(body[0..n]));
}

test "clientHello session id at offset 39" {
    var out: [512]u8 = undefined;
    const random = [_]u8{0x11} ** 32;
    const sid = [_]u8{0x22} ** 32;
    const pubk = [_]u8{0x33} ** 32;
    const n = try buildClientHello(&out, "example.com", &random, &sid, &pubk);
    try std.testing.expect(n > 39 + 32);
    try std.testing.expectEqual(@as(u8, 1), out[0]); // client_hello
    try std.testing.expectEqual(@as(u8, 32), out[38]); // session id length
    try std.testing.expectEqualSlices(u8, &sid, out[39..][0..32]);
}

test "buildClientHello rejects oversized SNI" {
    var out: [2048]u8 = undefined;
    const random = [_]u8{0x11} ** 32;
    const sid = [_]u8{0x22} ** 32;
    const pubk = [_]u8{0x33} ** 32;
    const long_sni = "a" ** 256;
    try std.testing.expectError(
        error.SniTooLong,
        buildClientHello(&out, long_sni, &random, &sid, &pubk),
    );
}

test "decodePublicKey length" {
    // 32 zero bytes, base64url (fake key material)
    const pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    var out: [32]u8 = undefined;
    try decodePublicKey(pbk, &out);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &out);
}
