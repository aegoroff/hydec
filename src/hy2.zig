const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("quicz");
const ca_bundle = @import("ca_bundle.zig");
const netutil = @import("netutil.zig");
const proxy_uri = @import("proxy_uri.zig");
const util = @import("util.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const MAX_PEERS = 32;
const MAX_MESSAGE_LEN = 2048;
const MAX_PADDING_LEN = 4096;
const alpn = [_][]const u8{"h3"};

const Options = struct {
    auth: []const u8,
    server_name: []const u8,
    insecure: bool,
    pin: ?[Sha256.digest_length]u8,

    fn parse(arena: std.mem.Allocator, proxy: proxy_uri.Proxy) !Options {
        var params = std.mem.splitScalar(u8, proxy.query, '&');
        while (params.next()) |pair| {
            const eq = std.mem.findScalar(u8, pair, '=') orelse continue;
            if (eq + 1 == pair.len) continue;
            const name = pair[0..eq];
            if (std.mem.eql(u8, name, "obfs") or std.mem.eql(u8, name, "obfs-password"))
                return error.UnsupportedObfs;
            if (std.mem.eql(u8, name, "ech")) return error.UnsupportedHysteriaEch;
        }
        const name = try proxy.getParamDecoded(arena, "sni") orelse "";
        const raw_pin = try proxy.getParamDecoded(arena, "pinSHA256");
        return .{
            .auth = proxy.userinfo,
            .server_name = if (name.len == 0) proxy.host else name,
            .insecure = util.queryParamTruthy(proxy.query, "insecure"),
            .pin = if (raw_pin) |pin| try parsePin(pin) else null,
        };
    }
};

fn parsePin(input: []const u8) ![Sha256.digest_length]u8 {
    var hex: [Sha256.digest_length * 2]u8 = undefined;
    var len: usize = 0;
    for (input) |byte| {
        if (byte == ':') continue;
        if (len == hex.len) return error.InvalidHysteriaPin;
        hex[len] = byte;
        len += 1;
    }
    if (len != hex.len) return error.InvalidHysteriaPin;
    var pin: [Sha256.digest_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&pin, &hex) catch return error.InvalidHysteriaPin;
    return pin;
}

pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    proxy: proxy_uri.Proxy,
    target: util.Target,
    timeout_secs: u32,
    bind_spec: ?[]const u8,
    addresses: ?[]Io.net.IpAddress,
    stage: *util.Stage,
    dialed: ?*Io.net.IpAddress,
) !u64 {
    stage.* = .setup;
    const deadline = netutil.deadlineNs(io, timeout_secs);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const opts = try Options.parse(arena.allocator(), proxy);
    const roots = if (opts.insecure) null else try ca_bundle.ensureCaBundle(gpa, io);

    stage.* = .connect;
    var storage: [MAX_PEERS]Io.net.IpAddress = undefined;
    const known: []Io.net.IpAddress = addresses orelse &.{};
    const peers = if (known.len != 0) known else try destinations(io, proxy, deadline, &storage);
    var last_err: anyerror = error.ConnectTimeout;
    for (peers, 0..) |peer, index| {
        const now = netutil.monoNow(io);
        if (now >= deadline) return error.ConnectTimeout;
        const connect_budget = @divTrunc(deadline - now, @as(i128, @intCast(peers.len - index)));
        stage.* = .connect;
        const ms = (switch (peer) {
            .ip4 => probePeer(quicz.runtime.client.Client, gpa, io, peer, opts, roots, target, bind_spec, connect_budget, deadline, stage),
            .ip6 => probePeer(quicz.runtime.client.ClientForTupleWithDatagramLimit(quicz.endpoint.Udp6Tuple, 1350), gpa, io, peer, opts, roots, target, bind_spec, connect_budget, deadline, stage),
        }) catch |err| switch (err) {
            error.ConnectTimeout,
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.HostUnreachable,
            error.AddressFamilyUnsupported,
            error.AddressNotAvailable,
            error.AddressUnavailable,
            error.HysteriaSourceFamilyMismatch,
            => {
                if (stage.* != .connect) return err;
                last_err = err;
                continue;
            },
            error.VolumeRefused => {
                if (dialed) |slot| slot.* = peer;
                return err;
            },
            else => return err,
        };
        if (dialed) |slot| slot.* = peer;
        if (index != 0) std.mem.swap(Io.net.IpAddress, &peers[0], &peers[index]);
        return ms;
    }
    return last_err;
}

fn destinations(io: Io, proxy: proxy_uri.Proxy, deadline: i128, storage: *[MAX_PEERS]Io.net.IpAddress) ![]Io.net.IpAddress {
    if (Io.net.IpAddress.parse(proxy.host, proxy.port)) |ip| {
        storage[0] = ip;
        return storage[0..1];
    } else |_| {}
    return netutil.resolveAllUntil(io, proxy.host, proxy.port, deadline, storage);
}

fn bindSocket(io: Io, peer: Io.net.IpAddress, bind_spec: ?[]const u8) !Io.net.Socket {
    var local: Io.net.IpAddress = switch (peer) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    var device: ?[]const u8 = null;
    if (builtin.target.os.tag != .windows) {
        if (bind_spec) |spec| {
            if (Io.net.IpAddress.parse(spec, 0)) |source| {
                if (std.meta.activeTag(source) != std.meta.activeTag(peer)) return error.HysteriaSourceFamilyMismatch;
                local = source;
            } else |_| {
                device = spec;
            }
        }
    }
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    errdefer socket.close(io);
    if (builtin.target.os.tag != .windows) try netutil.applyBind(socket.handle, device);
    return socket;
}

fn probePeer(
    comptime Client: type,
    gpa: std.mem.Allocator,
    io: Io,
    peer: Io.net.IpAddress,
    opts: Options,
    roots: ?*const std.crypto.Certificate.Bundle,
    target: util.Target,
    bind_spec: ?[]const u8,
    connect_budget: i128,
    deadline: i128,
    stage: *util.Stage,
) !u64 {
    const start = netutil.monoNow(io);
    var config: Client.Config = .{
        .server_port = peer.getPort(),
        .server_name = opts.server_name,
        .alpn = &alpn,
        .ca_bundle = roots,
        .insecure_skip_verify = opts.insecure,
    };
    if (Client == quicz.runtime.client.Client) {
        config.server_host = peer.ip4.bytes;
    } else {
        config.server_host = peer.ip6.bytes;
        config.server_scope_id = peer.ip6.interface.index;
    }
    const client = try gpa.create(Client);
    defer gpa.destroy(client);
    const socket = try bindSocket(io, peer, bind_spec);
    client.* = Client.initWithSocket(gpa, io, socket, config) catch |err| {
        socket.close(io);
        return err;
    };
    defer client.deinit();

    const connect_left = @min(start + connect_budget, deadline) - netutil.monoNow(io);
    if (connect_left <= 0) return error.ConnectTimeout;
    const timeout_ms: u32 = @intCast(@min(@divCeil(connect_left, std.time.ns_per_ms), std.math.maxInt(u32)));
    client.connectWithTimeout(timeout_ms) catch |err| switch (err) {
        error.ConnectionTimedOut => return error.ConnectTimeout,
        else => return err,
    };
    stage.* = .handshake;
    const hs = &client.client.transport.backend.hs;
    if (!std.mem.eql(u8, hs.negotiated_alpn[0..hs.negotiated_alpn_len], alpn[0])) return error.HysteriaAlpnMismatch;
    if (opts.pin) |pin| {
        if (hs.server_cert_len == 0) return error.HysteriaPinMismatch;
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(hs.server_cert[0..hs.server_cert_len], &digest, .{});
        if (!std.mem.eql(u8, &pin, &digest)) return error.HysteriaPinMismatch;
    }

    if (netutil.monoNow(io) >= deadline) return error.Timeout;
    const until: Io.Clock.Timestamp = .{ .raw = .fromNanoseconds(@intCast(deadline)), .clock = .awake };
    const Result = union(enum) { exchange: anyerror!u64, timeout: Io.Cancelable!void };
    var results: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    defer select.cancelDiscard();
    const Worker = struct {
        fn run(alloc: std.mem.Allocator, worker_io: Io, conn: *Client, auth: []const u8, test_target: util.Target, progress: *util.Stage, started: i128) anyerror!u64 {
            return exchange(alloc, worker_io, conn, auth, test_target, progress, started);
        }
    };
    try select.concurrent(.exchange, Worker.run, .{ gpa, io, client, opts.auth, target, stage, start });
    try select.concurrent(.timeout, Io.Clock.Timestamp.wait, .{ until, io });
    return switch (try select.await()) {
        .exchange => |result| result,
        .timeout => |result| blk: {
            try result;
            break :blk error.Timeout;
        },
    };
}

fn exchange(
    gpa: std.mem.Allocator,
    io: Io,
    client: anytype,
    auth: []const u8,
    target: util.Target,
    stage: *util.Stage,
    start: i128,
) !u64 {
    const H3 = quicz.runtime.h3_client.ClientFor(@TypeOf(client.*));
    const http = try gpa.create(H3);
    defer gpa.destroy(http);
    http.* = H3.init(gpa, client, 0, 0);
    defer http.deinit();
    try http.run();
    const auth_id = try http.sendRequest(.{
        .method = "POST",
        .authority = "hysteria",
        .path = "/auth",
        .extra_headers = &.{
            .{ .name = "hysteria-auth", .value = auth },
            .{ .name = "hysteria-cc-rx", .value = "0" },
        },
    });
    const response = try http.receiveResponse(auth_id);
    if (response.status != 233) return error.HysteriaAuthRejected;

    stage.* = .tunnel;
    const stream = try client.openStream();
    var address_storage: [256]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_storage, "{s}:{d}", .{ target.domain, util.PROBE_HTTP_PORT });
    var request_storage: [272]u8 = undefined;
    const request = try writeTcpRequest(&request_storage, address);
    try client.sendOnStream(stream, request, false);
    try readTcpResponse(client, stream);

    stage.* = .reply;
    const http_buf = try gpa.alloc(u8, util.PROBE_HTTP_BUF_LEN);
    defer gpa.free(http_buf);
    var len: usize = 0;
    try client.sendOnStream(stream, target.warmup, false);
    try readHttp(client, stream, http_buf, &len, .{ .trace = util.PROBE_UA_WARMUP });
    try client.sendOnStream(stream, target.steady, false);
    try readHttp(client, stream, http_buf, &len, target.steady_reply);
    return netutil.elapsedMs(start, io);
}

fn writeTcpRequest(buf: []u8, address: []const u8) ![]const u8 {
    var writer = Io.Writer.fixed(buf);
    try quicz.packet.encodeVarInt(&writer, 0x401);
    try quicz.packet.encodeVarInt(&writer, address.len);
    try writer.writeAll(address);
    try quicz.packet.encodeVarInt(&writer, 0);
    return writer.buffered();
}

fn readExact(client: anytype, stream: u64, bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try client.receive(stream, bytes[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn readFieldLen(client: anytype, stream: u64, limit: usize) !usize {
    var bytes: [8]u8 = undefined;
    try readExact(client, stream, bytes[0..1]);
    const width = @as(usize, 1) << @as(u2, @truncate(bytes[0] >> 6));
    try readExact(client, stream, bytes[1..width]);
    var len: u64 = bytes[0] & 63;
    for (bytes[1..width]) |byte| len = (len << 8) | byte;
    if (len > limit) return error.InvalidHysteriaResponse;
    return @intCast(len);
}

fn readTcpResponse(client: anytype, stream: u64) !void {
    var buf: [MAX_PADDING_LEN]u8 = undefined;
    try readExact(client, stream, buf[0..1]);
    switch (buf[0]) {
        0 => {},
        1 => return error.HysteriaTunnelRejected,
        else => return error.InvalidHysteriaResponse,
    }
    const msg_len = try readFieldLen(client, stream, MAX_MESSAGE_LEN);
    try readExact(client, stream, buf[0..msg_len]);
    const padding_len = try readFieldLen(client, stream, MAX_PADDING_LEN);
    try readExact(client, stream, buf[0..padding_len]);
}

fn readHttp(client: anytype, stream: u64, buf: []u8, len: *usize, expect: util.ProbeReply) !void {
    while (!try util.takeProbeResponse(buf, len, expect, false)) {
        if (len.* == buf.len) return error.ProbeResponseMismatch;
        const n = try client.receive(stream, buf[len.*..]);
        if (n == 0) {
            if (try util.takeProbeResponse(buf, len, expect, true)) return;
            return error.EndOfStream;
        }
        len.* += n;
    }
}

test "Hysteria URI options decode the SNI and enforce a SHA-256 fingerprint" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const pin = "0123456789abcdef" ++ "0123456789abcdef" ++ "0123456789abcdef" ++ "0123456789abcdef";
    var proxy = try proxy_uri.parse(gpa, "hy2://user%3Apass@127.0.0.1?sni=test%2Eexample&insecure=1&pinSHA256=" ++ pin);
    defer proxy.deinit(gpa);

    const opts = try Options.parse(gpa, proxy);

    try std.testing.expectEqualStrings("user:pass", opts.auth);
    try std.testing.expectEqualStrings("test.example", opts.server_name);
    try std.testing.expect(opts.insecure);
    try std.testing.expectEqual(@as(u8, 0x01), opts.pin.?[0]);
    try std.testing.expectError(error.InvalidHysteriaPin, parsePin("01:23"));
}

test "Hysteria URI rejects obfuscation and ECH before dialing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const proxy = try proxy_uri.parse(gpa, "hy2://auth@127.0.0.1?obfs=&obfs=salamander");
    var ech_proxy = proxy;
    ech_proxy.query = "ech=encoded";

    try std.testing.expectError(error.UnsupportedObfs, Options.parse(gpa, proxy));
    try std.testing.expectError(error.UnsupportedHysteriaEch, Options.parse(gpa, ech_proxy));
}

test "TCPRequest encodes the Hysteria frame type and a multi-byte length" {
    const address = @as([68]u8, @splat('a')) ++ ":80";
    var buf: [256]u8 = undefined;

    const packet = try writeTcpRequest(&buf, address);

    try std.testing.expectEqualSlices(u8, "\x44\x01\x40\x47" ++ address ++ "\x00", packet);
}

test "TCPResponse consumes segmented fields without consuming tunneled bytes" {
    const Peer = struct {
        bytes: []const u8,
        fn receive(self: *@This(), _: u64, out: []u8) !usize {
            if (self.bytes.len == 0) return 0;
            out[0] = self.bytes[0];
            self.bytes = self.bytes[1..];
            return 1;
        }
    };
    var ok: Peer = .{ .bytes = "\x00\x02ok\x03abcHTTP" };
    var rejected: Peer = .{ .bytes = "\x01" };
    var oversized: Peer = .{ .bytes = "\x00\x48\x01" };

    try readTcpResponse(&ok, 4);

    try std.testing.expectEqualStrings("HTTP", ok.bytes);
    try std.testing.expectError(error.HysteriaTunnelRejected, readTcpResponse(&rejected, 4));
    try std.testing.expectError(error.InvalidHysteriaResponse, readTcpResponse(&oversized, 4));
}
