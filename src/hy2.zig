const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");
const netutil = @import("netutil.zig");

const Io = std.Io;
const posix = std.posix;

const max_peers = 32;
const packet_len = 1200;
const cid_len = 8;
/// Unsupported QUIC version (GREASE shape). A hysteria2 server must answer
/// with Version Negotiation and does not look at the payload.
const grease_version: u32 = 0x1a2a3a4a;

/// Reachability of a hysteria2 endpoint. `OK` means some datagram came back,
/// not that `userinfo` was accepted. `obfs` defeats this ping.
pub fn probe(
    gpa: std.mem.Allocator,
    io: Io,
    host: []const u8,
    port: u16,
    query: []const u8,
    timeout_secs: u32,
    bind_spec: ?[]const u8,
    addresses: ?[]Io.net.IpAddress,
    stage: *util.Stage,
    dialed: ?*Io.net.IpAddress,
) !u64 {
    stage.* = .setup;
    try rejectObfs(gpa, query);

    const deadline = netutil.deadlineNs(io, timeout_secs);
    stage.* = .connect;
    var storage: [max_peers]Io.net.IpAddress = undefined;
    const dests = try destinations(io, host, port, addresses, deadline, &storage);

    var dcid: [cid_len]u8 = undefined;
    var scid: [cid_len]u8 = undefined;
    io.random(&dcid);
    io.random(&scid);
    var packet: [packet_len]u8 = undefined;
    writeProbe(&packet, &dcid, &scid);

    // shortcut: Windows waits on one address at a time, so a silent address
    // burns the rest of the deadline. Upgrade when several UDP sockets can be polled together.
    const ms = if (builtin.target.os.tag == .windows)
        try probeWindows(io, host, port, dests, &packet, &scid, deadline, stage)
    else
        try probePosix(io, host, port, dests, bind_spec, &packet, &scid, deadline, stage);
    if (dialed) |slot| {
        if (dests.len > 0) slot.* = dests[0];
    }
    return ms;
}

fn rejectObfs(gpa: std.mem.Allocator, query: []const u8) !void {
    var params = std.mem.splitScalar(u8, query, '&');
    while (params.next()) |pair| {
        const eq = std.mem.findScalar(u8, pair, '=');
        const name = if (eq) |i| pair[0..i] else pair;
        if (!std.mem.eql(u8, name, "obfs")) continue;
        const raw = if (eq) |i| pair[i + 1 ..] else "";
        if (raw.len == 0) continue;
        const decoded = try util.urlDecodeStrict(gpa, raw);
        defer gpa.free(decoded);
        // An empty first value must not hide obfs in a later parameter.
        if (decoded.len != 0) return error.UnsupportedObfs;
    }
}

fn destinations(
    io: Io,
    host: []const u8,
    port: u16,
    addresses: ?[]Io.net.IpAddress,
    deadline: i128,
    storage: *[max_peers]Io.net.IpAddress,
) ![]Io.net.IpAddress {
    if (addresses) |known| if (known.len > 0) {
        if (known.len > max_peers) return error.TooManyResolvedAddresses;
        return known;
    };
    if (Io.net.IpAddress.parse(host, port)) |ip| {
        storage[0] = ip;
        return storage[0..1];
    } else |_| {}
    return netutil.resolveAllUntil(io, host, port, deadline, storage);
}

fn writeProbe(out: *[packet_len]u8, dcid: *const [cid_len]u8, scid: *const [cid_len]u8) void {
    @memset(out, 0);
    // Long header, fixed bit, Initial, 1-byte packet number.
    out[0] = 0xc0;
    std.mem.writeInt(u32, out[1..5], grease_version, .big);
    out[5] = cid_len;
    @memcpy(out[6..][0..cid_len], dcid);
    out[14] = cid_len;
    @memcpy(out[15..][0..cid_len], scid);
    out[23] = 0; // empty token
    // 2-byte varint length of the packet number and the zero payload.
    const body: u16 = packet_len - 26;
    out[24] = 0x40 | @as(u8, @intCast(body >> 8));
    out[25] = @truncate(body);
}

fn isVersionNegotiation(packet: []const u8, scid: *const [cid_len]u8) bool {
    if (packet.len < 6 + cid_len) return false;
    if (packet[0] & 0x80 == 0) return false;
    if (std.mem.readInt(u32, packet[1..5], .big) != 0) return false;
    if (packet[5] != cid_len) return false;
    return std.mem.eql(u8, packet[6..][0..cid_len], scid);
}

fn noteReply(host: []const u8, port: u16, reply: []const u8, scid: *const [cid_len]u8) void {
    if (isVersionNegotiation(reply, scid)) {
        std.log.debug("hysteria2 {s}:{d}: version negotiation", .{ host, port });
    } else {
        std.log.debug("hysteria2 {s}:{d}: udp reply ({d} bytes)", .{ host, port, reply.len });
    }
}

fn probeWindows(
    io: Io,
    host: []const u8,
    port: u16,
    dests: []Io.net.IpAddress,
    packet: []const u8,
    scid: *const [cid_len]u8,
    deadline: i128,
    stage: *util.Stage,
) !u64 {
    var last_err: anyerror = error.Timeout;
    const start = netutil.monoNow(io);
    var sent = false;
    for (dests) |dest| {
        if (netutil.monoNow(io) >= deadline) return error.Timeout;
        const local: Io.net.IpAddress = switch (dest) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = local.bind(io, .{ .mode = .dgram }) catch |err| {
            last_err = err;
            continue;
        };
        defer socket.close(io);

        socket.send(io, &dest, packet) catch |err| {
            last_err = err;
            continue;
        };
        if (!sent) {
            sent = true;
            stage.* = .handshake;
        }
        var buf: [2048]u8 = undefined;
        while (true) {
            const now = netutil.monoNow(io);
            if (now >= deadline) return error.Timeout;
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(deadline - now)),
                .clock = .awake,
            } };
            const message = socket.receiveTimeout(io, &buf, timeout) catch |err| {
                last_err = err;
                break;
            };
            if (message.data.len == 0 or !samePeer(message.from, dest)) continue;
            noteReply(host, port, message.data, scid);
            promote(dests, dest);
            return netutil.elapsedMs(start, io);
        }
    }
    return last_err;
}

fn promote(addresses: []Io.net.IpAddress, chosen: Io.net.IpAddress) void {
    for (addresses[1..], 1..) |address, i| {
        if (!samePeer(address, chosen)) continue;
        addresses[i] = addresses[0];
        addresses[0] = chosen;
        return;
    }
}

fn samePeer(from: Io.net.IpAddress, dest: Io.net.IpAddress) bool {
    return switch (dest) {
        .ip4 => |ip4| from == .ip4 and from.ip4.port == ip4.port and std.mem.eql(u8, &from.ip4.bytes, &ip4.bytes),
        .ip6 => |ip6| from == .ip6 and from.ip6.port == ip6.port and std.mem.eql(u8, &from.ip6.bytes, &ip6.bytes),
    };
}

const Attempt = struct {
    sock: posix.socket_t,
    dest: Io.net.IpAddress,
    open: bool = true,

    fn close(self: *Attempt) void {
        if (!self.open) return;
        self.open = false;
        _ = posix.system.close(self.sock);
    }
};

fn probePosix(
    io: Io,
    host: []const u8,
    port: u16,
    dests: []Io.net.IpAddress,
    bind_spec: ?[]const u8,
    packet: []const u8,
    scid: *const [cid_len]u8,
    deadline: i128,
    stage: *util.Stage,
) !u64 {
    var attempts: [max_peers]Attempt = undefined;
    var n: usize = 0;
    defer for (attempts[0..n]) |*attempt| attempt.close();

    var last_err: anyerror = error.Timeout;
    for (dests) |dest| {
        const sock = netutil.openUdpSocket(dest, bind_spec) catch |err| {
            last_err = err;
            continue;
        };
        // Sets the only peer the kernel will deliver, including ICMP unreachables.
        connectPeer(sock, dest) catch |err| {
            last_err = err;
            _ = posix.system.close(sock);
            continue;
        };
        attempts[n] = .{ .sock = sock, .dest = dest };
        n += 1;
    }
    if (n == 0) return last_err;

    stage.* = .handshake;
    const start = netutil.monoNow(io);
    var sent: usize = 0;
    for (attempts[0..n]) |*attempt| {
        udpSend(attempt.sock, packet) catch |err| {
            last_err = if (err == error.WouldBlock) error.Timeout else err;
            attempt.close();
            continue;
        };
        sent += 1;
    }
    if (sent == 0) {
        stage.* = .connect;
        return last_err;
    }
    return waitForReply(io, host, port, dests, attempts[0..n], scid, start, deadline, &last_err);
}

fn waitForReply(
    io: Io,
    host: []const u8,
    port: u16,
    dests: []Io.net.IpAddress,
    attempts: []Attempt,
    scid: *const [cid_len]u8,
    start: i128,
    deadline: i128,
    last_err: *anyerror,
) !u64 {
    var buf: [2048]u8 = undefined;
    while (true) {
        const now = netutil.monoNow(io);
        if (now >= deadline) return error.Timeout;

        var fds: [max_peers]posix.pollfd = undefined;
        var map: [max_peers]usize = undefined;
        var nfds: usize = 0;
        for (attempts, 0..) |attempt, i| {
            if (!attempt.open) continue;
            fds[nfds] = .{ .fd = attempt.sock, .events = posix.POLL.IN, .revents = 0 };
            map[nfds] = i;
            nfds += 1;
        }
        if (nfds == 0) return last_err.*;

        const timeout_ms: i32 = @intCast(@min(@divTrunc(deadline - now, std.time.ns_per_ms), std.math.maxInt(i32)));
        if (try posix.poll(fds[0..nfds], timeout_ms) == 0) return error.Timeout;

        for (fds[0..nfds], map[0..nfds]) |fd, index| {
            if (fd.revents == 0) continue;
            const nread = udpRecv(attempts[index].sock, &buf) catch |err| switch (err) {
                error.WouldBlock => {
                    if (fd.revents & (posix.POLL.ERR | posix.POLL.NVAL | posix.POLL.HUP) != 0) {
                        last_err.* = error.ConnectionResetByPeer;
                        attempts[index].close();
                    }
                    continue;
                },
                else => |e| {
                    last_err.* = e;
                    attempts[index].close();
                    continue;
                },
            };
            if (nread == 0) continue;
            noteReply(host, port, buf[0..nread], scid);
            promote(dests, attempts[index].dest);
            return netutil.elapsedMs(start, io);
        }
    }
}

fn connectPeer(sock: posix.socket_t, address: Io.net.IpAddress) !void {
    while (true) {
        const rc = switch (address) {
            .ip4 => |ip4| blk: {
                const sa = posix.sockaddr.in{
                    .port = std.mem.nativeToBig(u16, ip4.port),
                    .addr = @bitCast(ip4.bytes),
                };
                break :blk posix.system.connect(sock, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
            },
            .ip6 => |ip6| blk: {
                const sa = posix.sockaddr.in6{
                    .port = std.mem.nativeToBig(u16, ip6.port),
                    .flowinfo = ip6.flow,
                    .addr = ip6.bytes,
                    .scope_id = ip6.interface.index,
                };
                break :blk posix.system.connect(sock, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
            },
        };
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            // UDP connect only stores the peer. A non-blocking socket may still
            // report these; the association is already in place.
            .INPROGRESS, .AGAIN => return,
            .CONNREFUSED => return error.ConnectionRefused,
            .NETUNREACH => return error.NetworkUnreachable,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETDOWN => return error.NetworkDown,
            .TIMEDOUT => return error.ConnectTimeout,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .ACCES, .PERM => return error.AccessDenied,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            else => return error.Unexpected,
        }
    }
}

fn udpSend(sock: posix.socket_t, data: []const u8) !void {
    while (true) {
        const rc = posix.system.send(sock, data.ptr, data.len, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (@as(usize, @intCast(rc)) != data.len) return error.MessageOversize;
                return;
            },
            .INTR => continue,
            else => |err| return udpErrno(err),
        }
    }
}

fn udpRecv(sock: posix.socket_t, buf: []u8) !usize {
    while (true) {
        const rc = posix.system.recv(sock, buf.ptr, buf.len, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => |err| return udpErrno(err),
        }
    }
}

fn udpErrno(err: posix.E) anyerror {
    return switch (err) {
        .AGAIN => error.WouldBlock,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        .NETDOWN => error.NetworkDown,
        .MSGSIZE => error.MessageOversize,
        .NOBUFS, .NOMEM => error.SystemResources,
        .ACCES, .PERM => error.AccessDenied,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        else => error.Unexpected,
    };
}

test "version negotiation probe is a padded Initial" {
    var packet: [packet_len]u8 = undefined;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    writeProbe(&packet, &dcid, &scid);

    try std.testing.expectEqual(@as(u8, 0xc0), packet[0]);
    try std.testing.expectEqual(grease_version, std.mem.readInt(u32, packet[1..5], .big));
    try std.testing.expectEqualSlices(u8, &dcid, packet[6..14]);
    try std.testing.expectEqualSlices(u8, &scid, packet[15..23]);
    try std.testing.expectEqual(@as(u8, 0), packet[23]);
    try std.testing.expectEqual(@as(u16, 0x4496), std.mem.readInt(u16, packet[24..26], .big));
    try std.testing.expectEqual(@as(u8, 0), packet[26]);
    try std.testing.expectEqual(@as(u8, 0), packet[packet_len - 1]);
}

test "version negotiation reply echoes our source id" {
    const scid = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    var reply: [20]u8 = undefined;
    @memset(&reply, 0);
    reply[0] = 0x80;
    reply[5] = cid_len;
    @memcpy(reply[6..][0..cid_len], &scid);
    try std.testing.expect(isVersionNegotiation(&reply, &scid));

    reply[6] ^= 1;
    try std.testing.expect(!isVersionNegotiation(&reply, &scid));
    try std.testing.expect(!isVersionNegotiation(&[_]u8{0x40}, &scid));
}

test "rejectObfs ignores an empty value" {
    const gpa = std.testing.allocator;
    try rejectObfs(gpa, "");
    try rejectObfs(gpa, "sni=example.com");
    try rejectObfs(gpa, "obfs=");
    try rejectObfs(gpa, "obfs=&sni=example.com");
    try std.testing.expectError(error.UnsupportedObfs, rejectObfs(gpa, "obfs=&obfs=salamander"));
    try std.testing.expectError(error.UnsupportedObfs, rejectObfs(gpa, "sni=a&obfs=sala%6dander"));
}

test "probe rejects obfs before dialing" {
    var stage: util.Stage = .reply;
    try std.testing.expectError(error.UnsupportedObfs, probe(
        std.testing.allocator,
        std.testing.io,
        "192.0.2.1",
        443,
        "obfs=salamander",
        1,
        null,
        null,
        &stage,
        null,
    ));
    try std.testing.expectEqual(util.Stage.setup, stage);
}

test "udp ping accepts a loopback reply" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const server = try local.bind(io, .{ .mode = .dgram });
    defer server.close(io);

    const thread = try std.Thread.spawn(.{}, replyOnce, .{server.handle});
    defer thread.join();

    var addresses = [_]Io.net.IpAddress{server.address};
    var stage: util.Stage = .setup;
    const ms = try probe(
        std.testing.allocator,
        io,
        "127.0.0.1",
        server.address.getPort(),
        "sni=example.com",
        2,
        null,
        &addresses,
        &stage,
        null,
    );
    try std.testing.expect(ms < 2000);
    try std.testing.expectEqual(util.Stage.handshake, stage);
}

test "closed udp port fails without waiting out the timeout" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const local: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const server = try local.bind(io, .{ .mode = .dgram });
    const port = server.address.getPort();
    server.close(io);

    var stage: util.Stage = .setup;
    const start = netutil.monoNow(io);
    try std.testing.expectError(error.ConnectionRefused, probe(
        std.testing.allocator,
        io,
        "127.0.0.1",
        port,
        "",
        5,
        null,
        null,
        &stage,
        null,
    ));
    try std.testing.expect(netutil.elapsedMs(start, io) < 1000);
}

fn replyOnce(sock: posix.socket_t) void {
    var fds = [_]posix.pollfd{.{ .fd = sock, .events = posix.POLL.IN, .revents = 0 }};
    const ready = posix.poll(&fds, 3000) catch return;
    if (ready == 0) return;

    var buf: [2048]u8 = undefined;
    var src: posix.sockaddr.in = undefined;
    var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    const rc = posix.system.recvfrom(sock, &buf, buf.len, 0, @ptrCast(&src), &src_len);
    if (posix.errno(rc) != .SUCCESS or rc == 0) return;

    var reply: [14]u8 = @splat(0);
    reply[0] = 0x80;
    var reply_len: usize = 7;
    if (rc >= 23 and buf[14] == cid_len) {
        reply[5] = cid_len;
        @memcpy(reply[6..][0..cid_len], buf[15..][0..cid_len]);
        reply_len = reply.len;
    }
    _ = posix.system.sendto(sock, &reply, reply_len, 0, @ptrCast(&src), src_len);
}
