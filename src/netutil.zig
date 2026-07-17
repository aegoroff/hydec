const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;

pub fn connectHostPort(io: Io, host: []const u8, port: u16, timeout_secs: u32) !Io.net.Stream {
    // Zig's Threaded Io panics on ConnectOptions.timeout ("TODO"), so IP dials
    // use a non-blocking connect + poll. Hostnames fall back to untimed Io connect.
    if (Io.net.IpAddress.parse(host, port)) |addr| {
        const stream = try connectIpTimed(io, addr, timeout_secs);
        setTcpNoDelay(stream);
        return stream;
    } else |_| {}

    const hostname = try Io.net.HostName.init(host);
    const stream = try hostname.connect(io, port, .{ .mode = .stream });
    setTcpNoDelay(stream);
    return stream;
}

fn connectIpTimed(io: Io, address: Io.net.IpAddress, timeout_secs: u32) !Io.net.Stream {
    if (builtin.os.tag == .windows) {
        // Best-effort: Zig Windows connect timeout is also TODO.
        return address.connect(io, .{ .mode = .stream });
    }

    const family: posix.sa_family_t = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const flags: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const sock = try openSocket(family, flags);
    errdefer _ = posix.system.close(sock);

    try startConnect(sock, address);
    try waitConnected(io, sock, timeout_secs);
    try clearNonblock(sock);

    return .{ .socket = .{ .handle = sock, .address = address } };
}

fn openSocket(family: posix.sa_family_t, flags: u32) !posix.socket_t {
    while (true) {
        const rc = posix.system.socket(family, flags, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            else => return error.Unexpected,
        }
    }
}

fn startConnect(sock: posix.socket_t, address: Io.net.IpAddress) !void {
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
        .SUCCESS => {},
        .INTR => try startConnect(sock, address),
        .INPROGRESS, .AGAIN => {},
        .CONNREFUSED => return error.ConnectionRefused,
        .NETUNREACH => return error.NetworkUnreachable,
        .HOSTUNREACH => return error.HostUnreachable,
        .TIMEDOUT => return error.Timeout,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.Unexpected,
    }
}

fn waitConnected(io: Io, sock: posix.socket_t, timeout_secs: u32) !void {
    const deadline = deadlineNs(io, timeout_secs);
    while (true) {
        const now = monoNow(io);
        if (deadline) |d| {
            if (now >= d) return error.Timeout;
        }
        const timeout_ms: i32 = if (deadline) |d|
            @intCast(@min(@divTrunc(d - now, std.time.ns_per_ms), std.math.maxInt(i32)))
        else
            -1;

        var fds = [_]posix.pollfd{.{
            .fd = sock,
            .events = posix.POLL.OUT,
            .revents = 0,
        }};
        const n = try posix.poll(&fds, timeout_ms);
        if (n == 0) return error.Timeout;

        const re = fds[0].revents;
        if ((re & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL | posix.POLL.OUT)) != 0) {
            try checkSocketError(sock);
            return;
        }
    }
}

fn checkSocketError(sock: posix.socket_t) !void {
    var err_code: i32 = 0;
    var len: posix.socklen_t = @sizeOf(i32);
    const rc = posix.system.getsockopt(
        sock,
        posix.SOL.SOCKET,
        posix.SO.ERROR,
        @ptrCast(&err_code),
        &len,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    if (err_code == 0) return;
    switch (@as(posix.E, @enumFromInt(err_code))) {
        .SUCCESS => {},
        .CONNREFUSED => return error.ConnectionRefused,
        .NETUNREACH => return error.NetworkUnreachable,
        .HOSTUNREACH => return error.HostUnreachable,
        .TIMEDOUT => return error.Timeout,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.Unexpected,
    }
}

fn clearNonblock(sock: posix.socket_t) !void {
    const get_rc = posix.system.fcntl(sock, posix.F.GETFL, @as(usize, 0));
    switch (posix.errno(get_rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    var flags: posix.O = @bitCast(@as(u32, @truncate(@as(usize, @intCast(get_rc)))));
    flags.NONBLOCK = false;
    const set_rc = posix.system.fcntl(sock, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags))));
    switch (posix.errno(set_rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
}

/// Disable Nagle — required for timely HTTP/2 preface/SETTINGS exchange.
pub fn setTcpNoDelay(stream: Io.net.Stream) void {
    if (builtin.os.tag == .windows) return;
    const one: c_int = 1;
    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&one),
    ) catch {};
}

pub fn monoNow(io: Io) i128 {
    const ts = Io.Clock.awake.now(io);
    return @intCast(ts.nanoseconds);
}

pub fn elapsedMs(start_ns: i128, io: Io) u64 {
    const now = monoNow(io);
    if (now <= start_ns) return 0;
    return @intCast(@divTrunc(now - start_ns, std.time.ns_per_ms));
}

pub fn deadlineNs(io: Io, timeout_secs: u32) ?i128 {
    if (timeout_secs == 0) return null;
    return monoNow(io) + @as(i128, timeout_secs) * std.time.ns_per_s;
}

/// Wait until the socket is readable or the absolute deadline passes.
/// Uses poll(2) — safe with Zig 0.16 Threaded Io (unlike SO_RCVTIMEO).
pub fn waitReadableUntil(stream: Io.net.Stream, io: Io, deadline_ns: ?i128) !void {
    const deadline = deadline_ns orelse return;
    if (builtin.os.tag == .windows) return;

    while (true) {
        const now = monoNow(io);
        if (now >= deadline) return error.Timeout;
        const remain_ms_i128 = @divTrunc(deadline - now, std.time.ns_per_ms);
        const timeout_ms: i32 = @intCast(@min(remain_ms_i128, std.math.maxInt(i32)));

        var fds = [_]std.posix.pollfd{.{
            .fd = stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const n = try std.posix.poll(&fds, timeout_ms);
        if (n == 0) return error.Timeout;
        if ((fds[0].revents & std.posix.POLL.IN) != 0) return;
        if ((fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0)
            return error.ConnectionResetByPeer;
        if ((fds[0].revents & std.posix.POLL.HUP) != 0) return;
    }
}

/// Unblocks a stuck blocking read/write by shutting the socket down after `timeout_ns`.
/// Needed for `std.crypto.tls` which ignores our poll-based deadlines.
/// Caller must keep `done` alive until `disarm` returns.
pub const DeadlineShutdown = struct {
    done: *std.atomic.Value(bool),
    thread: ?std.Thread,

    pub fn arm(fd: posix.fd_t, timeout_ns: u64, done: *std.atomic.Value(bool)) !DeadlineShutdown {
        done.* = std.atomic.Value(bool).init(false);
        if (builtin.os.tag == .windows or timeout_ns == 0) {
            return .{ .done = done, .thread = null };
        }
        const thread = try std.Thread.spawn(.{}, watchdog, .{ fd, timeout_ns, done });
        return .{ .done = done, .thread = thread };
    }

    pub fn disarm(self: *DeadlineShutdown) void {
        if (self.thread) |t| {
            self.done.store(true, .release);
            t.join();
            self.thread = null;
        }
    }

    fn watchdog(fd: posix.fd_t, timeout_ns: u64, done: *std.atomic.Value(bool)) void {
        const chunk: u64 = 50 * std.time.ns_per_ms;
        var left = timeout_ns;
        while (left > 0 and !done.load(.acquire)) {
            const step = @min(left, chunk);
            sleepNs(step);
            left -= step;
        }
        if (!done.load(.acquire)) {
            _ = posix.system.shutdown(fd, posix.SHUT.RDWR);
        }
    }

    fn sleepNs(ns: u64) void {
        var req = posix.timespec{
            .sec = @intCast(ns / std.time.ns_per_s),
            .nsec = @intCast(ns % std.time.ns_per_s),
        };
        while (true) {
            const rc = posix.system.nanosleep(&req, &req);
            switch (posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                else => return,
            }
        }
    }
};

pub fn remainingTimeoutNs(start_ns: i128, io: Io, timeout_secs: u32) u64 {
    if (timeout_secs == 0) return std.math.maxInt(u64);
    const budget: i128 = @as(i128, timeout_secs) * std.time.ns_per_s;
    const elapsed = monoNow(io) - start_ns;
    if (elapsed >= budget) return 0;
    return @intCast(budget - elapsed);
}
