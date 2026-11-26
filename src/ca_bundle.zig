const std = @import("std");
const Io = std.Io;
const Certificate = std.crypto.Certificate;

const CaState = struct {
    mutex: Io.Mutex = .init,
    rw: Io.RwLock = .init,
    bundle: Certificate.Bundle = .empty,
    loaded: bool = false,
    /// Set after the one rescan attempt fails; do not retry for every probe.
    failed: bool = false,
};

var ca_state: CaState = .{};

pub fn ensureCaBundle(gpa: std.mem.Allocator, io: Io) !*Certificate.Bundle {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    if (ca_state.loaded) return &ca_state.bundle;
    if (ca_state.failed) return error.CertificateBundleLoadFailure;
    const now = Io.Clock.real.now(io);
    ca_state.bundle.rescan(gpa, io, now) catch {
        ca_state.failed = true;
        return error.CertificateBundleLoadFailure;
    };
    ca_state.loaded = true;
    return &ca_state.bundle;
}

/// Free the process-wide CA cache. Call once after all probes finish
/// (DebugAllocator otherwise reports Bundle.rescan allocations as leaks).
pub fn deinitCaBundle(gpa: std.mem.Allocator, io: Io) void {
    ca_state.mutex.lockUncancelable(io);
    defer ca_state.mutex.unlock(io);
    // A failed rescan can leave allocations even though `loaded` is false.
    ca_state.bundle.deinit(gpa);
    ca_state.bundle = .empty;
    ca_state.loaded = false;
    ca_state.failed = false;
}

pub fn lock() *Io.RwLock {
    return &ca_state.rw;
}

test "deinitCaBundle frees a partial failed rescan" {
    // Arrange: rescan can allocate before returning an error, leaving loaded=false.
    const gpa = std.testing.allocator;
    try ca_state.bundle.bytes.append(gpa, 0x01);
    ca_state.loaded = false;

    // Act
    deinitCaBundle(gpa, std.testing.io);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.bytes.capacity);
    try std.testing.expectEqual(@as(usize, 0), ca_state.bundle.map.count());
}

test "ensureCaBundle does not rescan after a previous failure" {
    // Arrange
    const gpa = std.testing.allocator;
    deinitCaBundle(gpa, std.testing.io);
    ca_state.failed = true;
    defer ca_state.failed = false;

    // Act
    const result = ensureCaBundle(gpa, std.testing.io);

    // Assert
    try std.testing.expectError(error.CertificateBundleLoadFailure, result);
    try std.testing.expectEqual(false, ca_state.loaded);
    try std.testing.expectEqual(true, ca_state.failed);
}
