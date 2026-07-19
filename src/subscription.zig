const std = @import("std");
const util = @import("util.zig");

/// Decode standard or URL-safe base64 (with optional padding / whitespace).
pub fn decodeBase64(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    return util.decodeBase64Url(gpa, input, true);
}

/// Split decoded subscription into non-empty trimmed lines. Lines are slices into `decoded`.
pub fn iterLines(decoded: []const u8, comptime callback: anytype, ctx: anytype) !void {
    var iter = std.mem.splitScalar(u8, decoded, '\n');
    while (iter.next()) |raw| {
        var line = raw;
        if (std.mem.indexOfScalar(u8, line, '\r')) |r| line = line[0..r];
        line = std.mem.trim(u8, line, " \t");
        if (line.len == 0) continue;
        try callback(ctx, line);
    }
}

test "decodeBase64 hello" {
    const gpa = std.testing.allocator;
    const got = try decodeBase64(gpa, "aGVsbG8=");
    defer gpa.free(got);
    try std.testing.expectEqualStrings("hello", got);
}

test "decodeBase64 url-safe" {
    const gpa = std.testing.allocator;
    // ">>>" as standard base64 is "Pj4+" / url-safe "Pj4-"
    const got = try decodeBase64(gpa, "Pj4-");
    defer gpa.free(got);
    try std.testing.expectEqualStrings(">>>", got);
}

test "iterLines skips blanks" {
    const Ctx = struct {
        count: usize = 0,
        fn on(self: *@This(), line: []const u8) !void {
            _ = line;
            self.count += 1;
        }
    };
    var ctx: Ctx = .{};
    try iterLines("a\n\n b \n\r\nc", Ctx.on, &ctx);
    try std.testing.expectEqual(@as(usize, 3), ctx.count);
}
