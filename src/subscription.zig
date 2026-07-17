const std = @import("std");

/// Decode standard or URL-safe base64 (with optional padding / whitespace).
pub fn decodeBase64(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    var cleaned: std.ArrayList(u8) = .empty;
    defer cleaned.deinit(gpa);

    for (input) |c| {
        switch (c) {
            ' ', '\t', '\n', '\r' => {},
            '-' => try cleaned.append(gpa, '+'),
            '_' => try cleaned.append(gpa, '/'),
            else => try cleaned.append(gpa, c),
        }
    }

    // Pad to multiple of 4
    while (cleaned.items.len % 4 != 0) {
        try cleaned.append(gpa, '=');
    }

    const max_len = try std.base64.standard.Decoder.calcSizeForSlice(cleaned.items);
    const out = try gpa.alloc(u8, max_len);
    errdefer gpa.free(out);
    try std.base64.standard.Decoder.decode(out, cleaned.items);
    return out;
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
