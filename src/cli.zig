const std = @import("std");
const zig_cli = @import("zig_cli");
const build_options = @import("build_options");

const Io = std.Io;

pub const Command = enum { best, ping };

pub const Options = struct {
    command: Command,
    /// Owned by the caller; free with `gpa.free`.
    /// `best`: subscription URL; `ping`: full proxy URI.
    uri: []u8,
    timeout_secs: u32,
    verbose: bool,
    /// Optional owned interface/source-IP spec forwarded to probe sockets.
    /// `null` = kernel chooses. Free with `gpa.free`.
    interface: ?[]u8,
};

const Capture = struct {
    gpa: std.mem.Allocator,
    options: ?Options = null,
};

var capture: Capture = undefined;

fn parseTimeout(ctx: *zig_cli.BaseCommand.ParseContext) !u32 {
    const timeout_secs: u32 = blk: {
        if (ctx.getOption("timeout")) |value| {
            break :blk std.fmt.parseInt(u32, value, 10) catch return error.InvalidTimeout;
        }
        break :blk 5;
    };
    if (timeout_secs == 0) return error.InvalidTimeout;
    return timeout_secs;
}

fn onBest(ctx: *zig_cli.BaseCommand.ParseContext) !void {
    const uri_arg = ctx.getArgument(0) orelse return error.MissingRequiredArgument;
    const uri = try capture.gpa.dupe(u8, uri_arg);
    errdefer capture.gpa.free(uri);

    const interface = try dupeOpt(capture.gpa, ctx.getOption("interface"));
    errdefer if (interface) |i| capture.gpa.free(i);

    capture.options = .{
        .command = .best,
        .uri = uri,
        .timeout_secs = try parseTimeout(ctx),
        .verbose = ctx.hasOption("verbose"),
        .interface = interface,
    };
}

fn onPing(ctx: *zig_cli.BaseCommand.ParseContext) !void {
    const uri_arg = ctx.getArgument(0) orelse return error.MissingRequiredArgument;
    const uri = try capture.gpa.dupe(u8, uri_arg);
    errdefer capture.gpa.free(uri);

    const interface = try dupeOpt(capture.gpa, ctx.getOption("interface"));
    errdefer if (interface) |i| capture.gpa.free(i);

    capture.options = .{
        .command = .ping,
        .uri = uri,
        .timeout_secs = try parseTimeout(ctx),
        .verbose = false,
        .interface = interface,
    };
}

fn dupeOpt(gpa: std.mem.Allocator, value: ?[]const u8) !?[]u8 {
    if (value) |v| {
        if (v.len == 0) return error.EmptyInterfaceName;
        return try gpa.dupe(u8, v);
    }
    return null;
}

fn wantsHelp(args: []const []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return true;
    }
    return false;
}

fn wantsVersion(args: []const []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) return true;
    }
    return false;
}

fn shortTakesValue(options: []const zig_cli.Option, short: u8) bool {
    for (options) |opt| {
        if (opt.short) |s| {
            if (s == short) return opt.option_type != .bool;
        }
    }
    return false;
}

fn normalizeArgs(
    gpa: std.mem.Allocator,
    options: []const zig_cli.Option,
    args: []const []const u8,
) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(gpa);

    for (args) |arg| {
        if (arg.len >= 3 and arg[0] == '-' and arg[1] != '-' and shortTakesValue(options, arg[1])) {
            try list.append(gpa, arg[0..2]);
            try list.append(gpa, arg[2..]);
            continue;
        }
        if (arg.len >= 4 and std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
                if (eq > 2) {
                    try list.append(gpa, arg[0..eq]);
                    try list.append(gpa, arg[eq + 1 ..]);
                    continue;
                }
            }
        }
        try list.append(gpa, arg);
    }
    return try list.toOwnedSlice(gpa);
}

fn collectArgs(gpa: std.mem.Allocator, args: std.process.Args) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| gpa.free(s);
        list.deinit(gpa);
    }

    var iter = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iter.deinit();
    _ = iter.skip();
    while (iter.next()) |arg| {
        const owned = try gpa.dupe(u8, arg);
        errdefer gpa.free(owned);
        try list.append(gpa, owned);
    }
    return try list.toOwnedSlice(gpa);
}

fn freeCollectedArgs(gpa: std.mem.Allocator, args: []const []const u8) void {
    for (args) |s| gpa.free(s);
    gpa.free(args);
}

fn addTimeoutOption(cmd: *zig_cli.BaseCommand) !*zig_cli.BaseCommand {
    return cmd.addOption(
        zig_cli.Option.init(
            "timeout",
            "timeout",
            "Per-proxy probe timeout in seconds (default: 5)",
            .int,
        ).withShort('t'),
    );
}

fn addInterfaceOption(cmd: *zig_cli.BaseCommand) !*zig_cli.BaseCommand {
    return cmd.addOption(
        zig_cli.Option.init(
            "interface",
            "interface",
            "Bind probe sockets to a network interface NAME or source IP (default: kernel chooses; NAME needs root/CAP_NET_RAW on Linux)",
            .string,
        ).withShort('I'),
    );
}

fn buildRoot(gpa: std.mem.Allocator, description: []const u8) !*zig_cli.BaseCommand {
    const root = try zig_cli.BaseCommand.init(gpa, "hydec", description);
    errdefer {
        root.deinit();
        gpa.destroy(root);
    }

    _ = try root.addOption(
        zig_cli.Option.init(
            "version",
            "version",
            "Print version and exit",
            .bool,
        ).withShort('V'),
    );

    {
        var owned = true;
        const best = try zig_cli.BaseCommand.init(gpa, "best", "Find the fastest working proxy from a subscription URL");
        errdefer if (owned) {
            best.deinit();
            gpa.destroy(best);
        };
        _ = try best.addArgument(
            zig_cli.Argument.init("URI", "Subscription URL (HTTPS, base64 body)", .string).withRequired(true),
        );
        _ = try addTimeoutOption(best);
        _ = try addInterfaceOption(best);
        _ = try best.addOption(
            zig_cli.Option.init(
                "verbose",
                "verbose",
                "Log each probe result to stderr",
                .bool,
            ).withShort('v'),
        );
        _ = best.setAction(onBest);
        _ = try root.addCommand(best);
        owned = false;
    }

    {
        var owned = true;
        const ping = try zig_cli.BaseCommand.init(gpa, "ping", "Probe a single proxy URI");
        errdefer if (owned) {
            ping.deinit();
            gpa.destroy(ping);
        };
        _ = try ping.addArgument(
            zig_cli.Argument.init("PROXY", "Full proxy URI (ss://, trojan://, vless://)", .string).withRequired(true),
        );
        _ = try addTimeoutOption(ping);
        _ = try addInterfaceOption(ping);
        _ = ping.setAction(onPing);
        _ = try root.addCommand(ping);
        owned = false;
    }

    return root;
}

fn optionValueLabel(option_type: zig_cli.Option.OptionType) []const u8 {
    return switch (option_type) {
        .string => " <VALUE>",
        .int => " <INT>",
        .float => " <FLOAT>",
        .bool => "",
    };
}

fn optionLeftWidth(opt: zig_cli.Option) usize {
    return 6 + 2 + opt.long.len + optionValueLabel(opt.option_type).len;
}

fn argumentLeftWidth(arg: zig_cli.Argument) usize {
    var width: usize = 4 + arg.name.len;
    if (arg.variadic) width += 3;
    return width;
}

fn writePadding(writer: *std.Io.Writer, used: usize, column: usize) !void {
    var i = used;
    while (i < column) : (i += 1) {
        try writer.writeByte(' ');
    }
}

fn printHelp(io: Io, cmd: *zig_cli.BaseCommand, usage_name: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(io, &buf);
    const out = &file_writer.interface;

    const help_left = "  -h, --help";
    var left_column: usize = help_left.len;
    for (cmd.arguments.items) |arg| {
        left_column = @max(left_column, argumentLeftWidth(arg));
    }
    for (cmd.options.items) |opt| {
        left_column = @max(left_column, optionLeftWidth(opt));
    }
    for (cmd.subcommands.items) |sub| {
        left_column = @max(left_column, 2 + sub.name.len);
    }
    const desc_column = left_column + 2;

    try out.print("\n{s} v{s}\n{s}\n\n", .{ "hydec", build_options.version, cmd.description });

    try out.print("USAGE:\n  {s}", .{usage_name});
    if (cmd.subcommands.items.len > 0) try out.print(" <COMMAND>", .{});
    if (cmd.options.items.len > 0) try out.print(" [OPTIONS]", .{});
    for (cmd.arguments.items) |arg| {
        if (arg.required) {
            try out.print(" <{s}>", .{arg.name});
        } else {
            try out.print(" [{s}]", .{arg.name});
        }
    }
    try out.print("\n\n", .{});

    if (cmd.arguments.items.len > 0) {
        try out.print("ARGUMENTS:\n", .{});
        for (cmd.arguments.items) |arg| {
            try out.print("  <{s}>", .{arg.name});
            try writePadding(out, argumentLeftWidth(arg), desc_column);
            try out.print("{s}\n", .{arg.description});
        }
        try out.print("\n", .{});
    }

    if (cmd.options.items.len > 0) {
        try out.print("OPTIONS:\n", .{});
        for (cmd.options.items) |opt| {
            if (opt.short) |s| {
                try out.print("  -{c}, ", .{s});
            } else {
                try out.print("      ", .{});
            }
            try out.print("--{s}{s}", .{ opt.long, optionValueLabel(opt.option_type) });
            try writePadding(out, optionLeftWidth(opt), desc_column);
            try out.print("{s}\n", .{opt.description});
        }
        try out.print("{s}", .{help_left});
        try writePadding(out, help_left.len, desc_column);
        try out.print("Print help\n\n", .{});
    } else if (cmd.subcommands.items.len > 0) {
        try out.print("OPTIONS:\n", .{});
        try out.print("{s}", .{help_left});
        try writePadding(out, help_left.len, desc_column);
        try out.print("Print help\n\n", .{});
    }

    if (cmd.subcommands.items.len > 0) {
        try out.print("COMMANDS:\n", .{});
        for (cmd.subcommands.items) |sub| {
            try out.print("  {s}", .{sub.name});
            try writePadding(out, 2 + sub.name.len, desc_column);
            try out.print("{s}\n", .{sub.description});
        }
        try out.print("\nRun 'hydec <COMMAND> --help' for more information on a command.\n\n", .{});
    }

    try out.flush();
}

pub fn printVersion(io: Io) !void {
    var buf: [256]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(io, &buf);
    try file_writer.interface.print("hydec {s}\n", .{build_options.version});
    try file_writer.interface.flush();
}

const ParseResult = union(enum) {
    help,
    version,
    run: Options,
};

fn normalizeOptionsFor(root: *zig_cli.BaseCommand, args: []const []const u8) []const zig_cli.Option {
    if (args.len > 0) {
        if (root.findSubcommand(args[0])) |sub| return sub.options.items;
    }
    return root.options.items;
}

pub fn parse(gpa: std.mem.Allocator, io: Io, args: std.process.Args) !ParseResult {
    const description = try std.fmt.allocPrint(
        gpa,
        \\Probe proxies from a subscription or a single URI ({s})
        \\Copyright (C) 2026. MIT License.
    ,
        .{build_options.cpu_arch},
    );
    defer gpa.free(description);

    const root = try buildRoot(gpa, description);
    defer {
        root.deinit();
        gpa.destroy(root);
    }

    const raw_args = try collectArgs(gpa, args);
    defer freeCollectedArgs(gpa, raw_args);
    const arg_slice = try normalizeArgs(gpa, normalizeOptionsFor(root, raw_args), raw_args);
    defer gpa.free(arg_slice);

    if (arg_slice.len == 0 or wantsHelp(arg_slice)) {
        if (arg_slice.len >= 1) {
            if (root.findSubcommand(arg_slice[0])) |sub| {
                const usage = try std.fmt.allocPrint(gpa, "hydec {s}", .{sub.name});
                defer gpa.free(usage);
                try printHelp(io, sub, usage);
                return .help;
            }
        }
        try printHelp(io, root, "hydec");
        return .help;
    }
    if (wantsVersion(arg_slice)) {
        return .version;
    }

    if (arg_slice.len == 0 or root.findSubcommand(arg_slice[0]) == null) {
        return error.UnknownCommand;
    }

    capture = .{ .gpa = gpa };
    var parser = zig_cli.Parser.init(gpa);
    parser.parse(root, arg_slice) catch |err| {
        if (capture.options) |opts| {
            gpa.free(opts.uri);
            if (opts.interface) |i| gpa.free(i);
        }
        capture.options = null;
        return err;
    };
    const opts = capture.options orelse return error.MissingRequiredArgument;
    return .{ .run = opts };
}

test "normalizeArgs expands attached timeout" {
    const options = [_]zig_cli.Option{
        zig_cli.Option.init("timeout", "timeout", "", .int).withShort('t'),
        zig_cli.Option.init("verbose", "verbose", "", .bool).withShort('v'),
    };
    const raw = [_][]const u8{ "-t3", "-v", "https://example.com/s/x" };
    const normalized = try normalizeArgs(std.testing.allocator, &options, &raw);
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqual(@as(usize, 4), normalized.len);
    try std.testing.expectEqualStrings("-t", normalized[0]);
    try std.testing.expectEqualStrings("3", normalized[1]);
}

test "normalizeArgs expands --timeout=value" {
    const options = [_]zig_cli.Option{
        zig_cli.Option.init("timeout", "timeout", "", .int).withShort('t'),
    };
    const raw = [_][]const u8{ "--timeout=5", "https://example.com/s/x" };
    const normalized = try normalizeArgs(std.testing.allocator, &options, &raw);
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqual(@as(usize, 3), normalized.len);
    try std.testing.expectEqualStrings("--timeout", normalized[0]);
    try std.testing.expectEqualStrings("5", normalized[1]);
}

test "normalizeArgs expands attached interface" {
    const options = [_]zig_cli.Option{
        zig_cli.Option.init("interface", "interface", "", .string).withShort('I'),
    };
    const raw = [_][]const u8{ "-Ieth0", "https://example.com/s/x" };
    const normalized = try normalizeArgs(std.testing.allocator, &options, &raw);
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqual(@as(usize, 3), normalized.len);
    try std.testing.expectEqualStrings("-I", normalized[0]);
    try std.testing.expectEqualStrings("eth0", normalized[1]);
}
