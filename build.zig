const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = resolveTarget(b);
    const optimize = b.standardOptimizeOption(.{});
    const strip = optimize != .Debug;
    const options = b.addOptions();

    const version_opt = b.option([]const u8, "version", "The version of the app") orelse "0.1.0-dev";
    options.addOption([]const u8, "version", version_opt);
    options.addOption([]const u8, "cpu_arch", @tagName(target.result.cpu.arch));

    const exe = b.addExecutable(.{
        .name = "hydec",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .optimize = optimize,
            .target = target,
            .strip = strip,
            .link_libc = true,
        }),
    });
    const zig_cli = b.dependency("zig_cli", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zig_cli", zig_cli.module("zig_cli"));
    exe.root_module.addImport("build_options", options.createModule());

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .optimize = optimize,
            .target = target,
            .link_libc = true,
        }),
    });
    unit_tests.root_module.addImport("zig_cli", zig_cli.module("zig_cli"));
    unit_tests.root_module.addImport("build_options", options.createModule());

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const tr = target.result;
    const tar_file = b.fmt("{s}/hydec-{s}-{s}-{s}-{s}.tar.gz", .{
        b.install_prefix,
        version_opt,
        @tagName(tr.cpu.arch),
        @tagName(tr.os.tag),
        @tagName(tr.abi),
    });

    const zig_step = b.addSystemCommand(&.{
        "tar",
        "-czf",
        tar_file,
        "-C",
        b.exe_dir,
        ".",
    });
    zig_step.step.dependOn(b.getInstallStep());

    const archive_step = b.step("archive", "Create a tar.gz archive of the build");
    archive_step.dependOn(&zig_step.step);
}

const pinned_glibc: std.Target.Query.SemanticVersion = .{
    .major = 2,
    .minor = 38,
    .patch = 0,
};

fn resolveTarget(b: *std.Build) std.Build.ResolvedTarget {
    const default_target: std.Target.Query = .{
        .abi = .gnu,
        .glibc_version = pinned_glibc,
    };

    var query = b.standardTargetOptionsQueryOnly(.{
        .default_target = default_target,
    });

    // A -Dcpu without -Dtarget must not silently switch the build over to native
    // OS-version detection: spell out the host triple so it matches -Dtarget.
    if (query.cpu_arch == null and query.os_tag == null) switch (query.cpu_model) {
        .native, .explicit => {
            query.cpu_arch = builtin.cpu.arch;
            query.os_tag = builtin.target.os.tag;
            query.abi = query.abi orelse builtin.target.abi;
        },
        .baseline, .determined_by_arch_os => {},
    };

    if (query.glibc_version == null) {
        const os = query.os_tag orelse builtin.target.os.tag;
        if (os == .linux) {
            const abi = query.abi orelse builtin.target.abi;
            if (abi.isGnu()) {
                query.glibc_version = pinned_glibc;
            }
        }
    }

    return b.resolveTargetQuery(query);
}
