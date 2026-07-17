# AGENTS.md

Instructions for AI coding agents working in the **hydec** repository.

## Project overview

A non-interactive file system information tool implemented in Zig. It gets and probes sing-box proxies and finds the best one.

| Item | Value |
|------|-------|
| Language | Zig **0.16.0** (see `mise.toml`) |
| CLI parsing | [zig-cli](https://github.com/zig-utils/zig-cli) |
| License | MIT |

## Build and run

Use **mise** to pin the Zig version, or install Zig 0.16.0 manually.

```bash
# Standard local build
zig build

# Run tests
zig build test

# Run with a path to analyze
zig build run -- .

# Cross-compile example
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
```

Via **just** (uses mise for Zig; CI uses the same recipes):

```bash
just build                                                      # ReleaseFast, x86_64-linux-musl, core2
just test
just arch=x86_64 os=linux abi=musl ver=0.3.0 cpu=core2 release
just ver=0.3.0 build-all                                        # all CI targets + archives
```

Binary output: `zig-out/bin/hydec` (or custom prefix from `--prefix-exe-dir`).

**Linux-gnu note:** `build.zig` pins glibc to 2.38 so Zig links its bundled CRT. Do not drop that pin without understanding the `.sframe` / system `crt1.o` issue documented in `build.zig`.

## Zig conventions for this repo

- **Minimize scope.** Small, focused diffs. No drive-by refactors.
- **Match existing style.** Follow patterns in existing `src/*.zig` modules for naming, error handling, and allocator use.
- **Use std library first.** Avoid adding dependencies without discussion.
- **I/O.** This codebase uses Zig 0.16 `std.Io` APIs (`init.io`, `std.Io.File`, `std.Io.Dir`, `std.Io.Clock`, `std.Io.Writer`). Do not revert to pre-0.16 file APIs.
- **Comments.** Only for non-obvious logic; the code should read clearly on its own.
- **Tests.** Add `test` blocks in the same file as the code under test. Run `zig build test` before finishing.
- **Format.** Apply `zig fmt` to changed Zig files before finishing.

## Code style

- Follow Zig standard library conventions
- `snake_case` for functions and variables; `PascalCase` for types; `SCREAMING_SNAKE_CASE` for constants
- Prefer explicit error handling with `!` return types
- Keep functions small and focused on a single responsibility
- Prefer `gpa` as the allocator parameter name
- Prefer `init.gpa` / `init.io` from `std.process.Init` in `main` rather than inventing globals

## Development rules

### Before making changes

1. Read existing code to understand patterns and conventions
2. Check for existing tests related to modified functionality
3. Keep changes compatible with the existing CLI unless the task changes it

### When writing code

1. Write idiomatic Zig following std lib patterns
2. Handle errors explicitly — no silent failures (existing `catch {}` / `catch continue` in the walk path are intentional; do not broaden that pattern casually)
3. Add tests for new functionality (AAA: Arrange, Act, Assert)
4. Keep backward compatibility when possible

### When fixing bugs

1. Understand root cause before fixing
2. Add a regression test if missing
3. Check for similar issues in related code
4. Verify the fix does not break existing tests

## Testing

```bash
zig build test
```

Prefer table-driven or focused unit tests (see `src/lib.zig`). Full-tree scans are for manual smoke checks, not default automated tests.

CI runs tests only for `x86_64-linux` builds (`just release`). Ensure tests pass on that target.

## CI and releases

- **Branches:** `master`, `develop`; PRs target `master`.
- **CI:** `.github/workflows/ci_build.yml` — matrix build for Linux, Windows, macOS (x86_64 + aarch64).
- **Releases:** Tags `v*` trigger changelog generation (`cliff.toml` / git-cliff) and GitHub release with `.tar.gz` artifacts.
- **Version:** Passed at build time via `-Dversion=...` (`build_options.version` in code). Default: `0.3.0-dev`.

## Commit and PR guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: human-readable size in reporter
fix: skip unreadable entries without aborting walk
chore: readme corrected
ci: migration to mise
build: zig 0.16
refactor: pass walker entry by reference
```

- Do **not** commit unless explicitly asked.
- Do **not** push or force-push without explicit request.
- Keep PRs focused; describe what changed and how to verify (`zig build test`, manual `hydec .` smoke test).

## Security

- Never commit secrets, tokens, or credentials.
- Treat user-supplied paths carefully; prefer `std.Io.Dir` / path helpers over ad-hoc string concatenation when opening or joining paths.

## What agents should avoid

- Adding large frameworks or unnecessary abstractions for one-off logic.
- Copying entire files into rules or docs — reference paths instead.
- Changing `build.zig.zon` dependency hashes without fetching and verifying the new package.
- Breaking cross-compilation targets listed in CI without updating the workflow.
- Editing `README.md` or this file unless the task requires documentation updates.
- Reintroducing multithreading for the walk without a clear, measured plan (previously rolled back).

## Verification checklist

Before considering a task done:

1. `zig build` succeeds.
2. `zig build test` passes.
3. Changed Zig sources are formatted with `zig fmt`.
4. No new compiler warnings in ReleaseFast (CI default).
