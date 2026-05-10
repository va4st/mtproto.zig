//! `mtbuddy ss` — manage the Shadowsocks-2022 listener.
//!
//! Subcommands:
//!   * `enable`    — generate a fresh PSK and append a `[shadowsocks]` section
//!                   to config.toml; print SS URLs and a sing-box snippet.
//!   * `link`      — print SS URL / sing-box config from the current config.
//!   * `disable`   — set `[shadowsocks].enabled = false` (PSK kept for reuse).
//!   * `psk`       — generate and print a PSK base64 string only (no I/O).
//!
//! The default config path is `/opt/mtproto-proxy/config.toml` when present,
//! otherwise `./config.toml`. Override with `--config <path>`.

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const Config = @import("proxy_config").Config;

const Tui = tui_mod.Tui;

// PSK helpers — kept local so the ctl module doesn't depend on the
// proxy/protocol module tree (which imports Linux-only crypto headers
// indirectly via the proxy event loop).
const psk_len: usize = 32;

fn generatePsk(out: *[psk_len]u8) void {
    std.crypto.random.bytes(out);
}

fn encodePskBase64(out: []u8, psk: *const [psk_len]u8) []const u8 {
    const enc = std.base64.standard.Encoder;
    const n = enc.calcSize(psk_len);
    std.debug.assert(out.len >= n);
    return enc.encode(out[0..n], psk);
}

fn decodePskBase64(b64: []const u8) ?[psk_len]u8 {
    const dec = std.base64.standard.Decoder;
    const expected = dec.calcSizeForSlice(b64) catch return null;
    if (expected != psk_len) return null;
    var out: [psk_len]u8 = undefined;
    dec.decode(&out, b64) catch return null;
    return out;
}

const installed_config_path = "/opt/mtproto-proxy/config.toml";
const local_config_path = "config.toml";

const default_allowed_hosts =
    "telegram.org,t.me,fragment.com,wallet.tg,ton.org,tonkeeper.com," ++
    "tonapi.io,tonconsole.com,getgems.io,stonfi.io,stonfi.com," ++
    "ton.app,blum.codes,gatcoin.io,notcoin.bot,hamsterkombat.io";
const default_ss_port: u16 = 8388;

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    const sub = args.next() orelse {
        printHelp(ui);
        return;
    };
    var opts = parseOptions(args);

    if (std.mem.eql(u8, sub, "enable")) {
        try cmdEnable(ui, allocator, &opts);
        return;
    }
    if (std.mem.eql(u8, sub, "link") or std.mem.eql(u8, sub, "url")) {
        try cmdLink(ui, allocator, &opts);
        return;
    }
    if (std.mem.eql(u8, sub, "disable")) {
        try cmdDisable(ui, allocator, &opts);
        return;
    }
    if (std.mem.eql(u8, sub, "psk")) {
        cmdPsk(ui);
        return;
    }
    if (std.mem.eql(u8, sub, "help") or std.mem.eql(u8, sub, "--help") or std.mem.eql(u8, sub, "-h")) {
        printHelp(ui);
        return;
    }

    ui.fail("Unknown ss subcommand");
    printHelp(ui);
}

const SsOpts = struct {
    config_path: ?[]const u8 = null,
    server: ?[]const u8 = null,
    port: ?u16 = null,
    allowed_hosts: ?[]const u8 = null,
    block_private: ?bool = null,
};

fn parseOptions(args: *std.process.Args.Iterator) SsOpts {
    var opts = SsOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            opts.config_path = args.next();
        } else if (std.mem.eql(u8, arg, "--server") or std.mem.eql(u8, arg, "-s")) {
            opts.server = args.next();
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            const raw = args.next() orelse continue;
            opts.port = std.fmt.parseInt(u16, raw, 10) catch null;
        } else if (std.mem.eql(u8, arg, "--allowed-hosts")) {
            opts.allowed_hosts = args.next();
        } else if (std.mem.eql(u8, arg, "--block-private")) {
            const raw = args.next() orelse continue;
            opts.block_private = std.mem.eql(u8, raw, "true") or std.mem.eql(u8, raw, "1");
        }
    }
    return opts;
}

fn defaultConfigPath() []const u8 {
    if (sys.fileExists(installed_config_path)) return installed_config_path;
    return local_config_path;
}

fn resolveConfigPath(opts: *const SsOpts) []const u8 {
    return opts.config_path orelse defaultConfigPath();
}

fn printHelp(ui: *Tui) void {
    ui.print(
        \\
        \\  Usage: mtbuddy ss <enable|link|disable|psk> [--config <path>]
        \\
        \\  Subcommands:
        \\    enable    Generate a PSK and append a [shadowsocks] section to config.toml.
        \\              Options:
        \\                --port <u16>            Listen port (default: 8388)
        \\                --server <ip-or-host>   Override server host shown in printed URLs
        \\                --allowed-hosts <csv>   Override the default allow-list
        \\                --block-private <bool>  Default: true
        \\
        \\    link      Print SS URL / sing-box snippet from the current config.
        \\
        \\    disable   Set [shadowsocks].enabled = false (PSK kept for re-enable).
        \\
        \\    psk       Generate one PSK base64 string and print it (no I/O).
        \\
        \\
    ,
        .{},
    );
}

// ─── Subcommands ──────────────────────────────────────────────

fn cmdPsk(ui: *Tui) void {
    var psk: [psk_len]u8 = undefined;
    generatePsk(&psk);
    var b64_buf: [64]u8 = undefined;
    const b64 = encodePskBase64(&b64_buf, &psk);
    ui.print("{s}\n", .{b64});
}

fn cmdEnable(ui: *Tui, allocator: std.mem.Allocator, opts: *const SsOpts) !void {
    const path = resolveConfigPath(opts);

    var current = Config.loadFromFile(allocator, path) catch |err| {
        ui.print("  failed to load {s}: {any}\n", .{ path, err });
        return error.ConfigLoadFailed;
    };
    defer current.deinit(allocator);

    if (current.shadowsocks.enabled and current.shadowsocks.psk != null) {
        ui.warn("Shadowsocks is already enabled in this config.");
        ui.hint("Use `mtbuddy ss link` to print the connection URLs again.");
        try printConnectionDetails(ui, allocator, &current, opts);
        return;
    }

    var psk: [psk_len]u8 = undefined;
    if (current.shadowsocks.psk) |existing| {
        psk = existing;
    } else {
        generatePsk(&psk);
    }

    var psk_b64_buf: [64]u8 = undefined;
    const psk_b64 = encodePskBase64(&psk_b64_buf, &psk);

    const port = opts.port orelse if (current.shadowsocks.port != 0) current.shadowsocks.port else default_ss_port;
    const allowed_hosts = opts.allowed_hosts orelse default_allowed_hosts;
    const block_private = opts.block_private orelse current.shadowsocks.block_private_networks;

    try writeOrUpdateShadowsocksSection(allocator, path, .{
        .port = port,
        .psk_b64 = psk_b64,
        .allowed_hosts = allowed_hosts,
        .block_private = block_private,
    });

    ui.ok("Shadowsocks-2022 enabled");
    ui.info(path);

    // Reload current to reflect what we wrote (so printing uses fresh values).
    var reloaded = try Config.loadFromFile(allocator, path);
    defer reloaded.deinit(allocator);
    try printConnectionDetails(ui, allocator, &reloaded, opts);

    ui.section("Next steps");
    ui.print(
        \\  1. Open the SS port in your firewall:
        \\       sudo ufw allow {d}/tcp
        \\  2. Reload the proxy so it picks up the new section:
        \\       sudo systemctl reload mtproto-proxy
        \\     (or `sudo mtbuddy reload`)
        \\
    , .{port});
}

fn cmdLink(ui: *Tui, allocator: std.mem.Allocator, opts: *const SsOpts) !void {
    const path = resolveConfigPath(opts);
    var cfg = Config.loadFromFile(allocator, path) catch |err| {
        ui.print("  failed to load {s}: {any}\n", .{ path, err });
        return error.ConfigLoadFailed;
    };
    defer cfg.deinit(allocator);

    if (!cfg.shadowsocks.enabled or cfg.shadowsocks.psk == null) {
        ui.fail("Shadowsocks not configured in this config.");
        ui.hint("Run `mtbuddy ss enable` first.");
        return;
    }

    try printConnectionDetails(ui, allocator, &cfg, opts);
}

fn cmdDisable(ui: *Tui, allocator: std.mem.Allocator, opts: *const SsOpts) !void {
    const path = resolveConfigPath(opts);
    var cfg = Config.loadFromFile(allocator, path) catch |err| {
        ui.print("  failed to load {s}: {any}\n", .{ path, err });
        return error.ConfigLoadFailed;
    };
    defer cfg.deinit(allocator);

    if (!cfg.shadowsocks.enabled) {
        ui.warn("Shadowsocks already disabled.");
        return;
    }

    try setEnabledFlag(allocator, path, false);
    ui.ok("Shadowsocks-2022 disabled (PSK preserved)");
    ui.info(path);
    ui.hint("Run `sudo mtbuddy reload` to apply.");
}

// ─── Connection details printer ────────────────────────────────

fn printConnectionDetails(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    opts: *const SsOpts,
) !void {
    const psk = cfg.shadowsocks.psk orelse return;
    var psk_b64_buf: [64]u8 = undefined;
    const psk_b64 = encodePskBase64(&psk_b64_buf, &psk);
    const port = cfg.shadowsocks.port;

    const server = opts.server orelse (cfg.shadowsocks.bind_address orelse "<your-server-ip>");

    ui.section("Connection");
    ui.print("  method:   2022-blake3-aes-256-gcm\n", .{});
    ui.print("  server:   {s}\n", .{server});
    ui.print("  port:     {d}\n", .{port});
    ui.print("  password: {s}\n", .{psk_b64});

    // SS URL — Shadowrocket / Stash / Loon style.
    ui.section("Shadowsocks URL");
    ui.print("  ss://2022-blake3-aes-256-gcm:{s}@{s}:{d}#mtproto-ss\n", .{ psk_b64, server, port });

    // sing-box outbound JSON snippet — easy to drop into a config.
    ui.section("sing-box outbound");
    ui.print(
        \\  {{
        \\    "type": "shadowsocks",
        \\    "tag": "ss-mtproto",
        \\    "server": "{s}",
        \\    "server_port": {d},
        \\    "method": "2022-blake3-aes-256-gcm",
        \\    "password": "{s}"
        \\  }}
        \\
    , .{ server, port, psk_b64 });

    if (cfg.shadowsocks.allowed_hosts.len > 0) {
        ui.section("Allowed hosts");
        var w_buf: [2048]u8 = undefined;
        var w: std.Io.Writer = .fixed(&w_buf);
        for (cfg.shadowsocks.allowed_hosts, 0..) |h, i| {
            if (i > 0) try w.writeAll(", ");
            try w.writeAll(h);
        }
        ui.print("  {s}\n", .{w.buffered()});
    }

    _ = allocator;
}

// ─── config.toml manipulation ──────────────────────────────────

const SsSectionUpdate = struct {
    port: u16,
    psk_b64: []const u8,
    allowed_hosts: []const u8,
    block_private: bool,
};

fn writeOrUpdateShadowsocksSection(
    allocator: std.mem.Allocator,
    path: []const u8,
    update: SsSectionUpdate,
) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const original = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(original);

    var new_content: std.ArrayList(u8) = .empty;
    defer new_content.deinit(allocator);

    const existing = findSectionRange(original, "[shadowsocks]");
    if (existing) |range| {
        try new_content.appendSlice(allocator, original[0..range.start]);
        try writeShadowsocksSection(allocator, &new_content, update);
        try new_content.appendSlice(allocator, original[range.end..]);
    } else {
        try new_content.appendSlice(allocator, original);
        if (original.len > 0 and original[original.len - 1] != '\n') {
            try new_content.append(allocator, '\n');
        }
        try new_content.append(allocator, '\n');
        try writeShadowsocksSection(allocator, &new_content, update);
    }

    try atomicWriteFile(allocator, path, new_content.items);
}

fn writeShadowsocksSection(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    update: SsSectionUpdate,
) !void {
    var line_buf: [4096]u8 = undefined;

    const header = "[shadowsocks]\n";
    try out.appendSlice(allocator, header);

    const enabled_line = try std.fmt.bufPrint(&line_buf, "enabled = true\n", .{});
    try out.appendSlice(allocator, enabled_line);

    const port_line = try std.fmt.bufPrint(&line_buf, "port = {d}\n", .{update.port});
    try out.appendSlice(allocator, port_line);

    const psk_line = try std.fmt.bufPrint(&line_buf, "psk = \"{s}\"\n", .{update.psk_b64});
    try out.appendSlice(allocator, psk_line);

    const hosts_line = try std.fmt.bufPrint(&line_buf, "allowed_hosts = \"{s}\"\n", .{update.allowed_hosts});
    try out.appendSlice(allocator, hosts_line);

    const private_line = try std.fmt.bufPrint(
        &line_buf,
        "block_private_networks = {s}\n",
        .{if (update.block_private) "true" else "false"},
    );
    try out.appendSlice(allocator, private_line);
}

fn setEnabledFlag(allocator: std.mem.Allocator, path: []const u8, enabled: bool) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const original = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(original);

    const range = findSectionRange(original, "[shadowsocks]") orelse return error.NoShadowsocksSection;

    var new_content: std.ArrayList(u8) = .empty;
    defer new_content.deinit(allocator);

    try new_content.appendSlice(allocator, original[0..range.start]);

    var section_lines = std.mem.splitScalar(u8, original[range.start..range.end], '\n');
    var first_line = true;
    while (section_lines.next()) |line| {
        if (!first_line) try new_content.append(allocator, '\n');
        first_line = false;

        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "enabled")) {
            try new_content.appendSlice(allocator, if (enabled) "enabled = true" else "enabled = false");
        } else {
            try new_content.appendSlice(allocator, line);
        }
    }

    try new_content.appendSlice(allocator, original[range.end..]);
    try atomicWriteFile(allocator, path, new_content.items);
}

const SectionRange = struct { start: usize, end: usize };

/// Find the byte range covering `header` and all of its key/value lines, up to
/// (but excluding) the next section header or EOF.
fn findSectionRange(content: []const u8, header: []const u8) ?SectionRange {
    const idx = std.mem.indexOf(u8, content, header) orelse return null;
    // Validate that `idx` is at the start of a line.
    if (idx > 0 and content[idx - 1] != '\n') return null;

    var end = idx + header.len;
    while (end < content.len) {
        const next_nl = std.mem.indexOfScalarPos(u8, content, end, '\n') orelse content.len;
        const line_start = end;
        const line = content[line_start..next_nl];
        const trimmed = std.mem.trim(u8, line, " \t\r");
        // Stop when we hit another section header.
        if (trimmed.len > 0 and trimmed[0] == '[') break;
        end = if (next_nl < content.len) next_nl + 1 else next_nl;
        if (next_nl == content.len) break;
    }
    return .{ .start = idx, .end = end };
}

fn atomicWriteFile(allocator: std.mem.Allocator, path: []const u8, data: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const io = std.Io.Threaded.global_single_threaded.io();
    const tmp_file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{ .mode = 0o600 });
    {
        defer tmp_file.close(io);
        var w = tmp_file.writer(io, &.{});
        try w.interface.writeAll(data);
        try w.interface.flush();
    }

    // Best effort: preserve perms of the existing file when present.
    // Atomic on POSIX: rename(2) replaces atomically within the same FS.
    try std.Io.Dir.cwd().rename(io, tmp_path, path);
}

// ═══ Tests ═══════════════════════════════════════════════════

test "findSectionRange: locates existing section" {
    const content =
        \\[server]
        \\port = 443
        \\
        \\[shadowsocks]
        \\enabled = true
        \\port = 8388
        \\
        \\[other]
        \\value = 1
    ;
    const range = findSectionRange(content, "[shadowsocks]").?;
    const slice = content[range.start..range.end];
    try std.testing.expect(std.mem.startsWith(u8, slice, "[shadowsocks]"));
    try std.testing.expect(std.mem.indexOf(u8, slice, "enabled = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, slice, "[other]") == null);
}

test "findSectionRange: returns null when section missing" {
    const content =
        \\[server]
        \\port = 443
    ;
    try std.testing.expect(findSectionRange(content, "[shadowsocks]") == null);
}

test "PSK base64 helpers: roundtrip" {
    var psk: [psk_len]u8 = undefined;
    for (0..psk_len) |i| psk[i] = @intCast(i);

    var b64_buf: [64]u8 = undefined;
    const b64 = encodePskBase64(&b64_buf, &psk);

    const decoded = decodePskBase64(b64) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, &psk, &decoded);
}

test "decodePskBase64: rejects wrong length" {
    const bad = [_]u8{0x42} ** 16;
    var b64_buf: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder;
    const b64 = enc.encode(b64_buf[0..enc.calcSize(bad.len)], &bad);
    try std.testing.expect(decodePskBase64(b64) == null);
}

test "findSectionRange: section at EOF without trailing newline" {
    const content =
        \\[server]
        \\port = 443
        \\[shadowsocks]
        \\enabled = false
    ;
    const range = findSectionRange(content, "[shadowsocks]").?;
    try std.testing.expectEqual(content.len, range.end);
}
