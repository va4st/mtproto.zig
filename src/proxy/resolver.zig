//! DNS resolver for the Shadowsocks listener.
//!
//! Wraps `net_helpers.getAddressList` with a small TTL'd LRU-style cache
//! to avoid re-resolving the same hostname under load. Synchronous —
//! getaddrinfo is invoked on the calling thread, which means the event
//! loop blocks for the duration of the underlying lookup.
//!
//! That trade-off is acceptable for the SS path because:
//!   * SS sessions are long-lived (a single TCP connection serves many
//!     HTTP requests via keep-alive) so the lookup amortises well.
//!   * A 256-entry cache keyed by `host:port` covers the common case of
//!     a few popular Telegram domains (`t.me`, `fragment.com`, ...).
//!   * Negative results are also cached briefly to absorb DPI poisoning
//!     bursts.
//!
//! When this becomes a bottleneck, swap the body of `resolve()` for an
//! eventfd-driven thread pool — the public API is designed to support
//! that without callers changing.

const std = @import("std");
const net = std.Io.net;
const posix = std.posix;
const net_helpers = @import("net_helpers.zig");
const crypto = @import("../crypto/crypto.zig");

pub const positive_ttl_seconds: i64 = 300;
pub const negative_ttl_seconds: i64 = 30;
pub const max_addresses_per_host: usize = 8;
pub const cache_capacity: usize = 256;
pub const max_hostname_len: usize = 255;

fn nowSeconds() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

pub const ResolveError = error{
    NameTooLong,
    /// Authoritative negative — the resolver returned no addresses or a
    /// recent negative cache entry is still fresh.
    NotFound,
};

pub const Resolved = struct {
    /// Number of addresses actually populated in `addrs`.
    count: u8,
    addrs: [max_addresses_per_host]net.IpAddress,

    pub fn slice(self: *const Resolved) []const net.IpAddress {
        return self.addrs[0..self.count];
    }
};

const Entry = struct {
    used: bool = false,
    /// Inserted-at timestamp (MONOTONIC seconds).
    inserted_s: i64 = 0,
    /// Last-touched timestamp; used for LRU-ish eviction.
    last_touched_s: i64 = 0,
    /// Lowercased hostname stored inline (no allocation per entry).
    host_len: u8 = 0,
    host_buf: [max_hostname_len]u8 = undefined,
    /// Port keyed alongside the host so different ports cache independently.
    port: u16 = 0,
    /// Negative cache entry: `count == 0` and `inserted_s` valid.
    count: u8 = 0,
    addrs: [max_addresses_per_host]net.IpAddress = undefined,

    fn matches(self: *const Entry, host_lower: []const u8, port: u16) bool {
        return self.used and self.port == port and
            self.host_len == host_lower.len and
            std.mem.eql(u8, self.host_buf[0..self.host_len], host_lower);
    }
};

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    entries: [cache_capacity]Entry = [_]Entry{.{}} ** cache_capacity,

    pub fn init(allocator: std.mem.Allocator) Resolver {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Resolver) void {
        _ = self;
    }

    /// Lookup `host:port`. Returns a value type (no allocation across the API
    /// boundary). Repeated calls within `positive_ttl_seconds` are served
    /// from cache without touching getaddrinfo.
    pub fn resolve(self: *Resolver, host: []const u8, port: u16) ResolveError!Resolved {
        if (host.len == 0 or host.len > max_hostname_len) return error.NameTooLong;

        var lower_buf: [max_hostname_len]u8 = undefined;
        const host_lower = std.ascii.lowerString(lower_buf[0..host.len], host);

        const now_s = nowSeconds();

        if (self.lookup(host_lower, port, now_s)) |hit| {
            if (hit.count == 0) return error.NotFound;
            var out = Resolved{ .count = hit.count, .addrs = undefined };
            for (0..hit.count) |i| out.addrs[i] = withPort(hit.addrs[i], port);
            return out;
        }

        // Cache miss — perform the actual lookup.
        const list_result = net_helpers.getAddressList(self.allocator, host, port);
        if (list_result) |list| {
            defer list.deinit();
            const cap = @min(list.addrs.len, max_addresses_per_host);
            if (cap == 0) {
                self.insertNegative(host_lower, port, now_s);
                return error.NotFound;
            }
            var entry_addrs: [max_addresses_per_host]net.IpAddress = undefined;
            for (0..cap) |i| entry_addrs[i] = list.addrs[i];
            self.insertPositive(host_lower, port, now_s, entry_addrs[0..cap]);

            var out = Resolved{ .count = @intCast(cap), .addrs = undefined };
            for (0..cap) |i| out.addrs[i] = withPort(entry_addrs[i], port);
            return out;
        } else |_| {
            self.insertNegative(host_lower, port, now_s);
            return error.NotFound;
        }
    }

    fn lookup(self: *Resolver, host_lower: []const u8, port: u16, now_s: i64) ?*Entry {
        for (&self.entries) |*e| {
            if (!e.matches(host_lower, port)) continue;
            const ttl: i64 = if (e.count == 0) negative_ttl_seconds else positive_ttl_seconds;
            if (now_s - e.inserted_s > ttl) {
                e.used = false;
                return null;
            }
            e.last_touched_s = now_s;
            return e;
        }
        return null;
    }

    fn insertPositive(
        self: *Resolver,
        host_lower: []const u8,
        port: u16,
        now_s: i64,
        addrs: []const net.IpAddress,
    ) void {
        const slot = self.acquireSlot(now_s);
        slot.* = .{
            .used = true,
            .inserted_s = now_s,
            .last_touched_s = now_s,
            .host_len = @intCast(host_lower.len),
            .port = port,
            .count = @intCast(addrs.len),
        };
        @memcpy(slot.host_buf[0..host_lower.len], host_lower);
        for (0..addrs.len) |i| slot.addrs[i] = addrs[i];
    }

    fn insertNegative(self: *Resolver, host_lower: []const u8, port: u16, now_s: i64) void {
        const slot = self.acquireSlot(now_s);
        slot.* = .{
            .used = true,
            .inserted_s = now_s,
            .last_touched_s = now_s,
            .host_len = @intCast(host_lower.len),
            .port = port,
            .count = 0,
        };
        @memcpy(slot.host_buf[0..host_lower.len], host_lower);
    }

    fn acquireSlot(self: *Resolver, now_s: i64) *Entry {
        // Prefer an unused slot.
        for (&self.entries) |*e| {
            if (!e.used) return e;
        }
        // Then the freshest stale entry — anything past its TTL is fair game.
        for (&self.entries) |*e| {
            const ttl: i64 = if (e.count == 0) negative_ttl_seconds else positive_ttl_seconds;
            if (now_s - e.inserted_s > ttl) return e;
        }
        // Otherwise evict least-recently-touched.
        var oldest: *Entry = &self.entries[0];
        for (&self.entries) |*e| {
            if (e.last_touched_s < oldest.last_touched_s) oldest = e;
        }
        return oldest;
    }
};

fn withPort(addr: net.IpAddress, port: u16) net.IpAddress {
    return switch (addr) {
        .ip4 => |a| .{ .ip4 = .{ .bytes = a.bytes, .port = port } },
        .ip6 => |a| .{ .ip6 = .{
            .bytes = a.bytes,
            .port = port,
            .flow = a.flow,
            .interface = a.interface,
        } },
    };
}

// ═══ Tests ═══════════════════════════════════════════════════
//
// These are pure cache/state tests — they never hit getaddrinfo. We exercise
// the slot machinery directly by inserting synthetic entries and checking
// that lookup honours TTL, case folding, and port keying.

test "resolver: positive cache returns inserted address with new port" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();

    var lower_buf: [max_hostname_len]u8 = undefined;
    const host = "telegram.org";
    const lower = std.ascii.lowerString(lower_buf[0..host.len], host);

    var addrs: [max_addresses_per_host]net.IpAddress = undefined;
    addrs[0] = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 0 } };
    r.insertPositive(lower, 443, nowSeconds(), addrs[0..1]);

    const result = try r.resolve("Telegram.ORG", 443);
    try std.testing.expectEqual(@as(u8, 1), result.count);
    switch (result.addrs[0]) {
        .ip4 => |a| {
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &a.bytes);
            try std.testing.expectEqual(@as(u16, 443), a.port);
        },
        else => try std.testing.expect(false),
    }
}

test "resolver: different ports cache independently" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();

    var lower_buf: [max_hostname_len]u8 = undefined;
    const host = "fragment.com";
    const lower = std.ascii.lowerString(lower_buf[0..host.len], host);

    var addrs: [max_addresses_per_host]net.IpAddress = undefined;
    addrs[0] = .{ .ip4 = .{ .bytes = .{ 5, 6, 7, 8 }, .port = 0 } };
    r.insertPositive(lower, 443, nowSeconds(), addrs[0..1]);

    // Port 80 isn't cached — lookup against port 80 should miss the
    // synthetic entry. We can only verify miss by either checking that
    // the underlying real DNS path runs (we don't want to in tests) or by
    // inspecting cache state directly.
    const e443 = r.lookup("fragment.com", 443, nowSeconds());
    const e80 = r.lookup("fragment.com", 80, nowSeconds());
    try std.testing.expect(e443 != null);
    try std.testing.expect(e80 == null);
}

test "resolver: negative cache returned as NotFound" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();

    var lower_buf: [max_hostname_len]u8 = undefined;
    const host = "nope.invalid";
    const lower = std.ascii.lowerString(lower_buf[0..host.len], host);
    r.insertNegative(lower, 443, nowSeconds());

    try std.testing.expectError(error.NotFound, r.resolve("nope.invalid", 443));
}

test "resolver: positive entry expires after TTL" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();

    var lower_buf: [max_hostname_len]u8 = undefined;
    const host = "expiring.example";
    const lower = std.ascii.lowerString(lower_buf[0..host.len], host);

    var addrs: [max_addresses_per_host]net.IpAddress = undefined;
    addrs[0] = .{ .ip4 = .{ .bytes = .{ 9, 9, 9, 9 }, .port = 0 } };
    const inserted_at = nowSeconds() - positive_ttl_seconds - 1;
    r.insertPositive(lower, 443, inserted_at, addrs[0..1]);
    // Manually backdate the entry to simulate elapsed TTL.
    for (&r.entries) |*e| {
        if (e.matches(lower, 443)) {
            e.inserted_s = inserted_at;
        }
    }

    const hit = r.lookup(lower, 443, nowSeconds());
    try std.testing.expect(hit == null);
}

test "resolver: NameTooLong on empty or oversized host" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    try std.testing.expectError(error.NameTooLong, r.resolve("", 443));

    var huge: [256]u8 = undefined;
    @memset(&huge, 'a');
    try std.testing.expectError(error.NameTooLong, r.resolve(&huge, 443));
}

test "resolver: eviction prefers unused slots" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();

    var lower_buf: [max_hostname_len]u8 = undefined;
    const host = "first.example";
    const lower = std.ascii.lowerString(lower_buf[0..host.len], host);

    const now = nowSeconds();
    var addrs: [max_addresses_per_host]net.IpAddress = undefined;
    addrs[0] = .{ .ip4 = .{ .bytes = .{ 1, 1, 1, 1 }, .port = 0 } };
    r.insertPositive(lower, 443, now, addrs[0..1]);

    // The first slot (index 0) was filled, so the next slot acquired must
    // be a different unused one (index 1+), not an eviction.
    try std.testing.expect(r.entries[0].used);
    const slot = r.acquireSlot(now);
    try std.testing.expect(slot != &r.entries[0]);
    try std.testing.expect(!slot.used);
}

test "resolver: withPort overrides port for v4 and v6" {
    const v4: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 80 } };
    const v4_443 = withPort(v4, 443);
    try std.testing.expectEqual(@as(u16, 443), v4_443.ip4.port);

    const v6: net.IpAddress = .{ .ip6 = .{
        .bytes = [_]u8{0} ** 16,
        .port = 80,
        .flow = 0,
        .interface = .{ .index = 0 },
    } };
    const v6_443 = withPort(v6, 443);
    try std.testing.expectEqual(@as(u16, 443), v6_443.ip6.port);
}
