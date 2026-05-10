//! Host / address whitelist for the Shadowsocks listener.
//!
//! Two complementary checks:
//!   1. `Whitelist.allowsHostname(...)` — suffix match for client-supplied
//!      hostnames (`telegram.org` matches `cdn.telegram.org` but NOT
//!      `evil-telegram.org`).
//!   2. `isPrivateAddress(...)` — RFC1918 / link-local / loopback / ULA /
//!      multicast / unspecified, applied AFTER DNS resolution to prevent
//!      SSRF / lateral pivot when block_private = true.
//!
//! Both are pure / allocator-free.

const std = @import("std");
const net = std.Io.net;

// ─── Hostname suffix match ───────────────────────────────────

/// True when `host` matches `suffix` as a DNS suffix:
///   * exact match: `t.me` matches `t.me`
///   * subdomain:   `cdn.telegram.org` matches `telegram.org`
///   * NOT matched: `evil-telegram.org` against `telegram.org`
///
/// Comparison is case-insensitive (DNS labels are case-insensitive).
/// Empty suffixes never match (defensive — config layer rejects them).
pub fn isHostnameSuffixMatch(host: []const u8, suffix: []const u8) bool {
    if (suffix.len == 0) return false;
    if (host.len < suffix.len) return false;

    const tail_off = host.len - suffix.len;
    if (!std.ascii.eqlIgnoreCase(host[tail_off..], suffix)) return false;

    // Either exact match (tail starts at offset 0) or the byte just before
    // the tail must be a label boundary ('.').
    if (tail_off == 0) return true;
    return host[tail_off - 1] == '.';
}

/// Same as `isHostnameSuffixMatch` but checks against an array of suffixes.
pub fn isAllowedHostname(host: []const u8, suffixes: []const []const u8) bool {
    if (host.len == 0) return false;
    for (suffixes) |suffix| {
        if (isHostnameSuffixMatch(host, suffix)) return true;
    }
    return false;
}

// ─── Private network classification ──────────────────────────

/// True for IPv4 ranges that should never appear as a public CONNECT target.
pub fn isPrivateIpv4(b: [4]u8) bool {
    // 0.0.0.0/8 — "this network", current network, also includes 0.0.0.0
    if (b[0] == 0) return true;
    // 10.0.0.0/8 — RFC1918 private
    if (b[0] == 10) return true;
    // 100.64.0.0/10 — RFC6598 carrier-grade NAT
    if (b[0] == 100 and (b[1] & 0xC0) == 64) return true;
    // 127.0.0.0/8 — loopback
    if (b[0] == 127) return true;
    // 169.254.0.0/16 — link-local
    if (b[0] == 169 and b[1] == 254) return true;
    // 172.16.0.0/12 — RFC1918 private
    if (b[0] == 172 and (b[1] & 0xF0) == 16) return true;
    // 192.0.0.0/24 — IETF protocol assignments
    if (b[0] == 192 and b[1] == 0 and b[2] == 0) return true;
    // 192.0.2.0/24 — TEST-NET-1 (RFC5737)
    if (b[0] == 192 and b[1] == 0 and b[2] == 2) return true;
    // 192.168.0.0/16 — RFC1918 private
    if (b[0] == 192 and b[1] == 168) return true;
    // 198.18.0.0/15 — Network Interconnect Device Benchmark Testing
    if (b[0] == 198 and (b[1] & 0xFE) == 18) return true;
    // 198.51.100.0/24 — TEST-NET-2 (RFC5737)
    if (b[0] == 198 and b[1] == 51 and b[2] == 100) return true;
    // 203.0.113.0/24 — TEST-NET-3 (RFC5737)
    if (b[0] == 203 and b[1] == 0 and b[2] == 113) return true;
    // 224.0.0.0/4 — multicast
    if ((b[0] & 0xF0) == 224) return true;
    // 240.0.0.0/4 — reserved (includes 255.255.255.255 broadcast)
    if ((b[0] & 0xF0) == 240) return true;
    return false;
}

/// True for IPv6 ranges that should never appear as a public CONNECT target.
pub fn isPrivateIpv6(b: [16]u8) bool {
    // :: (unspecified)
    if (std.mem.allEqual(u8, &b, 0)) return true;

    // ::1 (loopback)
    var loopback: [16]u8 = [_]u8{0} ** 16;
    loopback[15] = 1;
    if (std.mem.eql(u8, &b, &loopback)) return true;

    // ::ffff:0:0/96 — IPv4-mapped — recurse into the embedded v4 octets.
    if (std.mem.eql(u8, b[0..10], &[_]u8{0} ** 10) and b[10] == 0xff and b[11] == 0xff) {
        return isPrivateIpv4(.{ b[12], b[13], b[14], b[15] });
    }

    // 64:ff9b::/96 — NAT64 well-known prefix; treat as transparent and
    // re-classify the embedded v4 portion.
    if (b[0] == 0x00 and b[1] == 0x64 and b[2] == 0xff and b[3] == 0x9b and
        std.mem.allEqual(u8, b[4..12], 0))
    {
        return isPrivateIpv4(.{ b[12], b[13], b[14], b[15] });
    }

    // fc00::/7 — Unique Local Addresses (RFC4193)
    if ((b[0] & 0xFE) == 0xFC) return true;

    // fe80::/10 — link-local (RFC4291)
    if (b[0] == 0xFE and (b[1] & 0xC0) == 0x80) return true;

    // ff00::/8 — multicast
    if (b[0] == 0xFF) return true;

    // 2001:db8::/32 — documentation prefix (RFC3849)
    if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x0D and b[3] == 0xB8) return true;

    // 100::/64 — discard prefix (RFC6666)
    if (b[0] == 0x01 and b[1] == 0x00 and std.mem.allEqual(u8, b[2..8], 0)) return true;

    return false;
}

/// True when an `IpAddress` falls into any private / non-routable range.
pub fn isPrivateAddress(addr: net.IpAddress) bool {
    return switch (addr) {
        .ip4 => |a| isPrivateIpv4(a.bytes),
        .ip6 => |a| isPrivateIpv6(a.bytes),
    };
}

/// Try to parse `host` as an IP literal. Returns the parsed address or null.
pub fn parseIpLiteral(host: []const u8) ?net.IpAddress {
    return net.IpAddress.parse(host, 0) catch null;
}

// ─── Whitelist policy aggregate ──────────────────────────────

pub const Decision = enum {
    /// Host is permitted by the policy and the runtime check.
    allowed,
    /// Hostname doesn't match any suffix in `allowed_hosts`.
    not_in_whitelist,
    /// Resolved (or literal) address falls in a private range.
    private_network,
    /// Empty / malformed input.
    invalid,
};

/// Configured policy. `allowed_hosts` slices are borrowed; their lifetime
/// must outlive the `Policy` value.
pub const Policy = struct {
    allowed_hosts: []const []const u8,
    block_private: bool,

    /// Check a client-supplied host string before DNS resolution.
    /// IP literals are pre-checked against `block_private` here too,
    /// so we can short-circuit before any allocation / lookup.
    pub fn checkClientHost(self: *const Policy, host: []const u8) Decision {
        if (host.len == 0) return .invalid;

        if (parseIpLiteral(host)) |addr| {
            if (self.block_private and isPrivateAddress(addr)) return .private_network;
            // IP literals bypass the suffix whitelist on purpose: they would
            // never match `telegram.org` style entries. If you want to deny
            // arbitrary IP literals entirely, set `allowed_hosts` containing
            // only DNS suffixes and rely on this branch returning .allowed
            // ONLY for the IPs we explicitly permit. We instead require an
            // explicit override for non-private IP literals.
            return .not_in_whitelist;
        }

        if (!isAllowedHostname(host, self.allowed_hosts)) return .not_in_whitelist;
        return .allowed;
    }

    /// Check a freshly resolved address (post-DNS).
    pub fn checkResolvedAddress(self: *const Policy, addr: net.IpAddress) Decision {
        if (self.block_private and isPrivateAddress(addr)) return .private_network;
        return .allowed;
    }
};

// ═══ Tests ═══════════════════════════════════════════════════

test "suffix match: exact" {
    try std.testing.expect(isHostnameSuffixMatch("t.me", "t.me"));
}

test "suffix match: subdomain" {
    try std.testing.expect(isHostnameSuffixMatch("cdn.telegram.org", "telegram.org"));
    try std.testing.expect(isHostnameSuffixMatch("a.b.c.telegram.org", "telegram.org"));
}

test "suffix match: case insensitive" {
    try std.testing.expect(isHostnameSuffixMatch("CDN.Telegram.ORG", "telegram.org"));
    try std.testing.expect(isHostnameSuffixMatch("cdn.telegram.org", "TELEGRAM.ORG"));
}

test "suffix match: rejects partial label" {
    // The bug we MUST never have: "evil-telegram.org" matching "telegram.org".
    try std.testing.expect(!isHostnameSuffixMatch("evil-telegram.org", "telegram.org"));
    try std.testing.expect(!isHostnameSuffixMatch("nottelegram.org", "telegram.org"));
    try std.testing.expect(!isHostnameSuffixMatch("xtelegram.org", "telegram.org"));
}

test "suffix match: short host" {
    try std.testing.expect(!isHostnameSuffixMatch("me", "t.me"));
    try std.testing.expect(!isHostnameSuffixMatch("", "t.me"));
}

test "suffix match: empty suffix" {
    try std.testing.expect(!isHostnameSuffixMatch("t.me", ""));
}

test "isAllowedHostname: matches one of many" {
    const list = [_][]const u8{ "t.me", "telegram.org", "fragment.com" };
    try std.testing.expect(isAllowedHostname("cdn.telegram.org", &list));
    try std.testing.expect(isAllowedHostname("t.me", &list));
    try std.testing.expect(isAllowedHostname("FRAGMENT.com", &list));
    try std.testing.expect(!isAllowedHostname("evil.com", &list));
}

test "private ipv4: RFC1918 + loopback + link-local" {
    try std.testing.expect(isPrivateIpv4(.{ 10, 0, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 192, 168, 1, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 172, 16, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 172, 31, 255, 255 }));
    try std.testing.expect(!isPrivateIpv4(.{ 172, 32, 0, 1 })); // outside /12
    try std.testing.expect(isPrivateIpv4(.{ 127, 0, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 169, 254, 0, 1 }));
}

test "private ipv4: CGNAT + multicast + reserved" {
    try std.testing.expect(isPrivateIpv4(.{ 100, 64, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 100, 127, 255, 255 }));
    try std.testing.expect(!isPrivateIpv4(.{ 100, 128, 0, 1 })); // outside /10
    try std.testing.expect(isPrivateIpv4(.{ 224, 0, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 239, 255, 255, 255 }));
    try std.testing.expect(isPrivateIpv4(.{ 240, 0, 0, 1 }));
    try std.testing.expect(isPrivateIpv4(.{ 255, 255, 255, 255 })); // broadcast
}

test "private ipv4: 0.0.0.0/8" {
    try std.testing.expect(isPrivateIpv4(.{ 0, 0, 0, 0 }));
    try std.testing.expect(isPrivateIpv4(.{ 0, 1, 2, 3 }));
}

test "private ipv4: public addresses pass" {
    try std.testing.expect(!isPrivateIpv4(.{ 1, 1, 1, 1 }));
    try std.testing.expect(!isPrivateIpv4(.{ 8, 8, 8, 8 }));
    try std.testing.expect(!isPrivateIpv4(.{ 149, 154, 175, 50 })); // Telegram DC1
    try std.testing.expect(!isPrivateIpv4(.{ 91, 108, 56, 170 }));
}

test "private ipv6: standard ranges" {
    var loopback: [16]u8 = [_]u8{0} ** 16;
    loopback[15] = 1;
    try std.testing.expect(isPrivateIpv6(loopback));

    try std.testing.expect(isPrivateIpv6([_]u8{0} ** 16)); // unspecified

    // fe80::1 — link-local
    var ll: [16]u8 = [_]u8{0} ** 16;
    ll[0] = 0xFE;
    ll[1] = 0x80;
    ll[15] = 1;
    try std.testing.expect(isPrivateIpv6(ll));

    // fc00::1 — ULA
    var ula: [16]u8 = [_]u8{0} ** 16;
    ula[0] = 0xFC;
    ula[15] = 1;
    try std.testing.expect(isPrivateIpv6(ula));

    // fd00::1 — ULA (top byte 0xFD also matches /7)
    var ula2: [16]u8 = [_]u8{0} ** 16;
    ula2[0] = 0xFD;
    try std.testing.expect(isPrivateIpv6(ula2));

    // ff02::1 — multicast
    var mc: [16]u8 = [_]u8{0} ** 16;
    mc[0] = 0xFF;
    mc[1] = 0x02;
    mc[15] = 1;
    try std.testing.expect(isPrivateIpv6(mc));
}

test "private ipv6: ipv4-mapped recurses into v4 logic" {
    // ::ffff:127.0.0.1 -> private
    var v4mapped: [16]u8 = [_]u8{0} ** 16;
    v4mapped[10] = 0xff;
    v4mapped[11] = 0xff;
    v4mapped[12] = 127;
    v4mapped[13] = 0;
    v4mapped[14] = 0;
    v4mapped[15] = 1;
    try std.testing.expect(isPrivateIpv6(v4mapped));

    // ::ffff:8.8.8.8 -> public
    v4mapped[12] = 8;
    v4mapped[13] = 8;
    v4mapped[14] = 8;
    v4mapped[15] = 8;
    try std.testing.expect(!isPrivateIpv6(v4mapped));
}

test "private ipv6: public address" {
    // 2606:4700:4700::1111 (Cloudflare)
    var cf: [16]u8 = [_]u8{0} ** 16;
    cf[0] = 0x26;
    cf[1] = 0x06;
    cf[2] = 0x47;
    cf[3] = 0x00;
    cf[4] = 0x47;
    cf[5] = 0x00;
    cf[14] = 0x11;
    cf[15] = 0x11;
    try std.testing.expect(!isPrivateIpv6(cf));
}

test "Policy: hostname allowed by suffix" {
    const allowed = [_][]const u8{ "telegram.org", "t.me" };
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = true };
    try std.testing.expectEqual(Decision.allowed, policy.checkClientHost("cdn.telegram.org"));
    try std.testing.expectEqual(Decision.allowed, policy.checkClientHost("t.me"));
    try std.testing.expectEqual(Decision.not_in_whitelist, policy.checkClientHost("evil.com"));
}

test "Policy: ip literal blocked when private" {
    const allowed = [_][]const u8{"telegram.org"};
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = true };
    try std.testing.expectEqual(Decision.private_network, policy.checkClientHost("127.0.0.1"));
    try std.testing.expectEqual(Decision.private_network, policy.checkClientHost("192.168.1.1"));
    // SS-2022 SOCKS5 conveys IPv6 as 16 raw bytes; bracket-form is never
    // received by us. Test bare literals only.
    try std.testing.expectEqual(Decision.private_network, policy.checkClientHost("::1"));
    try std.testing.expectEqual(Decision.private_network, policy.checkClientHost("fe80::1"));
}

test "Policy: ip literal not in whitelist when public" {
    const allowed = [_][]const u8{"telegram.org"};
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = true };
    // Public IP literal: not blocked as private, but also not whitelisted.
    try std.testing.expectEqual(Decision.not_in_whitelist, policy.checkClientHost("1.1.1.1"));
}

test "Policy: empty host rejected" {
    const allowed = [_][]const u8{"telegram.org"};
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = true };
    try std.testing.expectEqual(Decision.invalid, policy.checkClientHost(""));
}

test "Policy: checkResolvedAddress blocks private when configured" {
    const allowed = [_][]const u8{"telegram.org"};
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = true };

    const private_v4 = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 443 } };
    try std.testing.expectEqual(Decision.private_network, policy.checkResolvedAddress(private_v4));

    const public_v4 = net.IpAddress{ .ip4 = .{ .bytes = .{ 149, 154, 175, 50 }, .port = 443 } };
    try std.testing.expectEqual(Decision.allowed, policy.checkResolvedAddress(public_v4));
}

test "Policy: block_private = false skips private check" {
    const allowed = [_][]const u8{"telegram.org"};
    const policy = Policy{ .allowed_hosts = &allowed, .block_private = false };
    const private_v4 = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 443 } };
    try std.testing.expectEqual(Decision.allowed, policy.checkResolvedAddress(private_v4));
}
