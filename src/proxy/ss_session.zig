//! Per-connection state machine for the Shadowsocks-2022 listener.
//!
//! Lazily heap-allocated so MTProto sessions pay no extra memory for the
//! SS-only buffers (~32 KB per session: 16 KB ingress + 16 KB egress staging).
//!
//! The state machine is fed encrypted client bytes via `feedClient` and
//! produces one of:
//!   * `.need_more`            — keep reading
//!   * `.target_ready`         — variable header parsed, ready to resolve
//!                               + initial payload (may be empty) is buffered
//!   * `.payload`              — a chunk of decrypted client -> server bytes
//!                               that the caller should forward upstream
//!   * `.error_close`          — fatal protocol error; close the session
//!
//! Outgoing (server -> client) flow is driven by `wrapForClient`, which the
//! caller invokes with raw plaintext bytes coming from the upstream socket.
//! The session prepends server salt + fixed response header on first call.

const std = @import("std");
const ss = @import("../protocol/shadowsocks.zig");

pub const max_data_chunk: usize = ss.max_chunk_size; // 16383
pub const max_data_ciphertext: usize = max_data_chunk + ss.tag_len; // 16399
pub const max_var_header_size: usize = ss.max_chunk_size; // 16383
pub const max_in_buf_size: usize = max_data_ciphertext;

pub const Phase = enum {
    reading_salt,
    reading_fixed_header,
    reading_var_header,
    /// Variable header parsed; awaiting `markUpstreamConnected()` before
    /// streaming any further data.
    waiting_upstream,
    /// Bidirectional relay: alternating length / payload chunks.
    relaying,
    failed,
};

pub const FeedEvent = union(enum) {
    /// Need more bytes from the wire to make progress.
    need_more: void,
    /// Target host parsed; caller must resolve and connect upstream, then
    /// call `consumeInitialPayload()` to drain the buffered payload.
    target_ready: void,
    /// New plaintext bytes ready to be forwarded upstream.
    payload: []const u8,
    /// Fatal protocol error — close the session.
    error_close: anyerror,
};

const ChunkKind = enum { length, data };

pub const Session = struct {
    psk: [ss.psk_len]u8,
    phase: Phase,

    // ── Ingress (client -> server) ─────────────────────────────
    /// Bytes received from the client, accumulated until a full chunk is
    /// available. Sized for the worst-case data ciphertext.
    in_buf: [max_in_buf_size]u8 = undefined,
    in_have: usize = 0,
    in_need: usize,

    /// Working ciphertext for the relay loop (alternating length / data).
    next_chunk_kind: ChunkKind = .length,
    next_payload_size: u16 = 0,

    /// Decrypted-but-not-yet-flushed plaintext (variable header + relay data).
    /// Borrowed by the FeedEvent.payload variant.
    plaintext_scratch: [max_data_chunk]u8 = undefined,

    request_salt: [ss.salt_len]u8 = undefined,
    request_cipher: ?ss.ChunkCipher = null,
    request_timestamp: i64 = 0,

    // ── Egress (server -> client) ──────────────────────────────
    response_salt: [ss.salt_len]u8 = undefined,
    response_cipher: ?ss.ChunkCipher = null,
    response_header_sent: bool = false,

    // ── Parsed target ──────────────────────────────────────────
    /// Lowercased target hostname (from SOCKS5-style address).
    target_host_buf: [255]u8 = undefined,
    target_host_len: u8 = 0,
    target_port: u16 = 0,
    /// True when the SOCKS5 atyp was `domain` (resolver needed).
    target_is_hostname: bool = false,
    /// Pre-resolved target when atyp was IPv4 / IPv6.
    target_ip_v4: ?[4]u8 = null,
    target_ip_v6: ?[16]u8 = null,

    /// Initial payload that came inline with the variable header. Owned —
    /// consumed by the relay layer via `takeInitialPayload`.
    initial_payload: ?[]u8 = null,
    /// Allocator for the optional `initial_payload` buffer.
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, psk: *const [ss.psk_len]u8) Session {
        return .{
            .psk = psk.*,
            .phase = .reading_salt,
            .in_need = ss.salt_len,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.request_cipher) |*c| c.wipe();
        if (self.response_cipher) |*c| c.wipe();
        if (self.initial_payload) |buf| self.allocator.free(buf);
        std.crypto.secureZero(u8, &self.psk);
    }

    /// Append `data` into the ingress buffer up to the current chunk's
    /// `in_need` boundary. Returns the number of bytes consumed.
    pub fn appendIngress(self: *Session, data: []const u8) usize {
        const room = self.in_need - self.in_have;
        const take = @min(room, data.len);
        if (take == 0) return 0;
        @memcpy(self.in_buf[self.in_have .. self.in_have + take], data[0..take]);
        self.in_have += take;
        return take;
    }

    /// Drive the state machine forward; call after `appendIngress` until it
    /// returns `.need_more` or a non-progressable event.
    pub fn step(self: *Session, now_unix: i64) FeedEvent {
        switch (self.phase) {
            .reading_salt => {
                if (self.in_have < self.in_need) return .need_more;
                @memcpy(&self.request_salt, self.in_buf[0..ss.salt_len]);
                const session_key = ss.deriveSessionKey(&self.psk, &self.request_salt);
                self.request_cipher = ss.ChunkCipher.init(&session_key);
                self.in_have = 0;
                self.in_need = ss.fixed_request_header_size;
                self.phase = .reading_fixed_header;
                return .need_more;
            },

            .reading_fixed_header => {
                if (self.in_have < self.in_need) return .need_more;
                var pt: [ss.fixed_request_header_pt_len]u8 = undefined;
                self.request_cipher.?.open(&pt, self.in_buf[0..ss.fixed_request_header_size]) catch |err| {
                    self.phase = .failed;
                    return .{ .error_close = err };
                };
                const fixed = ss.decodeFixedRequestHeader(&pt);
                ss.validateFixedRequestHeader(fixed, now_unix) catch |err| {
                    self.phase = .failed;
                    return .{ .error_close = err };
                };
                self.request_timestamp = fixed.timestamp;
                self.in_have = 0;
                self.in_need = @as(usize, fixed.var_header_len) + ss.tag_len;
                self.phase = .reading_var_header;
                return .need_more;
            },

            .reading_var_header => {
                if (self.in_have < self.in_need) return .need_more;
                const var_pt_len = self.in_need - ss.tag_len;
                if (var_pt_len > self.plaintext_scratch.len) {
                    self.phase = .failed;
                    return .{ .error_close = error.VarHeaderTooLarge };
                }
                const pt = self.plaintext_scratch[0..var_pt_len];
                self.request_cipher.?.open(pt, self.in_buf[0..self.in_need]) catch |err| {
                    self.phase = .failed;
                    return .{ .error_close = err };
                };
                const parsed = ss.parseVariableRequestHeader(pt) catch |err| {
                    self.phase = .failed;
                    return .{ .error_close = err };
                };
                self.captureTarget(parsed.addr) catch |err| {
                    self.phase = .failed;
                    return .{ .error_close = err };
                };
                if (parsed.initial_payload.len > 0) {
                    const buf = self.allocator.alloc(u8, parsed.initial_payload.len) catch |err| {
                        self.phase = .failed;
                        return .{ .error_close = err };
                    };
                    @memcpy(buf, parsed.initial_payload);
                    self.initial_payload = buf;
                }
                self.in_have = 0;
                self.in_need = ss.length_chunk_size;
                self.next_chunk_kind = .length;
                self.phase = .waiting_upstream;
                return .target_ready;
            },

            .waiting_upstream => return .need_more,

            .relaying => {
                if (self.in_have < self.in_need) return .need_more;
                switch (self.next_chunk_kind) {
                    .length => {
                        const len = ss.openLength(
                            &self.request_cipher.?,
                            self.in_buf[0..ss.length_chunk_size],
                        ) catch |err| {
                            self.phase = .failed;
                            return .{ .error_close = err };
                        };
                        self.next_payload_size = len;
                        self.in_have = 0;
                        self.in_need = @as(usize, len) + ss.tag_len;
                        self.next_chunk_kind = .data;
                        return .need_more;
                    },
                    .data => {
                        const pt_len = self.in_need - ss.tag_len;
                        const pt = self.plaintext_scratch[0..pt_len];
                        self.request_cipher.?.open(pt, self.in_buf[0..self.in_need]) catch |err| {
                            self.phase = .failed;
                            return .{ .error_close = err };
                        };
                        self.in_have = 0;
                        self.in_need = ss.length_chunk_size;
                        self.next_chunk_kind = .length;
                        return .{ .payload = pt };
                    },
                }
            },

            .failed => return .{ .error_close = error.SessionFailed },
        }
    }

    /// Take ownership of the variable-header initial payload (may be empty).
    /// Caller becomes responsible for freeing the returned buffer.
    pub fn takeInitialPayload(self: *Session) ?[]u8 {
        const buf = self.initial_payload;
        self.initial_payload = null;
        return buf;
    }

    /// Called by the listener after the upstream socket is connected and ready
    /// to accept writes. Initialises the response cipher with a freshly-rolled
    /// salt and transitions into the relay phase.
    pub fn markUpstreamConnected(self: *Session) void {
        std.debug.assert(self.phase == .waiting_upstream);
        ss.generateSalt(&self.response_salt);
        const response_key = ss.deriveSessionKey(&self.psk, &self.response_salt);
        self.response_cipher = ss.ChunkCipher.init(&response_key);
        self.phase = .relaying;
    }

    pub fn isRelaying(self: *const Session) bool {
        return self.phase == .relaying;
    }

    /// Worst-case ciphertext size produced by `wrapForClient` for `pt_len`
    /// plaintext bytes WHEN `response_header_sent == true`. Each chunk costs
    /// 18 bytes for the length chunk plus 16 bytes of GCM tag.
    pub fn wrapBoundSubsequent(pt_len: usize) usize {
        const chunks = (pt_len + max_data_chunk - 1) / max_data_chunk;
        return chunks * (ss.length_chunk_size + ss.tag_len) + pt_len;
    }

    /// Worst-case ciphertext size for the very first response (response salt
    /// + encrypted fixed header + first payload chunk, which omits its own
    /// length chunk).
    pub fn wrapBoundFirst(pt_len: usize) usize {
        return ss.salt_len + ss.fixed_response_header_size + pt_len + ss.tag_len;
    }

    /// Serialize the response salt + encrypted fixed response header + the
    /// first payload chunk. Subsequent calls (`response_header_sent == true`)
    /// only emit length / data chunks.
    ///
    /// `out` must be at least:
    ///   first call: `salt_len + fixed_response_header_size + length_chunk_size + tag_len + pt.len`
    ///   later calls: `length_chunk_size + tag_len + pt.len`
    /// (assuming `pt.len <= max_data_chunk`).
    ///
    /// Returns the slice of `out` that was written.
    pub fn wrapForClient(self: *Session, out: []u8, pt: []const u8, now_unix: i64) ![]u8 {
        std.debug.assert(self.response_cipher != null);
        if (pt.len > max_data_chunk) return error.PayloadTooLarge;
        if (pt.len == 0 and self.response_header_sent) return out[0..0];

        var off: usize = 0;
        if (!self.response_header_sent) {
            const need = ss.salt_len + ss.fixed_response_header_size + ss.length_chunk_size + ss.tag_len + pt.len;
            if (out.len < need) return error.OutputTooSmall;

            @memcpy(out[off..][0..ss.salt_len], &self.response_salt);
            off += ss.salt_len;

            var header_pt: [ss.fixed_response_header_pt_len]u8 = undefined;
            ss.encodeFixedResponseHeader(&header_pt, now_unix, &self.request_salt, @intCast(pt.len));
            self.response_cipher.?.seal(out[off..][0..ss.fixed_response_header_size], &header_pt);
            off += ss.fixed_response_header_size;

            self.response_header_sent = true;
        } else {
            const need = ss.length_chunk_size + ss.tag_len + pt.len;
            if (out.len < need) return error.OutputTooSmall;

            var len_chunk: [ss.length_chunk_size]u8 = undefined;
            ss.sealLength(&self.response_cipher.?, &len_chunk, @intCast(pt.len));
            @memcpy(out[off..][0..ss.length_chunk_size], &len_chunk);
            off += ss.length_chunk_size;
        }

        // Encrypt payload chunk.
        self.response_cipher.?.seal(out[off..][0 .. pt.len + ss.tag_len], pt);
        off += pt.len + ss.tag_len;

        return out[0..off];
    }

    fn captureTarget(self: *Session, addr: ss.SocksAddr) !void {
        self.target_port = addr.port;
        switch (addr.atyp) {
            .ipv4 => {
                if (addr.addr.len != 4) return error.BadAddressLength;
                self.target_ip_v4 = addr.addr[0..4].*;
                self.target_is_hostname = false;
            },
            .ipv6 => {
                if (addr.addr.len != 16) return error.BadAddressLength;
                self.target_ip_v6 = addr.addr[0..16].*;
                self.target_is_hostname = false;
            },
            .domain => {
                if (addr.addr.len == 0 or addr.addr.len > self.target_host_buf.len) {
                    return error.BadAddressLength;
                }
                _ = std.ascii.lowerString(self.target_host_buf[0..addr.addr.len], addr.addr);
                self.target_host_len = @intCast(addr.addr.len);
                self.target_is_hostname = true;
            },
        }
    }

    /// Returns a string view of the configured target — for whitelist checks
    /// and logging. For IP literals returns a textual form using the supplied
    /// scratch buffer.
    pub fn targetString(self: *const Session, scratch: []u8) []const u8 {
        if (self.target_is_hostname) {
            return self.target_host_buf[0..self.target_host_len];
        }
        if (self.target_ip_v4) |b| {
            const w = std.fmt.bufPrint(scratch, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch return scratch[0..0];
            return w;
        }
        if (self.target_ip_v6) |b| {
            // Compact form is fine for logging; not parsed back.
            const w = std.fmt.bufPrint(
                scratch,
                "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
                .{
                    std.mem.readInt(u16, b[0..2], .big),
                    std.mem.readInt(u16, b[2..4], .big),
                    std.mem.readInt(u16, b[4..6], .big),
                    std.mem.readInt(u16, b[6..8], .big),
                    std.mem.readInt(u16, b[8..10], .big),
                    std.mem.readInt(u16, b[10..12], .big),
                    std.mem.readInt(u16, b[12..14], .big),
                    std.mem.readInt(u16, b[14..16], .big),
                },
            ) catch return scratch[0..0];
            return w;
        }
        return scratch[0..0];
    }
};

// ═══ Tests ═══════════════════════════════════════════════════

test "Session: full handshake roundtrip with initial payload" {
    const psk = [_]u8{0x42} ** ss.psk_len;
    const allocator = std.testing.allocator;

    // Synthesise the wire bytes a real client would send.
    var client_salt: [ss.salt_len]u8 = undefined;
    @memset(&client_salt, 0xA5);
    const client_key = ss.deriveSessionKey(&psk, &client_salt);
    var client_cipher = ss.ChunkCipher.init(&client_key);

    const target_host = "fragment.com";
    const addr: ss.SocksAddr = .{ .atyp = .domain, .addr = target_host, .port = 443 };
    var var_pt: [128]u8 = undefined;
    const padding = [_]u8{0xCC} ** 4;
    const initial = "INITDATA";
    const var_pt_len = try ss.encodeVariableRequestHeader(&var_pt, addr, &padding, initial);

    var fixed_pt: [ss.fixed_request_header_pt_len]u8 = undefined;
    const ts: i64 = 2_500_000_000;
    ss.encodeFixedRequestHeader(&fixed_pt, ts, @intCast(var_pt_len));

    var fixed_ct: [ss.fixed_request_header_size]u8 = undefined;
    client_cipher.seal(&fixed_ct, &fixed_pt);
    var var_ct: [128 + ss.tag_len]u8 = undefined;
    client_cipher.seal(var_ct[0 .. var_pt_len + ss.tag_len], var_pt[0..var_pt_len]);

    // Drive the session.
    var session = Session.init(allocator, &psk);
    defer session.deinit();

    // Feed salt.
    _ = session.appendIngress(&client_salt);
    try std.testing.expectEqual(FeedEvent.need_more, session.step(ts));

    // Feed fixed header.
    _ = session.appendIngress(&fixed_ct);
    try std.testing.expectEqual(FeedEvent.need_more, session.step(ts));

    // Feed variable header.
    _ = session.appendIngress(var_ct[0 .. var_pt_len + ss.tag_len]);
    const ev = session.step(ts);
    try std.testing.expectEqual(FeedEvent.target_ready, ev);

    // Verify parsed target.
    try std.testing.expect(session.target_is_hostname);
    try std.testing.expectEqualStrings(target_host, session.target_host_buf[0..session.target_host_len]);
    try std.testing.expectEqual(@as(u16, 443), session.target_port);

    const initial_buf = session.takeInitialPayload() orelse {
        try std.testing.expect(false);
        return;
    };
    defer allocator.free(initial_buf);
    try std.testing.expectEqualStrings(initial, initial_buf);
}

test "Session: rejects fixed header with bad type" {
    const psk = [_]u8{0x99} ** ss.psk_len;
    var session = Session.init(std.testing.allocator, &psk);
    defer session.deinit();

    var client_salt: [ss.salt_len]u8 = undefined;
    @memset(&client_salt, 0x12);
    const client_key = ss.deriveSessionKey(&psk, &client_salt);
    var client_cipher = ss.ChunkCipher.init(&client_key);

    var fixed_pt: [ss.fixed_request_header_pt_len]u8 = undefined;
    fixed_pt[0] = ss.header_type_server; // wrong direction
    std.mem.writeInt(u64, fixed_pt[1..9], 1000, .big);
    std.mem.writeInt(u16, fixed_pt[9..11], 50, .big);
    var fixed_ct: [ss.fixed_request_header_size]u8 = undefined;
    client_cipher.seal(&fixed_ct, &fixed_pt);

    _ = session.appendIngress(&client_salt);
    _ = session.step(1000);
    _ = session.appendIngress(&fixed_ct);
    const ev = session.step(1000);
    switch (ev) {
        .error_close => |err| try std.testing.expectEqual(error.WrongHeaderType, err),
        else => try std.testing.expect(false),
    }
}

test "Session: relay loop alternates length/data chunks" {
    const psk = [_]u8{0x77} ** ss.psk_len;
    const allocator = std.testing.allocator;

    var session = Session.init(allocator, &psk);
    defer session.deinit();

    // Skip handshake by manually setting up state — emulate post-handshake.
    var client_salt: [ss.salt_len]u8 = undefined;
    @memset(&client_salt, 0x55);
    const client_key = ss.deriveSessionKey(&psk, &client_salt);
    var client_cipher = ss.ChunkCipher.init(&client_key);

    session.request_salt = client_salt;
    session.request_cipher = ss.ChunkCipher.init(&client_key);
    session.phase = .relaying;
    session.in_need = ss.length_chunk_size;
    session.next_chunk_kind = .length;

    // Simulate what the client sends for one chunk of relay data.
    const payload = "HELLO_RELAY";
    var len_ct: [ss.length_chunk_size]u8 = undefined;
    ss.sealLength(&client_cipher, &len_ct, payload.len);
    var data_ct: [payload.len + ss.tag_len]u8 = undefined;
    client_cipher.seal(&data_ct, payload);

    // Feed length chunk.
    _ = session.appendIngress(&len_ct);
    try std.testing.expectEqual(FeedEvent.need_more, session.step(0));

    // Feed data chunk.
    _ = session.appendIngress(&data_ct);
    const ev = session.step(0);
    switch (ev) {
        .payload => |slice| try std.testing.expectEqualStrings(payload, slice),
        else => try std.testing.expect(false),
    }
}

test "Session: wrapForClient prepends salt + header on first call" {
    const psk = [_]u8{0xAA} ** ss.psk_len;
    var session = Session.init(std.testing.allocator, &psk);
    defer session.deinit();

    var client_salt: [ss.salt_len]u8 = undefined;
    @memset(&client_salt, 0xBB);
    session.request_salt = client_salt;
    session.phase = .waiting_upstream;
    session.markUpstreamConnected();

    var out: [256]u8 = undefined;
    const reply_pt = "REPLY_BYTES";
    const written = try session.wrapForClient(&out, reply_pt, 1_700_000_000);

    // Per SIP022 the very first response chunk inherits its length from
    // `initial_payload_len` in the fixed response header — no separate
    // length chunk. Layout: 32-byte salt + 59-byte fixed header ct +
    // (reply_pt.len + 16) data chunk.
    const expected_len = ss.salt_len + ss.fixed_response_header_size +
        reply_pt.len + ss.tag_len;
    try std.testing.expectEqual(expected_len, written.len);

    // Verify first 32 bytes match the chosen response salt.
    try std.testing.expectEqualSlices(u8, &session.response_salt, written[0..ss.salt_len]);

    // Decrypt fixed response header on the client side and check fields.
    const response_key = ss.deriveSessionKey(&psk, &session.response_salt);
    var client_resp_cipher = ss.ChunkCipher.init(&response_key);
    var resp_pt: [ss.fixed_response_header_pt_len]u8 = undefined;
    try client_resp_cipher.open(&resp_pt, written[ss.salt_len .. ss.salt_len + ss.fixed_response_header_size]);
    const resp_header = ss.decodeFixedResponseHeader(&resp_pt);
    try ss.validateFixedResponseHeader(resp_header, &client_salt, 1_700_000_000);
    try std.testing.expectEqual(@as(u16, reply_pt.len), resp_header.initial_payload_len);

    // Decrypt initial payload chunk that follows directly.
    var payload_pt: [reply_pt.len]u8 = undefined;
    const payload_off = ss.salt_len + ss.fixed_response_header_size;
    try client_resp_cipher.open(
        &payload_pt,
        written[payload_off .. payload_off + reply_pt.len + ss.tag_len],
    );
    try std.testing.expectEqualStrings(reply_pt, &payload_pt);
}

test "Session: subsequent wrapForClient emits length+data only" {
    const psk = [_]u8{0xCC} ** ss.psk_len;
    var session = Session.init(std.testing.allocator, &psk);
    defer session.deinit();

    var client_salt: [ss.salt_len]u8 = undefined;
    @memset(&client_salt, 0xDD);
    session.request_salt = client_salt;
    session.phase = .waiting_upstream;
    session.markUpstreamConnected();

    var out_first: [256]u8 = undefined;
    _ = try session.wrapForClient(&out_first, "abc", 1000);

    var out_next: [128]u8 = undefined;
    const next_pt = "second";
    const written = try session.wrapForClient(&out_next, next_pt, 1000);

    // 18-byte length chunk + (next_pt.len + 16) data chunk = 18 + 22 = 40
    try std.testing.expectEqual(ss.length_chunk_size + next_pt.len + ss.tag_len, written.len);
}

test "Session: targetString returns hostname for domain target" {
    const psk = [_]u8{0x10} ** ss.psk_len;
    var session = Session.init(std.testing.allocator, &psk);
    defer session.deinit();

    const host = "wallet.tg";
    @memcpy(session.target_host_buf[0..host.len], host);
    session.target_host_len = host.len;
    session.target_is_hostname = true;

    var scratch: [64]u8 = undefined;
    const got = session.targetString(&scratch);
    try std.testing.expectEqualStrings(host, got);
}

test "Session: targetString formats ipv4 literal" {
    const psk = [_]u8{0x11} ** ss.psk_len;
    var session = Session.init(std.testing.allocator, &psk);
    defer session.deinit();

    session.target_is_hostname = false;
    session.target_ip_v4 = .{ 1, 2, 3, 4 };

    var scratch: [64]u8 = undefined;
    const got = session.targetString(&scratch);
    try std.testing.expectEqualStrings("1.2.3.4", got);
}
