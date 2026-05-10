//! Shadowsocks-2022 (`2022-blake3-aes-256-gcm`) protocol primitives.
//!
//! Pure encoding / decoding helpers — no socket I/O.
//! Wire format follows SIP022: <https://shadowsocks.org/doc/sip022.html>
//!
//! Wire layout (TCP request, client -> server):
//!   [salt (32)]
//!   [fixed-length header chunk, AEAD-encrypted (11 + 16 tag = 27 bytes)]
//!     type (1) | timestamp (8 BE) | var_header_len (2 BE)
//!   [variable-length header chunk, AEAD-encrypted (var_header_len + 16 tag)]
//!     SOCKS5 addr | padding_len (2 BE) | padding | [initial payload]
//!   [stream chunks ...]
//!     length chunk: 2 BE + 16 tag
//!     data chunk:   data + 16 tag
//!
//! Wire layout (TCP response, server -> client):
//!   [salt (32)]
//!   [fixed-length header chunk, AEAD-encrypted (43 + 16 tag = 59 bytes)]
//!     type (1) | timestamp (8 BE) | request_salt (32) | initial_payload_len (2 BE)
//!   [initial payload chunk: initial_payload_len + 16 tag]
//!   [stream chunks ...]
//!
//! Nonce: 96-bit little-endian counter, starts at 0, incremented per AEAD call
//! (length chunk and data chunk each consume one nonce slot).

const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Blake3 = std.crypto.hash.Blake3;
const local_crypto = @import("../crypto/crypto.zig");

// ─── Constants ───────────────────────────────────────────────

pub const psk_len: usize = 32;
pub const salt_len: usize = 32;
pub const key_len: usize = Aes256Gcm.key_length; // 32
pub const tag_len: usize = Aes256Gcm.tag_length; // 16
pub const nonce_len: usize = Aes256Gcm.nonce_length; // 12

pub const length_chunk_size: usize = 2 + tag_len; // 18
pub const fixed_request_header_pt_len: usize = 1 + 8 + 2; // 11
pub const fixed_request_header_size: usize = fixed_request_header_pt_len + tag_len; // 27
pub const fixed_response_header_pt_len: usize = 1 + 8 + salt_len + 2; // 43
pub const fixed_response_header_size: usize = fixed_response_header_pt_len + tag_len; // 59

/// SS chunk length is a u16 BE but only 14 bits are usable
/// (the top 2 bits are reserved and MUST be zero).
pub const max_chunk_size: usize = 0x3FFF;

/// Allowed clock skew between client and server timestamps (seconds).
/// SIP022 mandates ±30s; we use the same.
pub const time_skew_seconds: i64 = 30;

pub const header_type_client: u8 = 0x00;
pub const header_type_server: u8 = 0x01;

const kdf_context: []const u8 = "shadowsocks 2022 session subkey";

// ─── KDF ─────────────────────────────────────────────────────

/// Derive a per-session AEAD subkey from the long-lived PSK and a per-session salt.
/// Per SIP022: `session_subkey = BLAKE3-derive-key("shadowsocks 2022 session subkey", PSK || salt)`.
pub fn deriveSessionKey(
    psk: *const [psk_len]u8,
    salt: *const [salt_len]u8,
) [key_len]u8 {
    var hasher = Blake3.initKdf(kdf_context, .{});
    hasher.update(psk);
    hasher.update(salt);
    var out: [key_len]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ─── Nonce ──────────────────────────────────────────────────

/// Increment a 96-bit little-endian counter in place.
pub fn incrementNonce(nonce: *[nonce_len]u8) void {
    var i: usize = 0;
    while (i < nonce_len) : (i += 1) {
        nonce[i] +%= 1;
        if (nonce[i] != 0) return;
    }
}

// ─── Chunk Cipher ────────────────────────────────────────────

/// One direction's AEAD state: owns the session subkey and a monotonic nonce.
/// One AEAD operation = one nonce; caller alternates length / data chunks.
pub const ChunkCipher = struct {
    key: [key_len]u8,
    nonce: [nonce_len]u8,

    pub fn init(key: *const [key_len]u8) ChunkCipher {
        return .{
            .key = key.*,
            .nonce = [_]u8{0} ** nonce_len,
        };
    }

    pub fn wipe(self: *ChunkCipher) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.nonce);
    }

    /// Encrypt `pt` into `out`. `out.len` MUST equal `pt.len + tag_len`.
    pub fn seal(self: *ChunkCipher, out: []u8, pt: []const u8) void {
        std.debug.assert(out.len == pt.len + tag_len);
        const ct = out[0..pt.len];
        const tag: *[tag_len]u8 = out[pt.len..][0..tag_len];
        Aes256Gcm.encrypt(ct, tag, pt, &.{}, self.nonce, self.key);
        incrementNonce(&self.nonce);
    }

    /// Decrypt `ct` into `out`. `out.len` MUST equal `ct.len - tag_len`.
    pub fn open(self: *ChunkCipher, out: []u8, ct: []const u8) !void {
        if (ct.len < tag_len) return error.ShortCiphertext;
        std.debug.assert(out.len == ct.len - tag_len);
        const body = ct[0 .. ct.len - tag_len];
        const tag: [tag_len]u8 = ct[ct.len - tag_len ..][0..tag_len].*;
        Aes256Gcm.decrypt(out, body, tag, &.{}, self.nonce, self.key) catch
            return error.AuthenticationFailed;
        incrementNonce(&self.nonce);
    }
};

// ─── Length Chunk ────────────────────────────────────────────

/// Encrypt a 2-byte length into the standard 18-byte length chunk.
pub fn sealLength(cipher: *ChunkCipher, out: *[length_chunk_size]u8, length: u16) void {
    var pt: [2]u8 = undefined;
    std.mem.writeInt(u16, &pt, length, .big);
    cipher.seal(out, &pt);
}

/// Decrypt a length chunk and return the payload length.
/// Rejects lengths with non-zero reserved bits or zero length.
pub fn openLength(cipher: *ChunkCipher, ct: *const [length_chunk_size]u8) !u16 {
    var pt: [2]u8 = undefined;
    try cipher.open(&pt, ct);
    const len = std.mem.readInt(u16, &pt, .big);
    if (len & 0xC000 != 0) return error.LengthReservedBitsSet;
    if (len == 0) return error.ZeroLength;
    return len;
}

// ─── SOCKS5 Address ──────────────────────────────────────────

pub const Atyp = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const SocksAddr = struct {
    atyp: Atyp,
    /// Slice into the source plaintext buffer:
    ///   ipv4   — 4 bytes
    ///   ipv6   — 16 bytes
    ///   domain — domain name (without the leading length byte)
    addr: []const u8,
    port: u16,
};

pub const ParsedSocksAddr = struct {
    addr: SocksAddr,
    consumed: usize,
};

/// Parse `[ATYP] [addr] [PORT BE]` from `buf`. No allocation —
/// `addr.addr` is a slice into `buf`.
pub fn parseSocksAddr(buf: []const u8) !ParsedSocksAddr {
    if (buf.len < 1) return error.ShortBuffer;
    const atyp_raw = buf[0];
    const atyp = std.enums.fromInt(Atyp, atyp_raw) orelse return error.UnsupportedAtyp;

    switch (atyp) {
        .ipv4 => {
            const total: usize = 1 + 4 + 2;
            if (buf.len < total) return error.ShortBuffer;
            return .{
                .addr = .{
                    .atyp = atyp,
                    .addr = buf[1..5],
                    .port = std.mem.readInt(u16, buf[5..7], .big),
                },
                .consumed = total,
            };
        },
        .ipv6 => {
            const total: usize = 1 + 16 + 2;
            if (buf.len < total) return error.ShortBuffer;
            return .{
                .addr = .{
                    .atyp = atyp,
                    .addr = buf[1..17],
                    .port = std.mem.readInt(u16, buf[17..19], .big),
                },
                .consumed = total,
            };
        },
        .domain => {
            if (buf.len < 2) return error.ShortBuffer;
            const dlen: usize = buf[1];
            if (dlen == 0) return error.EmptyDomain;
            const total: usize = 2 + dlen + 2;
            if (buf.len < total) return error.ShortBuffer;
            return .{
                .addr = .{
                    .atyp = atyp,
                    .addr = buf[2 .. 2 + dlen],
                    .port = std.mem.readInt(u16, buf[2 + dlen ..][0..2], .big),
                },
                .consumed = total,
            };
        },
    }
}

/// Compute the wire size of a SOCKS5 address with the given parameters.
pub fn socksAddrSize(atyp: Atyp, domain_len: usize) usize {
    return switch (atyp) {
        .ipv4 => 1 + 4 + 2,
        .ipv6 => 1 + 16 + 2,
        .domain => 2 + domain_len + 2,
    };
}

// ─── Fixed Request Header ────────────────────────────────────

pub const FixedRequestHeader = struct {
    type: u8,
    timestamp: i64,
    var_header_len: u16,
};

/// Encode the fixed-length request header plaintext into `out` (11 bytes).
pub fn encodeFixedRequestHeader(
    out: *[fixed_request_header_pt_len]u8,
    timestamp: i64,
    var_header_len: u16,
) void {
    out[0] = header_type_client;
    std.mem.writeInt(u64, out[1..9], @bitCast(timestamp), .big);
    std.mem.writeInt(u16, out[9..11], var_header_len, .big);
}

/// Decode the fixed-length request header plaintext (11 bytes).
pub fn decodeFixedRequestHeader(pt: *const [fixed_request_header_pt_len]u8) FixedRequestHeader {
    return .{
        .type = pt[0],
        .timestamp = @bitCast(std.mem.readInt(u64, pt[1..9], .big)),
        .var_header_len = std.mem.readInt(u16, pt[9..11], .big),
    };
}

/// Validate fixed-length request header semantics.
/// `now` is current Unix time (seconds), passed in for testability.
pub fn validateFixedRequestHeader(h: FixedRequestHeader, now: i64) !void {
    if (h.type != header_type_client) return error.WrongHeaderType;
    const skew = if (now > h.timestamp) now - h.timestamp else h.timestamp - now;
    if (skew > time_skew_seconds) return error.TimestampSkew;
    if (h.var_header_len == 0) return error.ZeroVarHeader;
    if (@as(usize, h.var_header_len) > max_chunk_size) return error.VarHeaderTooLarge;
}

// ─── Variable Request Header ─────────────────────────────────

pub const ParsedRequestVarHeader = struct {
    addr: SocksAddr,
    padding_len: u16,
    /// Initial payload bytes (may be empty); slice into source buffer.
    initial_payload: []const u8,
};

/// Parse the decrypted variable-length request header chunk.
/// Layout: SOCKS5 addr | padding_len (2 BE) | padding | initial payload.
pub fn parseVariableRequestHeader(pt: []const u8) !ParsedRequestVarHeader {
    const parsed_addr = try parseSocksAddr(pt);
    var off = parsed_addr.consumed;

    if (pt.len < off + 2) return error.ShortVarHeader;
    const padding_len = std.mem.readInt(u16, pt[off..][0..2], .big);
    off += 2;

    if (pt.len < off + @as(usize, padding_len)) return error.ShortPadding;
    off += padding_len;

    const initial_payload = pt[off..];
    return .{
        .addr = parsed_addr.addr,
        .padding_len = padding_len,
        .initial_payload = initial_payload,
    };
}

/// Encode a variable-length request header (used by tests and clients).
/// Returns the number of bytes written into `out`.
pub fn encodeVariableRequestHeader(
    out: []u8,
    addr: SocksAddr,
    padding: []const u8,
    initial_payload: []const u8,
) !usize {
    const addr_size = socksAddrSize(addr.atyp, addr.addr.len);
    const total = addr_size + 2 + padding.len + initial_payload.len;
    if (out.len < total) return error.OutputTooSmall;
    if (padding.len > std.math.maxInt(u16)) return error.PaddingTooLarge;

    out[0] = @intFromEnum(addr.atyp);
    var off: usize = 1;
    switch (addr.atyp) {
        .ipv4 => {
            if (addr.addr.len != 4) return error.BadAddressLength;
            @memcpy(out[off..][0..4], addr.addr);
            off += 4;
        },
        .ipv6 => {
            if (addr.addr.len != 16) return error.BadAddressLength;
            @memcpy(out[off..][0..16], addr.addr);
            off += 16;
        },
        .domain => {
            if (addr.addr.len == 0 or addr.addr.len > 255) return error.BadAddressLength;
            out[off] = @intCast(addr.addr.len);
            off += 1;
            @memcpy(out[off..][0..addr.addr.len], addr.addr);
            off += addr.addr.len;
        },
    }
    std.mem.writeInt(u16, out[off..][0..2], addr.port, .big);
    off += 2;

    std.mem.writeInt(u16, out[off..][0..2], @intCast(padding.len), .big);
    off += 2;
    if (padding.len > 0) {
        @memcpy(out[off..][0..padding.len], padding);
        off += padding.len;
    }
    if (initial_payload.len > 0) {
        @memcpy(out[off..][0..initial_payload.len], initial_payload);
        off += initial_payload.len;
    }
    return off;
}

// ─── Fixed Response Header ───────────────────────────────────

pub const FixedResponseHeader = struct {
    type: u8,
    timestamp: i64,
    request_salt: [salt_len]u8,
    initial_payload_len: u16,
};

pub fn encodeFixedResponseHeader(
    out: *[fixed_response_header_pt_len]u8,
    timestamp: i64,
    request_salt: *const [salt_len]u8,
    initial_payload_len: u16,
) void {
    out[0] = header_type_server;
    std.mem.writeInt(u64, out[1..9], @bitCast(timestamp), .big);
    @memcpy(out[9 .. 9 + salt_len], request_salt);
    std.mem.writeInt(u16, out[9 + salt_len ..][0..2], initial_payload_len, .big);
}

pub fn decodeFixedResponseHeader(pt: *const [fixed_response_header_pt_len]u8) FixedResponseHeader {
    var resp: FixedResponseHeader = undefined;
    resp.type = pt[0];
    resp.timestamp = @bitCast(std.mem.readInt(u64, pt[1..9], .big));
    @memcpy(&resp.request_salt, pt[9 .. 9 + salt_len]);
    resp.initial_payload_len = std.mem.readInt(u16, pt[9 + salt_len ..][0..2], .big);
    return resp;
}

/// Validate response header semantics.
pub fn validateFixedResponseHeader(
    h: FixedResponseHeader,
    expected_request_salt: *const [salt_len]u8,
    now: i64,
) !void {
    if (h.type != header_type_server) return error.WrongHeaderType;
    const skew = if (now > h.timestamp) now - h.timestamp else h.timestamp - now;
    if (skew > time_skew_seconds) return error.TimestampSkew;
    if (!std.crypto.timing_safe.eql([salt_len]u8, h.request_salt, expected_request_salt.*))
        return error.SaltMismatch;
}

// ─── Random Salt ─────────────────────────────────────────────

/// Generate a fresh per-session salt.
pub fn generateSalt(out: *[salt_len]u8) void {
    local_crypto.randomBytes(out);
}

/// Generate a random PSK (used by `mtbuddy ss enable`).
pub fn generatePsk(out: *[psk_len]u8) void {
    local_crypto.randomBytes(out);
}

// ─── PSK Codec ───────────────────────────────────────────────

/// Decode a base64-encoded PSK string into a 32-byte key.
/// Accepts both standard and URL-safe alphabets (we accept '+/' only here for SS compat).
pub fn decodePskBase64(b64: []const u8) ![psk_len]u8 {
    const decoder = std.base64.standard.Decoder;
    const expected = decoder.calcSizeForSlice(b64) catch return error.InvalidBase64;
    if (expected != psk_len) return error.WrongPskLength;
    var out: [psk_len]u8 = undefined;
    decoder.decode(&out, b64) catch return error.InvalidBase64;
    return out;
}

/// Encode a PSK to its base64 string representation.
/// Caller must provide a buffer of at least `encodedPskBase64Len()` bytes.
/// Returns a const slice into `out`.
pub fn encodePskBase64(out: []u8, psk: *const [psk_len]u8) []const u8 {
    const encoder = std.base64.standard.Encoder;
    const n = encoder.calcSize(psk_len);
    std.debug.assert(out.len >= n);
    return encoder.encode(out[0..n], psk);
}

pub fn encodedPskBase64Len() usize {
    return std.base64.standard.Encoder.calcSize(psk_len);
}

// ═══ Tests ═══════════════════════════════════════════════════

test "deriveSessionKey: same inputs -> same key" {
    const psk = [_]u8{0x42} ** psk_len;
    const salt = [_]u8{0xAB} ** salt_len;

    const k1 = deriveSessionKey(&psk, &salt);
    const k2 = deriveSessionKey(&psk, &salt);
    try std.testing.expectEqualSlices(u8, &k1, &k2);
}

test "deriveSessionKey: different salts -> different keys" {
    const psk = [_]u8{0x42} ** psk_len;
    const salt_a = [_]u8{0xAA} ** salt_len;
    const salt_b = [_]u8{0xBB} ** salt_len;

    const k_a = deriveSessionKey(&psk, &salt_a);
    const k_b = deriveSessionKey(&psk, &salt_b);
    try std.testing.expect(!std.mem.eql(u8, &k_a, &k_b));
}

test "deriveSessionKey: different PSKs -> different keys" {
    const salt = [_]u8{0xAA} ** salt_len;
    const psk_a = [_]u8{0x11} ** psk_len;
    const psk_b = [_]u8{0x22} ** psk_len;

    const k_a = deriveSessionKey(&psk_a, &salt);
    const k_b = deriveSessionKey(&psk_b, &salt);
    try std.testing.expect(!std.mem.eql(u8, &k_a, &k_b));
}

test "incrementNonce: increments low byte first" {
    var n = [_]u8{0} ** nonce_len;
    incrementNonce(&n);
    try std.testing.expectEqual(@as(u8, 1), n[0]);
    for (n[1..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "incrementNonce: rolls over to next byte" {
    var n = [_]u8{0} ** nonce_len;
    n[0] = 0xFF;
    incrementNonce(&n);
    try std.testing.expectEqual(@as(u8, 0), n[0]);
    try std.testing.expectEqual(@as(u8, 1), n[1]);
}

test "incrementNonce: cascade across 3 bytes" {
    var n = [_]u8{0} ** nonce_len;
    n[0] = 0xFF;
    n[1] = 0xFF;
    n[2] = 0xFF;
    incrementNonce(&n);
    try std.testing.expectEqual(@as(u8, 0), n[0]);
    try std.testing.expectEqual(@as(u8, 0), n[1]);
    try std.testing.expectEqual(@as(u8, 0), n[2]);
    try std.testing.expectEqual(@as(u8, 1), n[3]);
}

test "ChunkCipher: roundtrip a single chunk" {
    const key = [_]u8{0x55} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    const pt = "hello shadowsocks 2022 world";
    var ct: [pt.len + tag_len]u8 = undefined;
    enc.seal(&ct, pt);

    var rt: [pt.len]u8 = undefined;
    try dec.open(&rt, &ct);
    try std.testing.expectEqualStrings(pt, &rt);
}

test "ChunkCipher: nonce desync produces auth failure" {
    const key = [_]u8{0x77} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    // Encrypt two chunks, but only decrypt the second — nonces will desync.
    const pt = "first";
    var ct1: [pt.len + tag_len]u8 = undefined;
    enc.seal(&ct1, pt);

    const pt2 = "second";
    var ct2: [pt2.len + tag_len]u8 = undefined;
    enc.seal(&ct2, pt2);

    var rt2: [pt2.len]u8 = undefined;
    // dec is at nonce=0, but ct2 was encrypted at nonce=1 -> auth fails.
    try std.testing.expectError(error.AuthenticationFailed, dec.open(&rt2, &ct2));
}

test "ChunkCipher: tampered ciphertext rejected" {
    const key = [_]u8{0x99} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    const pt = "tamper test";
    var ct: [pt.len + tag_len]u8 = undefined;
    enc.seal(&ct, pt);
    ct[0] ^= 0x01;

    var rt: [pt.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, dec.open(&rt, &ct));
}

test "length chunk: roundtrip" {
    const key = [_]u8{0x33} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    var ct: [length_chunk_size]u8 = undefined;
    sealLength(&enc, &ct, 1234);
    const len = try openLength(&dec, &ct);
    try std.testing.expectEqual(@as(u16, 1234), len);
}

test "length chunk: rejects reserved high bits" {
    const key = [_]u8{0x44} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    // Build a length chunk manually with the top bit set in the underlying plaintext
    // by encrypting a u16 with high bits.
    var pt: [2]u8 = undefined;
    std.mem.writeInt(u16, &pt, 0x8001, .big);
    var ct: [length_chunk_size]u8 = undefined;
    enc.seal(&ct, &pt);

    try std.testing.expectError(error.LengthReservedBitsSet, openLength(&dec, &ct));
}

test "length chunk: rejects zero length" {
    const key = [_]u8{0x55} ** key_len;
    var enc = ChunkCipher.init(&key);
    var dec = ChunkCipher.init(&key);

    var ct: [length_chunk_size]u8 = undefined;
    sealLength(&enc, &ct, 0);
    try std.testing.expectError(error.ZeroLength, openLength(&dec, &ct));
}

test "parseSocksAddr: ipv4" {
    const buf = [_]u8{ 0x01, 1, 2, 3, 4, 0x01, 0xBB };
    const r = try parseSocksAddr(&buf);
    try std.testing.expectEqual(Atyp.ipv4, r.addr.atyp);
    try std.testing.expectEqual(@as(usize, 4), r.addr.addr.len);
    try std.testing.expectEqual(@as(u16, 443), r.addr.port);
    try std.testing.expectEqual(@as(usize, 7), r.consumed);
}

test "parseSocksAddr: ipv6" {
    var buf: [19]u8 = undefined;
    buf[0] = 0x04;
    for (0..16) |i| buf[1 + i] = @intCast(i);
    buf[17] = 0x01;
    buf[18] = 0xBB;
    const r = try parseSocksAddr(&buf);
    try std.testing.expectEqual(Atyp.ipv6, r.addr.atyp);
    try std.testing.expectEqual(@as(usize, 16), r.addr.addr.len);
    try std.testing.expectEqual(@as(u16, 443), r.addr.port);
}

test "parseSocksAddr: domain" {
    const domain = "fragment.com";
    var buf: [2 + domain.len + 2]u8 = undefined;
    buf[0] = 0x03;
    buf[1] = @intCast(domain.len);
    @memcpy(buf[2 .. 2 + domain.len], domain);
    buf[2 + domain.len] = 0x01;
    buf[2 + domain.len + 1] = 0xBB;
    const r = try parseSocksAddr(&buf);
    try std.testing.expectEqual(Atyp.domain, r.addr.atyp);
    try std.testing.expectEqualStrings(domain, r.addr.addr);
    try std.testing.expectEqual(@as(u16, 443), r.addr.port);
}

test "parseSocksAddr: errors" {
    try std.testing.expectError(error.ShortBuffer, parseSocksAddr(&[_]u8{}));
    try std.testing.expectError(error.UnsupportedAtyp, parseSocksAddr(&[_]u8{0x99}));
    try std.testing.expectError(error.ShortBuffer, parseSocksAddr(&[_]u8{ 0x01, 1, 2, 3 }));
    try std.testing.expectError(error.EmptyDomain, parseSocksAddr(&[_]u8{ 0x03, 0x00, 0, 0 }));
}

test "fixed request header: encode -> decode roundtrip" {
    var pt: [fixed_request_header_pt_len]u8 = undefined;
    encodeFixedRequestHeader(&pt, 1_700_000_000, 256);
    const h = decodeFixedRequestHeader(&pt);
    try std.testing.expectEqual(@as(u8, header_type_client), h.type);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), h.timestamp);
    try std.testing.expectEqual(@as(u16, 256), h.var_header_len);
}

test "validateFixedRequestHeader: accepts in-range timestamp" {
    var pt: [fixed_request_header_pt_len]u8 = undefined;
    encodeFixedRequestHeader(&pt, 1000, 50);
    const h = decodeFixedRequestHeader(&pt);
    try validateFixedRequestHeader(h, 1010);
}

test "validateFixedRequestHeader: rejects skewed timestamp" {
    var pt: [fixed_request_header_pt_len]u8 = undefined;
    encodeFixedRequestHeader(&pt, 1000, 50);
    const h = decodeFixedRequestHeader(&pt);
    try std.testing.expectError(error.TimestampSkew, validateFixedRequestHeader(h, 5000));
    try std.testing.expectError(error.TimestampSkew, validateFixedRequestHeader(h, 0));
}

test "validateFixedRequestHeader: rejects wrong type" {
    var pt = [_]u8{0} ** fixed_request_header_pt_len;
    pt[0] = header_type_server;
    std.mem.writeInt(u64, pt[1..9], 1000, .big);
    std.mem.writeInt(u16, pt[9..11], 10, .big);
    const h = decodeFixedRequestHeader(&pt);
    try std.testing.expectError(error.WrongHeaderType, validateFixedRequestHeader(h, 1000));
}

test "validateFixedRequestHeader: rejects zero var header" {
    var pt: [fixed_request_header_pt_len]u8 = undefined;
    encodeFixedRequestHeader(&pt, 1000, 0);
    const h = decodeFixedRequestHeader(&pt);
    try std.testing.expectError(error.ZeroVarHeader, validateFixedRequestHeader(h, 1000));
}

test "variable request header: roundtrip ipv4" {
    var buf: [256]u8 = undefined;
    const addr_bytes = [_]u8{ 1, 2, 3, 4 };
    const addr: SocksAddr = .{ .atyp = .ipv4, .addr = &addr_bytes, .port = 443 };
    const padding = [_]u8{0xCD} ** 8;
    const payload = "GET / HTTP/1.1\r\n";

    const written = try encodeVariableRequestHeader(&buf, addr, &padding, payload);
    const parsed = try parseVariableRequestHeader(buf[0..written]);

    try std.testing.expectEqual(Atyp.ipv4, parsed.addr.atyp);
    try std.testing.expectEqualSlices(u8, &addr_bytes, parsed.addr.addr);
    try std.testing.expectEqual(@as(u16, 443), parsed.addr.port);
    try std.testing.expectEqual(@as(u16, 8), parsed.padding_len);
    try std.testing.expectEqualStrings(payload, parsed.initial_payload);
}

test "variable request header: roundtrip domain" {
    var buf: [256]u8 = undefined;
    const domain = "wallet.tg";
    const addr: SocksAddr = .{ .atyp = .domain, .addr = domain, .port = 443 };
    const padding = [_]u8{};
    const payload = "";

    const written = try encodeVariableRequestHeader(&buf, addr, &padding, payload);
    const parsed = try parseVariableRequestHeader(buf[0..written]);

    try std.testing.expectEqual(Atyp.domain, parsed.addr.atyp);
    try std.testing.expectEqualStrings(domain, parsed.addr.addr);
    try std.testing.expectEqual(@as(u16, 443), parsed.addr.port);
    try std.testing.expectEqual(@as(u16, 0), parsed.padding_len);
    try std.testing.expectEqual(@as(usize, 0), parsed.initial_payload.len);
}

test "variable request header: short buffer for padding" {
    // Crafted: ipv4 (7 bytes) + padding_len=10 but only 5 bytes of padding present.
    var buf: [16]u8 = undefined;
    buf[0] = 0x01;
    @memcpy(buf[1..5], &[_]u8{ 1, 2, 3, 4 });
    std.mem.writeInt(u16, buf[5..7], 443, .big);
    std.mem.writeInt(u16, buf[7..9], 10, .big); // padding_len = 10
    @memset(buf[9..14], 0); // only 5 bytes of padding
    try std.testing.expectError(error.ShortPadding, parseVariableRequestHeader(buf[0..14]));
}

test "fixed response header: encode -> decode roundtrip" {
    var pt: [fixed_response_header_pt_len]u8 = undefined;
    const req_salt = [_]u8{0xAB} ** salt_len;
    encodeFixedResponseHeader(&pt, 1_700_000_000, &req_salt, 42);
    const h = decodeFixedResponseHeader(&pt);
    try std.testing.expectEqual(@as(u8, header_type_server), h.type);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), h.timestamp);
    try std.testing.expectEqualSlices(u8, &req_salt, &h.request_salt);
    try std.testing.expectEqual(@as(u16, 42), h.initial_payload_len);
}

test "validateFixedResponseHeader: salt mismatch rejected" {
    var pt: [fixed_response_header_pt_len]u8 = undefined;
    const sent_salt = [_]u8{0xAB} ** salt_len;
    encodeFixedResponseHeader(&pt, 1000, &sent_salt, 0);
    const h = decodeFixedResponseHeader(&pt);

    const expected_other = [_]u8{0xCD} ** salt_len;
    try std.testing.expectError(
        error.SaltMismatch,
        validateFixedResponseHeader(h, &expected_other, 1000),
    );
    try validateFixedResponseHeader(h, &sent_salt, 1000);
}

test "end-to-end: full request -> server parse -> response -> client parse" {
    const psk = [_]u8{0x77} ** psk_len;

    // === Client side: build request ===
    var client_salt: [salt_len]u8 = undefined;
    @memset(&client_salt, 0xA1);
    const client_session_key = deriveSessionKey(&psk, &client_salt);

    var client_enc = ChunkCipher.init(&client_session_key);

    // Variable header plaintext.
    var var_pt_buf: [128]u8 = undefined;
    const addr_bytes = [_]u8{ 149, 154, 175, 50 };
    const addr: SocksAddr = .{ .atyp = .ipv4, .addr = &addr_bytes, .port = 443 };
    const padding = [_]u8{0xEE} ** 4;
    const initial = "INIT";
    const var_pt_len = try encodeVariableRequestHeader(&var_pt_buf, addr, &padding, initial);

    // Fixed header plaintext.
    var fixed_pt: [fixed_request_header_pt_len]u8 = undefined;
    const ts_now: i64 = 2_000_000_000;
    encodeFixedRequestHeader(&fixed_pt, ts_now, @intCast(var_pt_len));

    // Encrypt fixed header chunk.
    var fixed_ct: [fixed_request_header_size]u8 = undefined;
    client_enc.seal(&fixed_ct, &fixed_pt);

    // Encrypt variable header chunk.
    var var_ct: [128 + tag_len]u8 = undefined;
    client_enc.seal(var_ct[0 .. var_pt_len + tag_len], var_pt_buf[0..var_pt_len]);

    // === Server side: receive and parse ===
    var server_dec = ChunkCipher.init(&deriveSessionKey(&psk, &client_salt));

    var fixed_pt_recv: [fixed_request_header_pt_len]u8 = undefined;
    try server_dec.open(&fixed_pt_recv, &fixed_ct);
    const fixed = decodeFixedRequestHeader(&fixed_pt_recv);
    try validateFixedRequestHeader(fixed, ts_now);
    try std.testing.expectEqual(@as(u16, @intCast(var_pt_len)), fixed.var_header_len);

    var var_pt_recv_buf: [128]u8 = undefined;
    try server_dec.open(var_pt_recv_buf[0..var_pt_len], var_ct[0 .. var_pt_len + tag_len]);
    const parsed = try parseVariableRequestHeader(var_pt_recv_buf[0..var_pt_len]);

    try std.testing.expectEqual(Atyp.ipv4, parsed.addr.atyp);
    try std.testing.expectEqualSlices(u8, &addr_bytes, parsed.addr.addr);
    try std.testing.expectEqual(@as(u16, 443), parsed.addr.port);
    try std.testing.expectEqualStrings(initial, parsed.initial_payload);

    // === Server side: build response ===
    var server_salt: [salt_len]u8 = undefined;
    @memset(&server_salt, 0xB2);
    const server_session_key = deriveSessionKey(&psk, &server_salt);
    var server_enc = ChunkCipher.init(&server_session_key);

    const reply_payload = "RESP";
    var resp_fixed_pt: [fixed_response_header_pt_len]u8 = undefined;
    encodeFixedResponseHeader(&resp_fixed_pt, ts_now, &client_salt, reply_payload.len);
    var resp_fixed_ct: [fixed_response_header_size]u8 = undefined;
    server_enc.seal(&resp_fixed_ct, &resp_fixed_pt);

    var resp_payload_ct: [reply_payload.len + tag_len]u8 = undefined;
    server_enc.seal(&resp_payload_ct, reply_payload);

    // === Client side: receive response ===
    var client_dec = ChunkCipher.init(&deriveSessionKey(&psk, &server_salt));
    var resp_fixed_pt_recv: [fixed_response_header_pt_len]u8 = undefined;
    try client_dec.open(&resp_fixed_pt_recv, &resp_fixed_ct);
    const resp_fixed = decodeFixedResponseHeader(&resp_fixed_pt_recv);
    try validateFixedResponseHeader(resp_fixed, &client_salt, ts_now);
    try std.testing.expectEqual(@as(u16, reply_payload.len), resp_fixed.initial_payload_len);

    var resp_payload_pt: [reply_payload.len]u8 = undefined;
    try client_dec.open(&resp_payload_pt, &resp_payload_ct);
    try std.testing.expectEqualStrings(reply_payload, &resp_payload_pt);
}

test "PSK base64 codec: encode -> decode roundtrip" {
    var psk: [psk_len]u8 = undefined;
    for (0..psk_len) |i| psk[i] = @intCast(i);

    var b64_buf: [64]u8 = undefined;
    const b64 = encodePskBase64(&b64_buf, &psk);
    try std.testing.expect(b64.len == encodedPskBase64Len());

    const decoded = try decodePskBase64(b64);
    try std.testing.expectEqualSlices(u8, &psk, &decoded);
}

test "PSK base64: rejects wrong-length key" {
    // Encode a 16-byte (wrong) buffer in base64 and try to decode as PSK.
    const bad = [_]u8{0x42} ** 16;
    var b64_buf: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder;
    const b64 = enc.encode(b64_buf[0..enc.calcSize(bad.len)], &bad);

    try std.testing.expectError(error.WrongPskLength, decodePskBase64(b64));
}

test "PSK base64: rejects garbage" {
    try std.testing.expectError(error.InvalidBase64, decodePskBase64("not-valid-base64!!!"));
}
