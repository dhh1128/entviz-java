package io.github.dhh1128.entviz;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Format-specific entropy parsing (port of {@code entropy.py} via
 * {@code entropy.rs} / {@code entropy.go}).
 *
 * <p>{@link #parse(String)} dispatches over the registered parsers in order
 * (order is semantics) and returns the first match, or falls back to
 * disproof-based alphabet detection. The pipeline re-encodes to base64url only
 * when this returns no match. A hard parse error (EIP-55 checksum failure)
 * aborts the whole render via {@link Eip55Exception}.
 */
final class Entropy {

    private Entropy() {
    }

    static final String HEX_CHARS_LOWER = "0123456789abcdef";
    static final String BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static final String BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    static final String BASE32_CHARS_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /** W3C DID: {@code did:<method>:<method-specific-id>} with an optional DID-URL tail. */
    private static final Pattern DID_REGEX =
            Pattern.compile("^did:([a-z0-9]+):([A-Za-z0-9._%:-]+)(?:[/?#].*)?$");

    /** RFC 8141 URN: {@code urn:<NID>:<NSS>} with optional r-/q-/f-components. */
    private static final Pattern URN_REGEX =
            Pattern.compile("^urn:([A-Za-z0-9][A-Za-z0-9-]{0,31}):([^?#]+)(?:[?#].*)?$",
                    Pattern.CASE_INSENSITIVE);

    // ---- char-class helpers ----------------------------------------------

    static boolean isAsciiHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    static boolean isHex(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!isAsciiHexDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    static boolean allIn(String s, String set) {
        for (int i = 0; i < s.length(); i++) {
            if (set.indexOf(s.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    static boolean isBase58(String s) {
        return !s.isEmpty() && allIn(s, BASE58_CHARS);
    }

    static boolean isBech32Either(String s) {
        return !s.isEmpty() && allIn(s.toLowerCase(Locale.ROOT), BECH32_CHARS);
    }

    static boolean isBase32Either(String s) {
        return !s.isEmpty() && allIn(s.toUpperCase(Locale.ROOT), BASE32_CHARS_UP);
    }

    static boolean isBase64urlNopad(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(isAsciiAlphanumeric(c) || c == '-' || c == '_')) {
                return false;
            }
        }
        return true;
    }

    static boolean isAsciiAlphanumeric(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    static boolean isAsciiLower(char c) {
        return c >= 'a' && c <= 'z';
    }

    static boolean isAsciiUpper(char c) {
        return c >= 'A' && c <= 'Z';
    }

    static boolean isAsciiAlpha(char c) {
        return isAsciiLower(c) || isAsciiUpper(c);
    }

    static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    static boolean isWhitespace(char r) {
        return switch (r) {
            case ' ', '\t', '\n', '\r', '\f', 0x0b -> true;
            default -> false;
        };
    }

    private static int len(String s) {
        return s.codePointCount(0, s.length());
    }

    // ---- CESR ------------------------------------------------------------

    private record CesrCode(String code, String label, int total) {
    }

    static Parsed parseCesr(String text) {
        CesrCode[] one = {
                new CesrCode("A", "Ed25519 seed", 44), new CesrCode("B", "Ed25519 nt pubkey", 44),
                new CesrCode("C", "X25519 pub enckey", 44), new CesrCode("D", "Ed25519 pubkey", 44),
                new CesrCode("E", "Blake3-256", 44), new CesrCode("F", "Blake2b-256", 44),
                new CesrCode("G", "Blake2s-256", 44), new CesrCode("H", "SHA3-256", 44),
                new CesrCode("I", "SHA2-256", 44), new CesrCode("J", "secp256k1 seed", 44),
                new CesrCode("K", "Ed448 seed", 76), new CesrCode("L", "X448 pub enckey", 76),
                new CesrCode("O", "X25519 priv deckey", 44), new CesrCode("P", "X25519 124 cipher 44 seed", 124),
                new CesrCode("Q", "secp256r1 seed", 44), new CesrCode("a", "blinding factor", 44),
                new CesrCode("c", "FN-DSA-512 seed", 44), new CesrCode("d", "FN-DSA-1024 seed", 44),
                new CesrCode("e", "FN-DSA-1024 sig", 1708), new CesrCode("b", "FN-DSA-1024 pubkey", 2392),
        };
        CesrCode[] two = {
                new CesrCode("0A", "random 128-bit number", 24), new CesrCode("0B", "Ed25519 sig", 88),
                new CesrCode("0C", "secp256k1 sig", 88), new CesrCode("0D", "Blake3-512", 88),
                new CesrCode("0E", "Blake2b-512", 88), new CesrCode("0F", "SHA3-512", 88),
                new CesrCode("0G", "SHA2-512", 88), new CesrCode("0I", "secp256r1 sig", 88),
        };
        CesrCode[] four = {
                new CesrCode("1AAA", "secp256k1 nt pubkey", 48), new CesrCode("1AAB", "secp256k1 pub/enc key", 48),
                new CesrCode("1AAC", "Ed448 nt pubkey", 80), new CesrCode("1AAD", "Ed448 pubkey", 80),
                new CesrCode("1AAE", "Ed448 sig", 156), new CesrCode("1AAH", "X25519 100 cipher 24 salt", 100),
                new CesrCode("1AAI", "secp256r1 nt pubkey", 48), new CesrCode("1AAJ", "secp256r1 pub/enc key", 48),
                new CesrCode("1AAR", "FN-DSA-512 sig", 892), new CesrCode("1AAQ", "FN-DSA-512 pubkey", 1200),
        };
        if (text.isEmpty()) {
            return null;
        }
        int length = len(text);
        char first = text.charAt(0);

        CesrCode[] items;
        if (first == '0' && anyLen(two, length)) {
            items = two;
        } else if (first == '1' && anyLen(four, length)) {
            items = four;
        } else if (first != '0' && first != '1' && anyLen(one, length)) {
            items = one;
        } else {
            return null;
        }
        for (CesrCode it : items) {
            if (text.startsWith(it.code()) && length == it.total() && isBase64urlNopad(text)) {
                return Parsed.of("CESR " + it.label(), Alphabet.BASE64URL, null, text, null);
            }
        }
        return null;
    }

    private static boolean anyLen(CesrCode[] items, int length) {
        for (CesrCode x : items) {
            if (x.total() == length) {
                return true;
            }
        }
        return false;
    }

    // ---- SSH -------------------------------------------------------------

    private record SshKeyType(String shortName, String matchStr, int prefixLength) {
    }

    private static final SshKeyType[] SSH_KEY_TYPES = {
            new SshKeyType("ecdsa-nistp256", "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB", 52),
            new SshKeyType("ecdsa-nistp384", "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABh", 52),
            new SshKeyType("ecdsa-nistp521", "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACF", 52),
            new SshKeyType("rsa", "AAAAB3NzaC1yc2EAAAADAQAB", 28),
            new SshKeyType("ed25519", "AAAAC3NzaC1lZDI1NTE5AAAA", 24),
            new SshKeyType("dss", "AAAAB3NzaC1kc3M", 15),
    };

    static Parsed parseSshKey(String text) {
        String payload = sshLineSplit(text);
        if (payload == null) {
            String[] m = sshKeyRegex(text);
            if (m != null) {
                return Parsed.of("SSH key", Alphabet.BASE64, m[0], m[1], null);
            }
            return null;
        }
        for (SshKeyType kt : SSH_KEY_TYPES) {
            if (payload.startsWith(kt.matchStr()) && len(payload) >= kt.prefixLength()) {
                int[] cps = payload.codePoints().toArray();
                String prefix = new String(cps, 0, kt.prefixLength());
                String body = new String(cps, kt.prefixLength(), cps.length - kt.prefixLength());
                return Parsed.of("SSH " + kt.shortName(), Alphabet.BASE64, prefix, body, null);
            }
        }
        String[] m = sshKeyRegex(payload);
        if (m != null) {
            return Parsed.of("SSH key", Alphabet.BASE64, m[0], m[1], null);
        }
        return null;
    }

    private static String[] sshKeyRegex(String text) {
        if (!text.startsWith("AAAA")) {
            return null;
        }
        String rest = text.substring(4);
        if (rest.isEmpty()) {
            return null;
        }
        int bodyEnd = rest.indexOf('=');
        if (bodyEnd < 0) {
            bodyEnd = rest.length();
        }
        String body = rest.substring(0, bodyEnd);
        String pad = rest.substring(bodyEnd);
        if (body.isEmpty()) {
            return null;
        }
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (!(isAsciiAlphanumeric(c) || c == '+' || c == '/')) {
                return null;
            }
        }
        if (pad.length() > 3) {
            return null;
        }
        for (int i = 0; i < pad.length(); i++) {
            if (pad.charAt(i) != '=') {
                return null;
            }
        }
        return new String[] {"AAAA", rest};
    }

    private static String sshLineSplit(String text) {
        String s = text;
        String[] typePrefixes = {
                "ssh-ed25519", "ssh-rsa", "ssh-dss",
                "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        };
        for (String tp : typePrefixes) {
            if (s.startsWith(tp)) {
                String rest = s.substring(tp.length());
                if (!rest.isEmpty() && isWhitespace(rest.charAt(0))) {
                    s = trimLeftWhitespace(rest);
                    break;
                }
            }
        }
        if (!s.startsWith("AAAA")) {
            return null;
        }
        int[] chars = s.codePoints().toArray();
        int i = 0;
        while (i < chars.length) {
            char c = (char) chars[i];
            if (isAsciiAlphanumeric(c) || c == '+' || c == '/') {
                i++;
            } else {
                break;
            }
        }
        while (i < chars.length && chars[i] == '=') {
            i++;
        }
        String payload = new String(chars, 0, i);
        if (!payload.startsWith("AAAA")) {
            return null;
        }
        String rest = new String(chars, i, chars.length - i);
        if (!rest.isEmpty() && !isWhitespace(rest.charAt(0))) {
            return null;
        }
        return payload;
    }

    private static String trimLeftWhitespace(String s) {
        int i = 0;
        while (i < s.length() && isWhitespace(s.charAt(i))) {
            i++;
        }
        return s.substring(i);
    }

    // ---- base58check verification ----------------------------------------

    /**
     * Decodes a base58 (Bitcoin alphabet) string to raw bytes, preserving
     * leading-zero bytes (each leading '1' is a 0x00 byte). Returns null if the
     * string contains a non-base58 character. Used only for checksum
     * verification; the visualized core is the original text.
     */
    private static byte[] base58DecodeBytes(String s) {
        java.math.BigInteger n = java.math.BigInteger.ZERO;
        java.math.BigInteger fifty8 = java.math.BigInteger.valueOf(58);
        for (int i = 0; i < s.length(); i++) {
            int v = BASE58_CHARS.indexOf(s.charAt(i));
            if (v < 0) {
                return null;
            }
            n = n.multiply(fifty8).add(java.math.BigInteger.valueOf(v));
        }
        byte[] body;
        if (n.signum() == 0) {
            body = new byte[0];
        } else {
            byte[] be = n.toByteArray();
            // BigInteger.toByteArray may prepend a 0x00 sign byte; strip it.
            int off = (be.length > 1 && be[0] == 0) ? 1 : 0;
            body = new byte[be.length - off];
            System.arraycopy(be, off, body, 0, body.length);
        }
        int pad = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '1') {
                pad++;
            } else {
                break;
            }
        }
        byte[] out = new byte[pad + body.length];
        System.arraycopy(body, 0, out, pad, body.length);
        return out;
    }

    /**
     * True iff {@code s} decodes to {@code payload || checksum} where checksum is
     * the first 4 bytes of double-SHA256(payload) — the near-universal
     * base58check construction (Bitcoin/Litecoin legacy). See docs/spec.md
     * "Checksum verification".
     */
    private static boolean base58checkOk(String s) {
        byte[] raw = base58DecodeBytes(s);
        if (raw == null || raw.length < 5) {
            return false;
        }
        int plen = raw.length - 4;
        byte[] payload = new byte[plen];
        System.arraycopy(raw, 0, payload, 0, plen);
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(md.digest(payload));
            for (int i = 0; i < 4; i++) {
                if (digest[i] != raw[plen + i]) {
                    return false;
                }
            }
            return true;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // ---- crypto addresses ------------------------------------------------

    static Parsed parseBitcoinAddress(String text) {
        if (!text.isEmpty()) {
            char first = text.charAt(0);
            if ("123mn".indexOf(first) >= 0) {
                String body = text.substring(1);
                int n = len(body);
                if (n >= 25 && n <= 34 && isBase58(body)) {
                    int[] bchars = body.codePoints().toArray();
                    String mid = new String(bchars, 0, bchars.length - 4);
                    String suf = new String(bchars, bchars.length - 4, 4);
                    int midLen = len(mid);
                    if (midLen >= 21 && midLen <= 30) {
                        // The 4-byte double-SHA256 checksum is surfaced as the
                        // suffix, so it MUST verify. A structural match with a
                        // bad checksum rejects.
                        if (!base58checkOk(text)) {
                            throw new ChecksumException("Bitcoin legacy",
                                    "Bitcoin legacy address fails its base58check (double-SHA256) checksum");
                        }
                        return Parsed.of("BTC legacy", Alphabet.BASE58, String.valueOf(first), mid, suf);
                    }
                }
            }
        }
        String[] pb = matchPrefixBech32(text, new String[] {"bc1", "tb1"}, 39, 69);
        if (pb != null) {
            // Bitcoin SegWit uses bech32 (BIP-173). Verify the polymod — a bad
            // checksum rejects.
            // pb[0] is "bc1"/"tb1" (HRP + '1' separator); the polymod HRP is the
            // HRP alone, so strip the trailing '1' before checking.
            String prefix = pb[0].toLowerCase(Locale.ROOT);
            String data = pb[1].toLowerCase(Locale.ROOT);
            if (!bech32ChecksumValid(rstripOne(prefix), data)) {
                throw new ChecksumException("Bitcoin segwit",
                        "Bitcoin segwit address fails its bech32 checksum");
            }
            return Parsed.of("BTC SegWit", Alphabet.BECH32, prefix, data, null);
        }
        return null;
    }

    /** Strips a single trailing {@code '1'} (bech32 HRP/separator split). */
    private static String rstripOne(String s) {
        return s.endsWith("1") ? s.substring(0, s.length() - 1) : s;
    }

    /**
     * True iff the bech32/bech32m polymod over {@code hrp}+{@code data} is valid
     * (constant 1 for bech32 or 0x2bc830a3 for bech32m). {@code data} is the
     * bech32 char string INCLUDING the 6 trailing checksum chars.
     */
    private static boolean bech32ChecksumValid(String hrp, String data) {
        long[] c = bech32ChecksumConst(hrp, data);
        return c != null && (c[0] == 1 || c[0] == 0x2bc830a3L);
    }

    private static String[] matchPrefixBech32(String text, String[] prefixes, int lo, int hi) {
        String low = text.toLowerCase(Locale.ROOT);
        for (String p : prefixes) {
            if (low.startsWith(p)) {
                int pn = len(p);
                int[] tr = text.codePoints().toArray();
                String prefix = new String(tr, 0, pn);
                String body = new String(tr, pn, tr.length - pn);
                int n = len(body);
                if (n >= lo && n <= hi && isBech32Either(body)) {
                    return new String[] {prefix, body};
                }
            }
        }
        return null;
    }

    static Parsed parseRippleAddress(String text) {
        if (text.startsWith("r")) {
            String rest = text.substring(1);
            if (len(rest) == 33 && isBase58(rest)) {
                return Parsed.of("XRP", Alphabet.BASE58, "r", rest, null);
            }
        }
        return null;
    }

    static Parsed parseEthereumAddress(String text) {
        boolean hasPrefix = false;
        String body = text;
        if (text.startsWith("0x") || text.startsWith("0X")) {
            hasPrefix = true;
            body = text.substring(2);
        }
        if (len(body) != 40 || !isHex(body)) {
            return null;
        }
        boolean hasLower = false;
        boolean hasUpper = false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (isAsciiAlpha(c)) {
                if (isAsciiLower(c)) {
                    hasLower = true;
                }
                if (isAsciiUpper(c)) {
                    hasUpper = true;
                }
            }
        }
        boolean isMixed = hasLower && hasUpper;

        if (!hasPrefix) {
            if (!isMixed) {
                return null;
            }
            validateEip55(body);
        } else if (isMixed) {
            validateEip55(body);
        }
        return Parsed.of("ETH", Alphabet.HEX, "0x", body.toLowerCase(Locale.ROOT), null);
    }

    private static void validateEip55(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        String digestHex = Keccak.keccak256Hex(lower.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (!isAsciiAlpha(c)) {
                continue;
            }
            boolean canonicalUpper = hexDigitValue(digestHex.charAt(i)) >= 8;
            char expected = canonicalUpper ? toUpperChar(c) : Core.toLowerChar(c);
            if (c != expected) {
                throw new Eip55Exception(i);
            }
        }
    }

    private static int hexDigitValue(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return 0;
    }

    private static char toUpperChar(char r) {
        if (r >= 'a' && r <= 'z') {
            return (char) (r - ('a' - 'A'));
        }
        return r;
    }

    static Parsed parseLitecoinAddress(String text) {
        for (String prefix : new String[] {"tL", "L"}) {
            if (text.startsWith(prefix)) {
                String rest = text.substring(prefix.length());
                if (len(rest) == 33 && isBase58(rest)) {
                    // Litecoin legacy is base58check; verify the double-SHA256
                    // checksum — a bad checksum rejects.
                    if (!base58checkOk(text)) {
                        throw new ChecksumException("Litecoin legacy",
                                "Litecoin legacy address fails its base58check (double-SHA256) checksum");
                    }
                    return Parsed.of("LTC legacy", Alphabet.BASE58, prefix, rest, null);
                }
            }
        }
        String[] pb = matchPrefixBech32(text, new String[] {"ltc1"}, 38, 68);
        if (pb != null) {
            // Modern Litecoin "ltc1…" uses bech32. Verify the polymod — a bad
            // checksum rejects.
            // pb[0] is "ltc1"; the polymod HRP is "ltc" (strip the separator).
            String prefix = pb[0].toLowerCase(Locale.ROOT);
            String data = pb[1].toLowerCase(Locale.ROOT);
            if (!bech32ChecksumValid(rstripOne(prefix), data)) {
                throw new ChecksumException("Litecoin",
                        "Litecoin address fails its bech32 checksum");
            }
            return Parsed.of("LTC", Alphabet.BECH32, prefix, data, null);
        }
        return null;
    }

    static Parsed parseBitcoinCashAddress(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        String prefix = null;
        String rest;
        if (low.startsWith("bitcoincash:")) {
            int n = "bitcoincash:".length();
            prefix = text.substring(0, n);
            rest = text.substring(n);
        } else if (low.startsWith("bchtest:")) {
            int n = "bchtest:".length();
            prefix = text.substring(0, n);
            rest = text.substring(n);
        } else {
            rest = text;
        }
        int[] rchars = rest.codePoints().toArray();
        if (rchars.length > 0) {
            char first = (char) rchars[0];
            if ((first == 'p' || first == 'q' || first == 'P' || first == 'Q') && rchars.length == 42) {
                String body = new String(rchars, 1, rchars.length - 1);
                if (isBech32Either(body)) {
                    // Verify the 40-bit CashAddr BCH checksum (a DIFFERENT
                    // code from bech32's polymod). The checksum HRP is the prefix
                    // WITHOUT the colon, defaulting to "bitcoincash" for a bare
                    // q…/p… address; the payload (INCLUDING its 8 trailing
                    // checksum chars) is the full `rest`. A structural CashAddr
                    // match with a bad checksum is REJECTED.
                    String hrp = (prefix == null ? "bitcoincash:" : prefix)
                            .replace(":", "").toLowerCase(Locale.ROOT);
                    if (!cashaddrVerify(hrp, rest)) {
                        throw new ChecksumException("Bitcoin Cash",
                                "Bitcoin Cash address fails its CashAddr checksum");
                    }
                    return Parsed.of("BCH", Alphabet.BECH32, prefix, rest.toLowerCase(Locale.ROOT), null);
                }
            }
        }
        return null;
    }

    // ---- CashAddr 40-bit BCH checksum ------------------------------------

    /**
     * CashAddr generator rows of the 40-bit BCH code used by Bitcoin Cash — a
     * DIFFERENT code from bech32's 30-bit BIP-173 polymod.
     */
    private static final long[] CASHADDR_GEN = {
            0x98f2bc8e61L, 0x79b76d99e2L, 0xf33e5fb3c4L, 0xae2eabe2a8L, 0x1e4f43e470L,
    };

    /**
     * The 40-bit BCH checksum polymod used by Bitcoin Cash CashAddr (NOT the
     * bech32 polymod). {@code values} is a list of 5-bit ints; valid iff this
     * returns 0. A {@code long} holds the 40-bit accumulator.
     */
    private static long cashaddrPolymod(int[] values) {
        long c = 1;
        for (int d : values) {
            long c0 = c >> 35;
            c = ((c & 0x07ffffffffL) << 5) ^ d;
            for (int i = 0; i < 5; i++) {
                if (((c0 >> i) & 1) != 0) {
                    c ^= CASHADDR_GEN[i];
                }
            }
        }
        return c ^ 1;
    }

    /**
     * True iff CashAddr {@code payload} (bech32-charset body INCLUDING the
     * trailing 8 checksum chars) carries a valid BCH checksum under {@code
     * prefix} (lowercase, e.g. {@code "bitcoincash"} / {@code "bchtest"}).
     */
    private static boolean cashaddrVerify(String prefix, String payload) {
        String low = payload.toLowerCase(Locale.ROOT);
        int[] values = new int[prefix.length() + 1 + low.length()];
        int p = 0;
        for (int i = 0; i < prefix.length(); i++) {
            values[p++] = prefix.charAt(i) & 0x1f;
        }
        values[p++] = 0;
        for (int i = 0; i < low.length(); i++) {
            int idx = BECH32_CHARS.indexOf(low.charAt(i));
            if (idx < 0) {
                return false;
            }
            values[p++] = idx;
        }
        return cashaddrPolymod(values) == 0;
    }

    static Parsed parseStellarAddress(String text) {
        int[] chars = text.codePoints().toArray();
        if (chars.length > 0) {
            char first = (char) chars[0];
            if ((first == 'G' || first == 'g') && chars.length == 56) {
                String body = new String(chars, 1, chars.length - 1);
                if (isBase32Either(body)) {
                    return Parsed.of("XLM", Alphabet.BASE32, "G", body.toUpperCase(Locale.ROOT), null);
                }
            }
            if ((first == 'M' || first == 'm') && chars.length == 69) {
                String body = new String(chars, 1, chars.length - 1);
                if (isBase32Either(body)) {
                    return Parsed.of("XLM muxed", Alphabet.BASE32, "M", body.toUpperCase(Locale.ROOT), null);
                }
            }
        }
        return null;
    }

    // ---- UUID / ULID / snowflake / LEI -----------------------------------

    static Parsed parseUuid(String text) {
        String s = text;
        if (s.startsWith("{")) {
            s = s.substring(1);
        }
        if (s.endsWith("}")) {
            s = s.substring(0, s.length() - 1);
        }
        int[] groups = {8, 4, 4, 4, 12};
        StringBuilder stripped = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '-') {
                stripped.append(c);
            }
        }
        String st = stripped.toString();
        if (len(st) != 32 || !isHex(st)) {
            return null;
        }
        int[] sc = s.codePoints().toArray();
        int pos = 0;
        for (int gi = 0; gi < groups.length; gi++) {
            for (int k = 0; k < groups[gi]; k++) {
                if (pos >= sc.length || !isAsciiHexDigit((char) sc[pos])) {
                    return null;
                }
                pos++;
            }
            if (gi < groups.length - 1 && pos < sc.length && sc[pos] == '-') {
                pos++;
            }
        }
        if (pos != sc.length) {
            return null;
        }
        return Parsed.of("UUID", Alphabet.HEX, null, st.toLowerCase(Locale.ROOT), null);
    }

    static Parsed parseUlid(String text) {
        if (len(text) != 26) {
            return null;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean ok = isAsciiDigit(c)
                    || (c >= 'A' && c <= 'T')
                    || (c >= 'V' && c <= 'Z')
                    || (c >= 'a' && c <= 't')
                    || (c >= 'v' && c <= 'z');
            if (!ok) {
                return null;
            }
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case 'I', 'i', 'L', 'l' -> b.append('1');
                case 'O', 'o' -> b.append('0');
                default -> b.append(c);
            }
        }
        String normalized = b.toString().toUpperCase(Locale.ROOT);
        return Parsed.of("ULID", Alphabet.CROCKFORD32, null, normalized, null);
    }

    static Parsed parseSnowflake(String text) {
        int n = len(text);
        if (n < 17 || n > 20) {
            return null;
        }
        for (int i = 0; i < text.length(); i++) {
            if (!isAsciiDigit(text.charAt(i))) {
                return null;
            }
        }
        long[] val = parseUint64Dec(text);
        if (val == null) {
            return null;
        }
        if (Long.compareUnsigned(val[0] >>> 63, 0) != 0) {
            return null;
        }
        return Parsed.of("snowflake", Alphabet.DECIMAL, null, text, null);
    }

    /** Parses a decimal string into uint64; returns null on overflow. */
    private static long[] parseUint64Dec(String s) {
        long v = 0;
        long umax = -1L; // 0xFFFFFFFFFFFFFFFF unsigned
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            long d = c - '0';
            // overflow check: v > (UMAX - d) / 10  (unsigned)
            long bound = Long.divideUnsigned(umax - d, 10);
            if (Long.compareUnsigned(v, bound) > 0) {
                return null;
            }
            v = v * 10 + d;
        }
        return new long[] {v};
    }

    static Parsed parseLei(String text) {
        if (len(text) != 20) {
            return null;
        }
        for (int i = 0; i < text.length(); i++) {
            if (!isAsciiAlphanumeric(text.charAt(i))) {
                return null;
            }
        }
        String upper = text.toUpperCase(Locale.ROOT);
        if (!upper.substring(4, 6).equals("00")) {
            // Missing the reserved "00" -> not a clear LEI; fall through so a bare
            // 20-char base36 string can still be recognized as an encoding.
            return null;
        }
        if (!leiChecksumOk(upper)) {
            // 20 base36 chars WITH the reserved "00" is an unambiguous LEI
            // match, and the MOD 97-10 check digits are surfaced as the bound
            // suffix — so a bad checksum REJECTS rather than falling through to a
            // generic base36 encoding. See docs/spec.md "Checksum verification".
            throw new ChecksumException("LEI", "LEI fails its MOD 97-10 checksum");
        }
        return Parsed.of("LEI", Alphabet.BASE36, null, upper.substring(0, 18), upper.substring(18));
    }

    private static boolean leiChecksumOk(String lei) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < lei.length(); i++) {
            char c = lei.charAt(i);
            if (isAsciiDigit(c)) {
                digits.append(c);
            } else if (isAsciiUpper(c)) {
                digits.append(c - 'A' + 10);
            } else {
                return false;
            }
        }
        long rem = 0;
        String ds = digits.toString();
        for (int i = 0; i < ds.length(); i++) {
            rem = (rem * 10 + (ds.charAt(i) - '0')) % 97;
        }
        return rem == 1;
    }

    // ---- DID / URN -------------------------------------------------------

    /**
     * Parses a W3C DID (or DID URL): {@code did:<method>:<method-specific-id>}.
     *
     * <p>The method name is IDENTITY (bound by PREFIX-FOLD via the semantic
     * prefix {@code did:<method>:}); the method-specific-id is the core, kept
     * VERBATIM (not percent-decoded, not case-folded) and tokenized as
     * base64url. Any DID-URL tail ({@code /path}, {@code ?query}, {@code #frag})
     * is a free annotation and is DROPPED.
     */
    static Parsed parseDid(String text) {
        if (text.isEmpty()) {
            return null;
        }
        Matcher m = DID_REGEX.matcher(text);
        if (!m.matches()) {
            return null;
        }
        String prefix = "did:" + m.group(1) + ":";
        return Parsed.of("", Alphabet.BASE64URL, prefix, m.group(2), null).semantic();
    }

    /**
     * Parses an RFC 8141 URN: {@code urn:<NID>:<NSS>}.
     *
     * <p>The scheme + NID are case-INSENSITIVE: the {@code urn:<nid>:} prefix is
     * LOWERCASED (and bound by PREFIX-FOLD), while the NSS core case is
     * PRESERVED. The NSS keeps internal {@code :} and {@code /} and ends only at
     * a {@code ?} or {@code #} component, which is DROPPED.
     */
    static Parsed parseUrn(String text) {
        if (text.isEmpty()) {
            return null;
        }
        Matcher m = URN_REGEX.matcher(text);
        if (!m.matches()) {
            return null;
        }
        String prefix = "urn:" + m.group(1).toLowerCase(Locale.ROOT) + ":";
        return Parsed.of("", Alphabet.BASE64URL, prefix, m.group(2), null).semantic();
    }

    // ---- SWHID / gitoid --------------------------------------------------

    static Parsed parseSwhid(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        String[] types = {"snp", "rel", "rev", "dir", "cnt"};
        for (String t : types) {
            String pre = "swh:1:" + t + ":";
            if (low.startsWith(pre)) {
                String rest = low.substring(pre.length());
                String hexpart = rest;
                int idx = rest.indexOf(';');
                if (idx >= 0) {
                    hexpart = rest.substring(0, idx);
                }
                if (len(hexpart) == 40 && isHex(hexpart)) {
                    String prefix = text.substring(0, pre.length());
                    return Parsed.of("", Alphabet.HEX, prefix.toLowerCase(Locale.ROOT), hexpart, null).semantic();
                }
            }
        }
        return null;
    }

    static Parsed parseGitoid(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        if (!low.startsWith("gitoid:")) {
            return null;
        }
        String[] parts = splitN(low, ':', 4);
        if (parts.length != 4) {
            return null;
        }
        String obj = parts[1];
        String algo = parts[2];
        String body = parts[3];
        if (!obj.equals("blob") && !obj.equals("tree") && !obj.equals("commit") && !obj.equals("tag")) {
            return null;
        }
        int want;
        switch (algo) {
            case "sha1" -> want = 40;
            case "sha256" -> want = 64;
            default -> {
                return null;
            }
        }
        if (len(body) != want || !isHex(body)) {
            return null;
        }
        String prefix = "gitoid:" + obj + ":" + algo + ":";
        return Parsed.of("", Alphabet.HEX, prefix, body, null).semantic();
    }

    private static String[] splitN(String s, char sep, int n) {
        List<String> out = new ArrayList<>();
        int start = 0;
        while (out.size() < n - 1) {
            int idx = s.indexOf(sep, start);
            if (idx < 0) {
                break;
            }
            out.add(s.substring(start, idx));
            start = idx + 1;
        }
        out.add(s.substring(start));
        return out.toArray(new String[0]);
    }

    // ---- generic bech32 (Cosmos-style) -----------------------------------

    private static long bech32Polymod(int[] values) {
        long[] gen = {0x3b6a57b2L, 0x26508e6dL, 0x1ea119faL, 0x3d4233ddL, 0x2a1462b3L};
        long chk = 1;
        for (int v : values) {
            long top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (int i = 0; i < gen.length; i++) {
                if (((top >> i) & 1) != 0) {
                    chk ^= gen[i];
                }
            }
        }
        return chk;
    }

    private static int[] bech32HrpExpand(String hrp) {
        int[] out = new int[hrp.length() * 2 + 1];
        int p = 0;
        for (int i = 0; i < hrp.length(); i++) {
            out[p++] = hrp.charAt(i) >> 5;
        }
        out[p++] = 0;
        for (int i = 0; i < hrp.length(); i++) {
            out[p++] = hrp.charAt(i) & 31;
        }
        return out;
    }

    private static long[] bech32ChecksumConst(String hrp, String data) {
        int[] values = new int[data.length()];
        for (int i = 0; i < data.length(); i++) {
            int idx = BECH32_CHARS.indexOf(data.charAt(i));
            if (idx < 0) {
                return null;
            }
            values[i] = idx;
        }
        int[] expand = bech32HrpExpand(hrp);
        int[] full = new int[expand.length + values.length];
        System.arraycopy(expand, 0, full, 0, expand.length);
        System.arraycopy(values, 0, full, expand.length, values.length);
        return new long[] {bech32Polymod(full)};
    }

    static Parsed parseBech32Address(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        int[] chars = low.codePoints().toArray();
        List<Integer> sepCandidates = new ArrayList<>();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '1') {
                sepCandidates.add(i);
            }
        }
        for (int i = sepCandidates.size() - 1; i >= 0; i--) {
            int sep = sepCandidates.get(i);
            if (sep < 1 || sep > 83) {
                continue;
            }
            String hrp = new String(chars, 0, sep);
            boolean hrpOk = true;
            for (int j = 0; j < hrp.length(); j++) {
                if (!isAsciiLower(hrp.charAt(j))) {
                    hrpOk = false;
                    break;
                }
            }
            if (!hrpOk) {
                continue;
            }
            String data = new String(chars, sep + 1, chars.length - (sep + 1));
            if (len(data) < 8 || !allIn(data, BECH32_CHARS)) {
                continue;
            }
            long[] c = bech32ChecksumConst(hrp, data);
            if (c != null && (c[0] == 1 || c[0] == 0x2bc830a3L)) {
                int[] dchars = data.codePoints().toArray();
                String core = new String(dchars, 0, dchars.length - 6);
                String suffix = new String(dchars, dchars.length - 6, 6);
                return Parsed.of("bech32", Alphabet.BECH32, hrp + "1", core, suffix);
            }
            // A `<hrp>1<data>` string with 8+ bech32 chars is a clear
            // bech32 structural match, and the 6-char checksum is surfaced as the
            // bound suffix — so an invalid polymod REJECTS rather than falling
            // through to a bare bech32 encoding (which would render an address
            // that fails its own checksum). Mirrors the specific bc1/ltc1
            // parsers. See docs/spec.md "Checksum verification".
            throw new ChecksumException("bech32",
                    "bech32 address fails its bech32 checksum");
        }
        return null;
    }

    // ---- IPFS CID --------------------------------------------------------

    static Parsed parseIpfsCid(String text) {
        if (text.startsWith("Qm")) {
            String rest = text.substring(2);
            if (len(rest) == 44 && isBase58(rest)) {
                return Parsed.of("CIDv0", Alphabet.BASE58, "Qm", rest, null);
            }
        }
        if (text.startsWith("b")) {
            String rest = text.substring(1);
            int n = len(rest);
            if (n >= 58 && n <= 112 && isBase32Either(rest)) {
                String label = "CIDv1";
                String[] cm = b32DecodeMulticodec(rest);
                if (cm != null) {
                    label = "CIDv1 " + cm[0];
                    if (!cm[1].equals("sha2-256")) {
                        label += "/" + cm[1];
                    }
                }
                return Parsed.of(label, Alphabet.BASE32, "b", rest.toUpperCase(Locale.ROOT), null);
            }
        }
        return null;
    }

    private static String[] b32DecodeMulticodec(String body) {
        byte[] bytes = base32Decode(body.toUpperCase(Locale.ROOT));
        if (bytes == null) {
            return null;
        }
        long[] r0 = readUvarint(bytes, 0);
        if (r0 == null || r0[0] != 1) {
            return null;
        }
        long[] r1 = readUvarint(bytes, (int) r0[1]);
        if (r1 == null) {
            return null;
        }
        long[] r2 = readUvarint(bytes, (int) r1[1]);
        if (r2 == null) {
            return null;
        }
        String codecName = multicodecContent(r1[0]);
        if (codecName == null) {
            return null;
        }
        String hashName = multihashFunc(r2[0]);
        if (hashName == null) {
            return null;
        }
        return new String[] {codecName, hashName};
    }

    /** Returns {value, nextPos} or null on truncation. */
    private static long[] readUvarint(byte[] data, int pos) {
        long result = 0;
        int shift = 0;
        while (pos < data.length) {
            int b = data[pos] & 0xFF;
            pos++;
            result |= ((long) (b & 0x7f)) << shift;
            if ((b & 0x80) == 0) {
                return new long[] {result, pos};
            }
            shift += 7;
        }
        return null;
    }

    private static byte[] base32Decode(String s) {
        int bits = 0;
        int value = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            int idx = BASE32_CHARS_UP.indexOf(s.charAt(i));
            if (idx < 0) {
                return null;
            }
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((value >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static String multicodecContent(long code) {
        return switch ((int) code) {
            case 0x00 -> "identity";
            case 0x51 -> "cbor";
            case 0x55 -> "raw";
            case 0x60 -> "rlp";
            case 0x70 -> "dag-pb";
            case 0x71 -> "dag-cbor";
            case 0x72 -> "libp2p-key";
            case 0x78 -> "git-raw";
            case 0x90 -> "eth-block";
            case 0x97 -> "eth-tx";
            case 0x0129 -> "dag-json";
            case 0x0202 -> "car";
            default -> null;
        };
    }

    private static String multihashFunc(long code) {
        return switch ((int) code) {
            case 0x11 -> "sha1";
            case 0x12 -> "sha2-256";
            case 0x13 -> "sha2-512";
            case 0x14 -> "sha3-224";
            case 0x15 -> "sha3-256";
            case 0x16 -> "sha3-384";
            case 0x17 -> "sha3-512";
            case 0x1b -> "keccak-256";
            case 0x41 -> "blake2b-256";
            default -> null;
        };
    }

    // ---- hex / EOS -------------------------------------------------------

    static Parsed parseHexFormat(String text) {
        if (text.isEmpty()) {
            return null;
        }
        String prefix = null;
        String body = text;
        if ((text.startsWith("0x") || text.startsWith("0X")) && len(text) > 2) {
            prefix = "0x";
            body = text.substring(2);
        } else if (len(text) % 2 != 0) {
            return null;
        }
        if (isHex(body)) {
            return Parsed.of("hex", Alphabet.HEX, prefix, body.toLowerCase(Locale.ROOT), null);
        }
        return null;
    }

    static Parsed parseEosAddress(String text) {
        if (!eosRegex(text)) {
            return null;
        }
        boolean allHex = true;
        for (int i = 0; i < text.length(); i++) {
            if ("0123456789abcdef".indexOf(text.charAt(i)) < 0) {
                allHex = false;
                break;
            }
        }
        if (allHex) {
            return null;
        }
        return Parsed.of("EOS", Alphabet.BASE64, null, text, null);
    }

    private static boolean eosRegex(String text) {
        int[] chars = text.codePoints().toArray();
        int n = chars.length;
        if (n >= 2 && n <= 12) {
            char last = (char) chars[n - 1];
            if (eosBodyOk(chars, 0, n - 1) && (isAsciiLower(last) || (last >= '1' && last <= '5'))) {
                return true;
            }
        }
        if (n == 13) {
            char last = (char) chars[12];
            if (eosBodyOk(chars, 0, 12) && ((last >= 'a' && last <= 'j') || (last >= '1' && last <= '5'))) {
                return true;
            }
        }
        return false;
    }

    private static boolean eosBodyOk(int[] chars, int from, int to) {
        for (int i = from; i < to; i++) {
            char c = (char) chars[i];
            if (!(isAsciiLower(c) || (c >= '1' && c <= '5') || c == '.')) {
                return false;
            }
        }
        return true;
    }

    // ---- dispatch --------------------------------------------------------

    @FunctionalInterface
    private interface ParserFn {
        Parsed apply(String text);
    }

    private static final ParserFn[] PARSERS = {
            Entropy::parseCesr,
            Entropy::parseSshKey,
            Entropy::parseBitcoinAddress,
            Entropy::parseRippleAddress,
            Entropy::parseEthereumAddress,
            Entropy::parseLitecoinAddress,
            Entropy::parseBitcoinCashAddress,
            Entropy::parseStellarAddress,
            Entropy::parseUuid,
            Entropy::parseUlid,
            Entropy::parseSnowflake,
            Entropy::parseLei,
            Entropy::parseDid,
            Entropy::parseUrn,
            Entropy::parseSwhid,
            Entropy::parseGitoid,
            Entropy::parseBech32Address,
            Entropy::parseIpfsCid,
            Entropy::parseHexFormat,
            Entropy::parseEosAddress,
    };

    /**
     * Classifies the (already-trimmed) entropy string. Returns the recognized
     * {@link Parsed}, or null when nothing matches (caller re-encodes to
     * base64url). Throws {@link Eip55Exception} on a hard rejection.
     */
    static Parsed parse(String entropy) {
        entropy = entropy.strip();
        for (ParserFn f : PARSERS) {
            Parsed p = f.apply(entropy);
            if (p != null) {
                return p;
            }
        }
        Alphabet detected = detectAlphabetByDisproof(entropy);
        if (detected != null) {
            String core = switch (detected.name()) {
                case "base32" -> entropy.toUpperCase(Locale.ROOT);
                case "bech32", "hex" -> entropy.toLowerCase(Locale.ROOT);
                default -> entropy;
            };
            return Parsed.of(detected.name(), detected, null, core, null);
        }
        return null;
    }

    private record DisproofEntry(Alphabet alpha, String charset, boolean caseSensitive) {
    }

    private static Alphabet detectAlphabetByDisproof(String text) {
        if (text.isEmpty()) {
            return null;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        DisproofEntry[] order = {
                new DisproofEntry(Alphabet.HEX, HEX_CHARS_LOWER, false),
                new DisproofEntry(Alphabet.BASE32, "abcdefghijklmnopqrstuvwxyz234567", false),
                new DisproofEntry(Alphabet.BECH32, BECH32_CHARS, false),
                new DisproofEntry(Alphabet.BASE58, BASE58_CHARS, true),
                new DisproofEntry(Alphabet.BASE64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true),
                new DisproofEntry(Alphabet.BASE64URL, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", true),
        };
        for (DisproofEntry e : order) {
            String view = e.caseSensitive() ? text : lower;
            if (allIn(view, e.charset())) {
                return e.alpha();
            }
        }
        return null;
    }

    // ---- large-input tokenization ----------------------------------------

    private static final int HEAD_TOKENS = 8;
    private static final int TAIL_TOKENS = 8;
    private static final int MAX_TOKENS = 22;

    private static int coreByteLength(String core, Alphabet alphabet) {
        return (len(core) * alphabet.bitsPerChar()) / 8;
    }

    /** Encodes a 24-bit value as 5 lowercase Crockford base32 chars. */
    private static String crockford5(int value) {
        final String c = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        char[] out = new char[5];
        int v = value;
        for (int i = 0; i < 5; i++) {
            out[4 - i] = c.charAt(v & 0x1F);
            v >>= 5;
        }
        return new String(out).toLowerCase(Locale.ROOT);
    }

    /** Result of {@link #tokenizeEntropy}: the token list plus the truncation flag. */
    record TokenizeResult(List<Token> tokens, boolean truncated) {
    }

    /** Tokenizes entropy, applying large-input (head/middle/tail) handling. */
    static TokenizeResult tokenizeEntropy(String core, Alphabet alphabet) {
        int tokenLen = 24 / alphabet.bitsPerChar();
        int nBytes = coreByteLength(core, alphabet);
        int runeCount = len(core);
        int tokenCount = (runeCount + tokenLen - 1) / tokenLen;
        if (tokenCount <= MAX_TOKENS && nBytes <= 64) {
            return new TokenizeResult(Core.tokenize(core, alphabet), false);
        }
        int[] chars = core.codePoints().toArray();
        int headChars = HEAD_TOKENS * tokenLen;
        int tailChars = TAIL_TOKENS * tokenLen;
        int headEnd = Math.min(headChars, chars.length);
        String head = new String(chars, 0, headEnd);
        int tailStart = Math.max(chars.length - tailChars, 0);
        String tail = new String(chars, tailStart, chars.length - tailStart);
        List<Token> headTokensList = Core.tokenize(head, alphabet);
        List<Token> tailTokensList = Core.tokenize(tail, alphabet);

        byte[] second = Core.secondDigest(core);
        List<Token> middle = new ArrayList<>(4);
        for (int i = 0; i < 4; i++) {
            int quant = ((second[3 * i] & 0xFF) << 16)
                    | ((second[3 * i + 1] & 0xFF) << 8)
                    | (second[3 * i + 2] & 0xFF);
            middle.add(new Token(crockford5(quant), i, quant));
        }

        List<Token> combined = new ArrayList<>();
        combined.addAll(headTokensList);
        combined.addAll(middle);
        combined.addAll(tailTokensList);
        List<Token> renumbered = new ArrayList<>(combined.size());
        for (int i = 0; i < combined.size(); i++) {
            Token t = combined.get(i);
            renumbered.add(new Token(t.text(), i, t.quant()));
        }
        return new TokenizeResult(renumbered, true);
    }
}
