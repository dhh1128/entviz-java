package io.github.dhh1128.entviz;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Entropy characterization model (spec v13).
 *
 * <p>Faithful port of the certified reference {@code characterize.py}. The
 * parser ({@link Entropy#parse}) produces a {@link Parsed} display record whose
 * {@code typeName} fuses several orthogonal facts (scheme, semantic role,
 * network/variant, size). {@link #characterize} re-expresses that recognition
 * along independent axes so downstream consumers read structured fields instead
 * of string-parsing the label.
 *
 * <p>The characterization is REPORTING-ONLY. It changes no rendered pixel, no
 * fingerprint input, and no label string. {@link Pipeline} emits the eight
 * fields onto the root {@code <svg>} as {@code data-*} attributes, and the
 * conformance model extractor recovers them from those attributes.
 *
 * <p>Axes (identical field set for every input): {@code encoding}, {@code
 * scheme} (nullable), {@code role} (closed enum or null), {@code qualifiers}
 * (ordered map), {@code sizeBasis} ({@code "decoded"}|{@code "utf8"}), {@code
 * sizeBits} (multiple of 8, CORE only, reporting-only), {@code parts} (ordered
 * [{text, bind}]), {@code entropyType} (= scheme ?? encoding).
 */
final class Characterize {

    private Characterize() {
    }

    // Closed role enum (spec v13). Nothing outside this set may appear.
    static final String ROLE_KEY = "key";
    static final String ROLE_SIGNATURE = "signature";
    static final String ROLE_DIGEST = "digest";
    static final String ROLE_ADDRESS = "address";
    static final String ROLE_IDENTIFIER = "identifier";

    // The public 8-field characterization and its ordered [{text, bind}] Part
    // are top-level public types (see Characterization.java, Part.java) so the
    // structured recognition is reachable through Entviz#characterize(String).

    // Non-power-of-2 alphabets whose true density is below the token-packing
    // bits_per_char convention. For these, sizeBits decodes the core as a big
    // integer and takes its minimal byte length (Resolution A).
    private static boolean isIntegerDecodeAlphabet(Alphabet a) {
        String n = a.name();
        return n.equals("base58") || n.equals("base36") || n.equals("decimal");
    }

    // CESR derivation-code role classification, keyed off the decoded primitive
    // name the parser puts in typeName ("CESR <name>").
    private static final String[] CESR_DIGEST_MARKERS =
            {"blake3", "blake2b", "blake2s", "sha3", "sha2", "sha"};

    private static String cesrRole(String name) {
        String low = name.toLowerCase(Locale.ROOT);
        if (low.contains("sig")) {
            return ROLE_SIGNATURE;
        }
        for (String m : CESR_DIGEST_MARKERS) {
            if (low.contains(m)) {
                return ROLE_DIGEST;
            }
        }
        // seeds, public keys, ciphers, blinding factors, random numbers, tags.
        return ROLE_KEY;
    }

    private static long decodedBytesInteger(String core, Alphabet alphabet) {
        String chars = alphabet.chars();
        String lower = chars.toLowerCase(Locale.ROOT);
        int base = chars.length();
        BigInteger n = BigInteger.ZERO;
        BigInteger bigBase = BigInteger.valueOf(base);
        for (int i = 0; i < core.length(); i++) {
            char c = core.charAt(i);
            int v = chars.indexOf(c);
            if (v < 0) {
                v = lower.indexOf(Character.toLowerCase(c));
            }
            if (v < 0) {
                v = 0;
            }
            n = n.multiply(bigBase).add(BigInteger.valueOf(v));
        }
        if (n.signum() == 0) {
            return 1;
        }
        return (n.bitLength() + 7) / 8;
    }

    private static long sizeBits(String core, Alphabet alphabet, String sizeBasis) {
        if (sizeBasis.equals("utf8")) {
            return (long) core.getBytes(StandardCharsets.UTF_8).length * 8;
        }
        if (isIntegerDecodeAlphabet(alphabet)) {
            return decodedBytesInteger(core, alphabet) * 8;
        }
        return ((long) core.length() * alphabet.bitsPerChar() / 8) * 8;
    }

    /** Holds (scheme, role, qualifiers, sizeBasis) — the scheme-driven facts. */
    private record Described(String scheme, String role, Map<String, Object> qualifiers, String sizeBasis) {
    }

    private static Described describeFromParsed(Parsed parsed) {
        String typeName = parsed.typeName() == null ? "" : parsed.typeName();
        String prefix = parsed.prefix();
        Map<String, Object> q = new LinkedHashMap<>();

        // --- Folded identity prefixes: did / urn / gitoid / swhid ---
        if (prefix != null && parsed.prefixSemantic()) {
            if (prefix.startsWith("did:")) {
                String method = stripTrailingColons(prefix.substring("did:".length()));
                q.put("method", method);
                if (method.equals("ethr")) {
                    String head = splitFirst(parsed.core(), ':');
                    q.put("network", head);
                }
                return new Described("did", ROLE_IDENTIFIER, q, "utf8");
            }
            if (prefix.startsWith("urn:")) {
                String nid = stripTrailingColons(prefix.substring("urn:".length()));
                q.put("nid", nid);
                return new Described("urn", ROLE_IDENTIFIER, q, "utf8");
            }
            if (prefix.startsWith("gitoid:")) {
                String[] segs = stripColons(prefix).split(":");
                if (segs.length >= 3) {
                    q.put("object", segs[1]);
                    q.put("algorithm", segs[2]);
                }
                return new Described("gitoid", ROLE_DIGEST, q, "decoded");
            }
            if (prefix.startsWith("swh:")) {
                String[] segs = stripColons(prefix).split(":");
                if (segs.length >= 3) {
                    q.put("object", segs[2]);
                }
                q.put("algorithm", "sha1");
                return new Described("swhid", ROLE_DIGEST, q, "decoded");
            }
        }

        // --- CESR primitives: "CESR <decoded-name>" ---
        if (typeName.startsWith("CESR ")) {
            String name = typeName.substring("CESR ".length());
            q.put("algorithm", name);
            return new Described("cesr", cesrRole(name), q, "decoded");
        }

        // --- SSH public keys: "SSH <algorithm>" or "SSH key" ---
        if (typeName.startsWith("SSH")) {
            String rest = typeName.substring("SSH".length()).strip();
            if (!rest.isEmpty() && !rest.equals("key")) {
                q.put("algorithm", rest);
            }
            return new Described("ssh", ROLE_KEY, q, "decoded");
        }

        // --- Blockchain addresses ---
        if (typeName.startsWith("BTC")) {
            q.put("network", "mainnet");
            String low = typeName.toLowerCase(Locale.ROOT);
            if (low.contains("legacy")) {
                q.put("variant", "legacy");
            } else if (low.contains("segwit")) {
                q.put("variant", "segwit");
            }
            return new Described("btc", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.equals("BCH")) {
            String p = prefix == null ? "" : prefix.toLowerCase(Locale.ROOT);
            q.put("network", p.startsWith("bchtest") ? "testnet" : "mainnet");
            return new Described("bch", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.startsWith("LTC")) {
            q.put("network", "mainnet");
            if (typeName.toLowerCase(Locale.ROOT).contains("legacy")) {
                q.put("variant", "legacy");
            }
            return new Described("ltc", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.startsWith("ADA")) {
            if (typeName.contains("Byron")) {
                q.put("variant", "byron");
            } else if (typeName.contains("Shelley")) {
                q.put("variant", "shelley");
            }
            return new Described("ada", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.equals("ETH")) {
            return new Described("eth", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.startsWith("XLM")) {
            if (typeName.contains("muxed")) {
                q.put("variant", "muxed");
            }
            return new Described("stellar", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.equals("XRP")) {
            return new Described("xrp", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.equals("EOS")) {
            return new Described("eos", ROLE_ADDRESS, q, "decoded");
        }
        if (typeName.equals("bech32")) {
            if (prefix != null && prefix.endsWith("1")) {
                q.put("hrp", prefix.substring(0, prefix.length() - 1));
            }
            return new Described("bech32", ROLE_ADDRESS, q, "decoded");
        }

        // --- Content identifiers (IPFS CID) ---
        if (typeName.startsWith("CIDv")) {
            if (typeName.startsWith("CIDv0")) {
                q.put("version", 0);
                q.put("codec", "dag-pb");
                q.put("hash", "sha2-256");
            } else {
                q.put("version", 1);
                String rest = typeName.substring("CIDv1".length()).strip();
                if (!rest.isEmpty()) {
                    int slash = rest.indexOf('/');
                    if (slash >= 0) {
                        q.put("codec", rest.substring(0, slash));
                        q.put("hash", rest.substring(slash + 1));
                    } else {
                        q.put("codec", rest);
                        q.put("hash", "sha2-256");
                    }
                }
            }
            return new Described("cid", ROLE_IDENTIFIER, q, "decoded");
        }

        // --- Structured identifiers ---
        if (typeName.equals("UUID")) {
            return new Described("uuid", ROLE_IDENTIFIER, q, "decoded");
        }
        if (typeName.equals("ULID")) {
            return new Described("ulid", ROLE_IDENTIFIER, q, "decoded");
        }
        if (typeName.equals("LEI")) {
            return new Described("lei", ROLE_IDENTIFIER, q, "decoded");
        }
        if (typeName.equals("snowflake")) {
            return new Described("snowflake", ROLE_IDENTIFIER, q, "decoded");
        }
        if (typeName.startsWith("multihash") || typeName.contains("multihash")) {
            return new Described("multihash", ROLE_DIGEST, q, "decoded");
        }

        // --- Bare encodings (hex / base64 / base64url / disproof fallbacks) ---
        return new Described(null, null, q, "decoded");
    }

    private static List<Part> partsFromParsed(Parsed parsed) {
        List<Part> parts = new ArrayList<>();
        if (parsed.prefix() != null) {
            String bind = parsed.prefixSemantic() ? "fold" : "none";
            parts.add(new Part(parsed.prefix(), bind));
        }
        parts.add(new Part(parsed.core(), "core"));
        if (parsed.suffix() != null) {
            parts.add(new Part(parsed.suffix(), "none"));
        }
        return parts;
    }

    // ---- Label projection (spec v15) ----------------------------------------
    //
    // The visible top/bottom label strips are a PURE PROJECTION of the eight
    // characterization fields through one grammar — no per-parser string fusing.
    // Every implementation renders the same strips by running this same
    // projection over the shared fields.
    //
    //   top    = [+hash ]PRIMARY[, MOD]...[, SIZE][, PREFIX]
    //   bottom = ...<suffix>[ (<note>)]
    //
    // Slot separator is ", " (comma-space); no trailing ':' or '...'. See
    // docs/spec.md -> "Label strips" and characterize.py render_label.

    // v15: large-input truncation marker. Prepended (bold dark-red, by the
    // renderer) to the top label when the text channel is a
    // head/fingerprint-middle/tail readout rather than a linear scan. Reads as
    // "the value, augmented with a hash of the parts that didn't fit" — the
    // leading "+" is additive, not substitutive. Replaces v14's "fingerprint
    // of ". Kept in sync with Pipeline (which splits on it to style the marker
    // tspan). See docs/spec.md and this.i:v15pfxlbl.
    static final String TRUNC_MARKER = "+hash ";

    // ASCII elision marker for a truncated prefix slot (matches the bottom
    // strip's "...<suffix>" convention; no Unicode ellipsis, so the
    // printable-ASCII / unicode guard is satisfied and cross-implementation font
    // behavior is uniform).
    private static final String PREFIX_ELLIPSIS = "...";

    // Minimum number of LEADING prefix characters kept when the prefix is
    // truncated. The label-line budget can leave a big prefix (only SSH's
    // structural header is ever this long) almost no room; without a floor it
    // would collapse to a bare "..." that shows nothing. 4 is enough to read
    // "there is a real prefix here" without materially widening the strip.
    private static final int PREFIX_MIN_HEAD = 4;

    // v15: fixed monospace advance (em) used to size the top strip's character
    // budget for prefix truncation. A spec constant — NOT the renderer's real
    // font metric — so all implementations compute the same integer budget and
    // the Tier-A label string is reproducible. 0.6 em is the conventional
    // monospace advance; the raster is unaffected (labels are excluded from the
    // Tier-B raster).
    static final double LABEL_ADVANCE_EM = 0.6;

    // Bare-encoding display shortenings for the PRIMARY slot when scheme is null
    // and the basis is decoded (the encoding name IS the primary). Mirrors the
    // pre-v14 pipeline renaming base64->b64, base64url->b64url; the other
    // alphabet names show verbatim.
    private static String encodingPrimary(String enc) {
        return switch (enc) {
            case "base64" -> "b64";
            case "base64url" -> "b64url";
            default -> enc;
        };
    }

    // scheme -> visible PRIMARY short-name for the non-self-describing schemes.
    private static String schemePrimaryShort(String scheme) {
        return switch (scheme) {
            case "eth" -> "ETH";
            case "btc" -> "BTC";
            case "ltc" -> "LTC";
            case "bch" -> "BCH";
            case "ada" -> "ADA";
            case "xrp" -> "XRP";
            case "stellar" -> "XLM";
            case "eos" -> "EOS";
            case "uuid" -> "UUID";
            case "ulid" -> "ULID";
            case "lei" -> "LEI";
            case "snowflake" -> "snowflake";
            case "ssh" -> "SSH";
            case "cesr" -> "CESR";
            case "bech32" -> "bech32";
            case "multihash" -> "multihash";
            default -> scheme;
        };
    }

    private static boolean isBlockchainScheme(String scheme) {
        return switch (scheme) {
            case "btc", "ltc", "bch", "ada", "eth", "xrp", "stellar", "eos", "bech32" -> true;
            default -> false;
        };
    }

    private static String qStr(Map<String, Object> q, String key) {
        Object v = q.get(key);
        return v == null ? null : String.valueOf(v);
    }

    /** The PRIMARY slot: the always-present head of the top label. */
    private static String primary(Characterization ch) {
        String scheme = ch.scheme();
        Map<String, Object> q = ch.qualifiers();
        if (scheme == null) {
            if (ch.sizeBasis().equals("utf8")) {
                return "text";
            }
            return encodingPrimary(ch.encoding());
        }
        switch (scheme) {
            case "did":
                return "did:" + qStr(q, "method");
            case "urn":
                return "urn:" + qStr(q, "nid");
            case "gitoid": {
                String obj = qStr(q, "object");
                String algo = qStr(q, "algorithm");
                return "gitoid:" + (obj == null ? "" : obj) + ":" + (algo == null ? "" : algo);
            }
            case "swhid": {
                String obj = qStr(q, "object");
                return "swh:1:" + (obj == null ? "" : obj);
            }
            case "cid": {
                Object ver = q.get("version");
                boolean v0 = (ver instanceof Integer i && i == 0) || "0".equals(String.valueOf(ver));
                return v0 ? "CIDv0" : "CIDv1";
            }
            default:
                return schemePrimaryShort(scheme);
        }
    }

    /** The MOD slots (zero or more): silent-default / loud-departure facets. */
    private static List<String> mods(Characterization ch) {
        String scheme = ch.scheme();
        Map<String, Object> q = ch.qualifiers();
        List<String> mods = new ArrayList<>();
        if (scheme == null) {
            return mods;
        }
        switch (scheme) {
            case "cesr": {
                String algo = qStr(q, "algorithm");
                if (algo != null) {
                    if (algo.endsWith(" pubkey")) {
                        algo = algo.substring(0, algo.length() - " pubkey".length());
                    }
                    if (!algo.isEmpty()) {
                        mods.add(algo);
                    }
                }
                break;
            }
            case "ssh": {
                String algo = qStr(q, "algorithm");
                if (algo != null) {
                    // v15: shorten the ECDSA curve to its common short name for
                    // the label — "ecdsa-nistp256" -> "ecdsa-p256" (there is no
                    // rival non-NIST "p256"; the algorithm word stays, only the
                    // redundant standards-body prefix drops). ASCII replace, so
                    // no locale concern. The data-qualifiers `algorithm` field
                    // keeps the faithful SSH curve id ("ecdsa-nistp256").
                    mods.add(algo.replace("nistp", "p"));
                }
                break;
            }
            case "cid": {
                Object ver = q.get("version");
                boolean v0 = (ver instanceof Integer i && i == 0) || "0".equals(String.valueOf(ver));
                if (!v0) {
                    String codec = qStr(q, "codec");
                    if (codec != null) {
                        mods.add(codec);
                    }
                    String hash = qStr(q, "hash");
                    if (hash != null && !hash.equals("sha2-256")) {
                        mods.add(hash);
                    }
                }
                break;
            }
            case "multihash": {
                String hash = qStr(q, "hash");
                if (hash != null && !hash.equals("sha2-256")) {
                    mods.add(hash);
                }
                break;
            }
            default:
                if (isBlockchainScheme(scheme)) {
                    String network = qStr(q, "network");
                    if (network != null && !network.equals("mainnet")) {
                        mods.add(network);
                    }
                }
        }
        return mods;
    }

    /** The SIZE slot (zero or one), or null when omitted. */
    private static String size(Characterization ch) {
        String scheme = ch.scheme();
        long sizeBits = ch.sizeBits();
        if (scheme == null) {
            if (ch.sizeBasis().equals("utf8")) {
                return (sizeBits / 8) + "-byte";
            }
            return sizeBits + "-bit";
        }
        if (scheme.equals("ssh") || scheme.equals("multihash")) {
            return sizeBits + "-bit";
        }
        return null;
    }

    /**
     * The literal front prefix that was stripped from the visualized core, or
     * {@code null}.
     *
     * <p>This is a leading {@code bind="none"} part — a presentation sigil peeled
     * off the front ({@code 0x}, {@code bc1}, {@code cosmos1}, Stellar {@code G},
     * the SSH structural header, …). A folded identity prefix ({@code
     * bind="fold"}: did/urn/gitoid/swhid) is NOT returned — it is already shown
     * verbatim as the PRIMARY slot, so echoing it again would double it. A {@code
     * bind="core"} leading part (e.g. a CESR derivation code, in the first cell)
     * is likewise not a stripped prefix. So the slot fires iff {@code
     * parts[0].bind == "none"}.
     */
    private static String strippedPrefix(Characterization ch) {
        List<Part> parts = ch.parts();
        if (parts != null && !parts.isEmpty() && "none".equals(parts.get(0).bind())) {
            return parts.get(0).text();
        }
        return null;
    }

    /**
     * Truncate the literal prefix slot to {@code avail} characters with a
     * trailing {@code ...} elision marker.
     *
     * <p>The prefix is the sole ELASTIC label element (v15): PRIMARY/MOD/SIZE are
     * never truncated. When the prefix does not fit, it is cut to {@code <head> +
     * "..."}; the head length is floored at {@link #PREFIX_MIN_HEAD} so a long
     * prefix on a tight line (only SSH's structural header hits this) still shows
     * a few leading characters rather than collapsing to a bare {@code ...}.
     */
    private static String fitPrefix(String prefix, int avail) {
        if (prefix.length() <= avail) {
            return prefix;
        }
        int keep = Math.max(avail - PREFIX_ELLIPSIS.length(), PREFIX_MIN_HEAD);
        return prefix.substring(0, keep) + PREFIX_ELLIPSIS;
    }

    /**
     * Projects a characterization into the (top, bottom) label strips (v15),
     * with no prefix-truncation budget (full prefix shown).
     *
     * @return a 2-element array {@code {top, bottom}}
     */
    static String[] renderLabel(Characterization ch, boolean truncated, String suffix, String note) {
        return renderLabel(ch, truncated, suffix, note, null);
    }

    /**
     * Projects a characterization into the (top, bottom) label strips (v15).
     *
     * <p>{@code top = [+hash ]PRIMARY[, MOD]...[, SIZE][, <prefix>]} — ", "
     * joined, no trailing {@code :}. The {@code +hash } marker is reflected in
     * the returned {@code top} so a text-only consumer sees it (the renderer
     * styles the marker tspan). The trailing {@code <prefix>} slot (v15) echoes a
     * front prefix that was stripped from the visualized core (a {@code
     * bind="none"} leading part); it is the only slot that may be truncated (to
     * {@code lineChars}) and may then end in {@code ...}. Fold-prefix schemes
     * (did/urn/gitoid/swhid) show their prefix as PRIMARY and get no extra slot.
     * {@code bottom = ...<suffix>} then {@code (<note>)} — the bound
     * (now-verified) checksum and the user caption; empty when neither present.
     *
     * @param lineChars the monospace character budget the grid leaves for the top
     *     strip, used only to truncate the elastic prefix slot; {@code null} = do
     *     not truncate (show the full prefix).
     * @return a 2-element array {@code {top, bottom}}
     */
    static String[] renderLabel(Characterization ch, boolean truncated, String suffix, String note,
            Integer lineChars) {
        List<String> slots = new ArrayList<>();
        slots.add(primary(ch));
        slots.addAll(mods(ch));
        String size = size(ch);
        if (size != null) {
            slots.add(size);
        }

        String prefix = strippedPrefix(ch);
        if (prefix != null && !prefix.isEmpty()) {
            if (lineChars != null) {
                // Budget left for the prefix = the line budget minus the marker
                // and the fixed PRIMARY/MOD/SIZE core (which never truncate) and
                // the ", " that joins the prefix slot.
                int markerLen = truncated ? TRUNC_MARKER.length() : 0;
                int coreLen = String.join(", ", slots).length();
                int avail = lineChars - markerLen - coreLen - ", ".length();
                prefix = fitPrefix(prefix, avail);
            }
            slots.add(prefix);
        }

        String top = String.join(", ", slots);
        if (truncated) {
            top = TRUNC_MARKER + top;
        }
        String bottom = "";
        if (suffix != null && !suffix.isEmpty()) {
            bottom = "..." + suffix;
        }
        if (note != null && !note.isEmpty()) {
            bottom = bottom.isEmpty() ? "(" + note + ")" : bottom + " (" + note + ")";
        }
        return new String[] {top, bottom};
    }

    /**
     * Characterize an entropy string into the structured model (spec v13).
     *
     * @param raw    the stripped entropy input (already {@code strip()}-ed by the caller)
     * @param parsed the parse record for {@code raw}, or null for the UTF-8 fallback
     * @param fallbackCore the base64url encoding of the raw UTF-8 bytes (fallback core)
     */
    static Characterization characterize(String raw, Parsed parsed, String fallbackCore) {
        if (parsed == null) {
            List<Part> parts = new ArrayList<>();
            parts.add(new Part(fallbackCore, "core"));
            return new Characterization(
                    Alphabet.BASE64URL.name(),
                    null,
                    null,
                    new LinkedHashMap<>(),
                    "utf8",
                    (long) raw.getBytes(StandardCharsets.UTF_8).length * 8,
                    parts,
                    Alphabet.BASE64URL.name());
        }
        Described d = describeFromParsed(parsed);
        long bits = sizeBits(parsed.core(), parsed.alphabet(), d.sizeBasis());
        String encoding = parsed.alphabet().name();
        String entropyType = d.scheme() != null ? d.scheme() : encoding;
        return new Characterization(
                encoding,
                d.scheme(),
                d.role(),
                d.qualifiers(),
                d.sizeBasis(),
                bits,
                partsFromParsed(parsed),
                entropyType);
    }

    // ---- JSON serialization (compact, no spaces; matches json.dumps
    // separators=(",",":") ensure_ascii=False) --------------------------------

    /** Serializes qualifiers to compact JSON, preserving insertion order. */
    static String qualifiersJson(Map<String, Object> q) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : q.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            jsonString(sb, e.getKey());
            sb.append(':');
            Object v = e.getValue();
            if (v instanceof Integer || v instanceof Long) {
                sb.append(v.toString());
            } else {
                jsonString(sb, String.valueOf(v));
            }
        }
        sb.append('}');
        return sb.toString();
    }

    /** Serializes parts to compact JSON. */
    static String partsJson(List<Part> parts) {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        boolean first = true;
        for (Part p : parts) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{");
            jsonString(sb, "text");
            sb.append(':');
            jsonString(sb, p.text());
            sb.append(',');
            jsonString(sb, "bind");
            sb.append(':');
            jsonString(sb, p.bind());
            sb.append('}');
        }
        sb.append(']');
        return sb.toString();
    }

    private static void jsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // ---- small string helpers mirroring Python behavior ---------------------

    private static String stripTrailingColons(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == ':') {
            end--;
        }
        return s.substring(0, end);
    }

    private static String stripColons(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && s.charAt(start) == ':') {
            start++;
        }
        while (end > start && s.charAt(end - 1) == ':') {
            end--;
        }
        return s.substring(start, end);
    }

    private static String splitFirst(String s, char sep) {
        int idx = s.indexOf(sep);
        return idx < 0 ? s : s.substring(0, idx);
    }
}
