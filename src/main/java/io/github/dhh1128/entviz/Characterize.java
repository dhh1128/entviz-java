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

    /**
     * The structured 8-field characterization. Field names mirror {@code
     * characterize.py}. {@code scheme} and {@code role} are null when absent.
     * {@code qualifiers} preserves insertion order; values are String or Integer.
     */
    record Model(
            String encoding,
            String scheme,
            String role,
            Map<String, Object> qualifiers,
            String sizeBasis,
            long sizeBits,
            List<Part> parts,
            String entropyType) {
    }

    /** An ordered [{text, bind}] part; {@code bind} in {none, fold, core}. */
    record Part(String text, String bind) {
    }

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

    /**
     * Characterize an entropy string into the structured model (spec v13).
     *
     * @param raw    the stripped entropy input (already {@code strip()}-ed by the caller)
     * @param parsed the parse record for {@code raw}, or null for the UTF-8 fallback
     * @param fallbackCore the base64url encoding of the raw UTF-8 bytes (fallback core)
     */
    static Model characterize(String raw, Parsed parsed, String fallbackCore) {
        if (parsed == null) {
            List<Part> parts = new ArrayList<>();
            parts.add(new Part(fallbackCore, "core"));
            return new Model(
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
        return new Model(
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
