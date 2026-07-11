package io.github.dhh1128.entviz;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * The deterministic shared core: alphabets, tokenization + 24-bit quant
 * extension, the SHA-512 fingerprint, ftok median/quartile selection, the
 * Oklab color rules + weighted-RGB edge selection, and grid selection.
 *
 * <p>Faithful port of the certified reference ({@code core.py} via
 * {@code core.go} / {@code core.rs}). The {@code quant} fields are 24-bit
 * unsigned values carried in {@code int}; comparisons that the spec performs on
 * the underlying digest bytes use {@link Integer#compareUnsigned}.
 */
final class Core {

    private Core() {
    }

    /** The entviz spec level this library implements. */
    static final String SPEC_VERSION = "v15";

    /** This module's own version stamp (not compared by the conformance checker). */
    static final String LIB_VERSION = "0.15.0";

    /** The fixed palette; indices 0-3 are background candidates, black (4) is always an edge color. */
    static final String[] POSSIBLE_EDGE_COLORS = {"#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"};

    private static final double OKLAB_THRESHOLD = 0.6;

    /** The frozen domain-separation constant for the second digest (trailing NUL included). */
    static final byte[] MIDDLE_DOMAIN_TAG = middleDomainTag();

    private static byte[] middleDomainTag() {
        byte[] prefix = "entviz/fingerprint-middle/v6".getBytes(StandardCharsets.US_ASCII);
        byte[] tag = new byte[prefix.length + 1];
        System.arraycopy(prefix, 0, tag, 0, prefix.length);
        tag[prefix.length] = 0x00; // trailing NUL
        return tag;
    }

    // ---- char value mapping ----------------------------------------------

    static int charValue(String chars, String lowerChars, char ch, int bitsPerChar) {
        int i = chars.indexOf(ch);
        if (i >= 0) {
            return i;
        }
        i = lowerChars.indexOf(toLowerChar(ch));
        if (i >= 0) {
            return i;
        }
        if (bitsPerChar == 6) {
            switch (ch) {
                case '-', '+' -> {
                    return 62;
                }
                case '_', '/' -> {
                    return 63;
                }
                default -> {
                    return -1;
                }
            }
        }
        return -1;
    }

    static char toLowerChar(char c) {
        if (c >= 'A' && c <= 'Z') {
            return (char) (c + ('a' - 'A'));
        }
        return c;
    }

    // ---- tokenization ----------------------------------------------------

    /**
     * Splits text into 24-bit tokens under the given alphabet, extending short
     * trailing chunks to a full 24-bit quant by the bit-repeat rule.
     */
    static List<Token> tokenize(String text, Alphabet alphabet) {
        int bitsPerChar = alphabet.bitsPerChar();
        int tokenLen = 24 / bitsPerChar;
        String lowerAlphabet = alphabet.chars().toLowerCase(Locale.ROOT);
        int[] chars = text.codePoints().toArray();
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < chars.length) {
            int end = Math.min(i + tokenLen, chars.length);
            String chunk = new String(chars, i, end - i);
            i = end;
            if (chunk.isEmpty()) {
                continue;
            }
            int val = 0;
            int actualBits = 0;
            for (int cp : chunk.codePoints().toArray()) {
                int cv = charValue(alphabet.chars(), lowerAlphabet, (char) cp, bitsPerChar);
                if (cv == -1) {
                    cv = 0;
                }
                val = (val << bitsPerChar) | cv;
                actualBits += bitsPerChar;
            }
            int quant = val;
            if (actualBits > 0 && actualBits < 24) {
                while (actualBits < 24) {
                    int shift = Math.min(actualBits, 24 - actualBits);
                    int mask = (1 << shift) - 1;
                    int add = quant & mask;
                    quant = (quant << shift) | add;
                    actualBits += shift;
                }
            } else if (actualBits > 24) {
                quant = val & 0xFFFFFF;
            }
            tokens.add(new Token(chunk, tokens.size(), quant & 0xFFFFFF));
        }
        return tokens;
    }

    // ---- fingerprints ----------------------------------------------------

    private static MessageDigest sha512() {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 not available", e);
        }
    }

    /** Returns the SHA-512 digest (64 bytes) of the core text bytes. */
    static byte[] computeFingerprint(String core) {
        return sha512().digest(core.getBytes(StandardCharsets.UTF_8));
    }

    /** Returns SHA-512(MIDDLE_DOMAIN_TAG ‖ core). */
    static byte[] secondDigest(String core) {
        MessageDigest md = sha512();
        md.update(MIDDLE_DOMAIN_TAG);
        md.update(core.getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }

    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    static String b64urlEncode(byte[] data) {
        return B64URL_NOPAD.encodeToString(data);
    }

    /** Serializes the 64-byte digest to base64url and splits it into 22 ftoks. */
    static List<Token> tokenizeFingerprint(byte[] digest) {
        String enc = b64urlEncode(digest);
        List<Token> toks = tokenize(enc, Alphabet.BASE64URL);
        if (toks.size() != 22) {
            throw new IllegalStateException("expected 22 ftoks, got " + toks.size());
        }
        return toks;
    }

    // ---- median / quartiles ----------------------------------------------

    /** Returns the lower-middle token of the ASCII text-sorted list, or null if empty. */
    static Token medianToken(List<Token> tokens) {
        if (tokens.isEmpty()) {
            return null;
        }
        List<Token> s = new ArrayList<>(tokens);
        s.sort((a, b) -> {
            int c = a.text().compareTo(b.text());
            return c != 0 ? c : Integer.compare(a.index(), b.index());
        });
        int mid = (s.size() - 1) / 2;
        return s.get(mid);
    }

    private static String reverse(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    /**
     * Returns the first token of each of the four mirror-sorted quartiles; a slot
     * is null when it would fall in padding.
     */
    static Token[] quartileTokens(List<Token> tokens) {
        Token[] out = new Token[4];
        if (tokens.isEmpty()) {
            return out;
        }
        List<Token> s = new ArrayList<>(tokens);
        s.sort((a, b) -> {
            String ra = reverse(a.text());
            String rb = reverse(b.text());
            int c = ra.compareTo(rb);
            return c != 0 ? c : Integer.compare(a.index(), b.index());
        });
        int qSize = (s.size() + 3) / 4; // ceil(n/4)
        for (int i = 0; i < 4; i++) {
            int idx = i * qSize;
            if (idx < s.size()) {
                out[i] = s.get(idx);
            }
        }
        return out;
    }

    // ---- colors ----------------------------------------------------------

    private static double srgbToLinear(double c) {
        if (c <= 0.04045) {
            return c / 12.92;
        }
        return Math.pow((c + 0.055) / 1.055, 2.4);
    }

    /** Returns the Oklab L of an sRGB color (channels in 0..255). */
    static double oklabLightness(int r, int g, int b) {
        double rl = srgbToLinear(r / 255.0);
        double gl = srgbToLinear(g / 255.0);
        double bl = srgbToLinear(b / 255.0);
        double l = 0.4122214708 * rl + 0.5363325363 * gl + 0.0514459929 * bl;
        double m = 0.2119034982 * rl + 0.6806995451 * gl + 0.1073969566 * bl;
        double s = 0.0883024619 * rl + 0.2817188376 * gl + 0.6299787005 * bl;
        return 0.2104542553 * Math.cbrt(l) + 0.793617785 * Math.cbrt(m) - 0.0040720468 * Math.cbrt(s);
    }

    /** Returns {bgHex, fgHex}. Red is the low byte of the quant. */
    static String[] nucleusColors(int quant) {
        int r = quant & 0xFF;
        int g = (quant >> 8) & 0xFF;
        int b = (quant >> 16) & 0xFF;
        String bg = String.format("#%02x%02x%02x", r, g, b);
        String fg = oklabLightness(r, g, b) < OKLAB_THRESHOLD ? "#ffffff" : "#000000";
        return new String[] {bg, fg};
    }

    static int parseHexByte(String s) {
        int v = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            v <<= 4;
            if (c >= '0' && c <= '9') {
                v |= c - '0';
            } else if (c >= 'a' && c <= 'f') {
                v |= c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                v |= c - 'A' + 10;
            }
        }
        return v;
    }

    private static int[] hexToRgb(String h) {
        return new int[] {parseHexByte(h.substring(1, 3)), parseHexByte(h.substring(3, 5)), parseHexByte(h.substring(5, 7))};
    }

    /** The spec's cheap CIELAB ΔE stand-in for edge selection. */
    static double weightedRgbDistance(String c1, String c2) {
        int[] a = hexToRgb(c1);
        int[] b = hexToRgb(c2);
        long dr = a[0] - b[0];
        long dg = a[1] - b[1];
        long db = a[2] - b[2];
        return Math.sqrt(2 * dr * dr + 4 * dg * dg + 3 * db * db);
    }

    /** Returns the palette entry with minimum weighted distance. */
    static String closestPaletteColor(String target, List<String> palette) {
        String best = palette.get(0);
        double bestD = Double.POSITIVE_INFINITY;
        for (String c : palette) {
            double d = weightedRgbDistance(c, target);
            if (d < bestD) {
                bestD = d;
                best = c;
            }
        }
        return best;
    }

    /**
     * The entviz background plus the 4-entry edge palette.
     *
     * @param bgColor    the chosen background color
     * @param edgeColors the four remaining palette colors
     */
    record VisualStyle(String bgColor, List<String> edgeColors) {
    }

    /**
     * Picks the background from the median ftok's low 2 bits and forms the edge
     * palette from the remaining four colors.
     */
    static VisualStyle selectVisualStyle(Token medianFtok) {
        int idx = medianFtok.quant() & 0x03;
        String bg = POSSIBLE_EDGE_COLORS[idx];
        List<String> edges = new ArrayList<>(4);
        for (int i = 0; i < POSSIBLE_EDGE_COLORS.length; i++) {
            if (i != idx) {
                edges.add(POSSIBLE_EDGE_COLORS[i]);
            }
        }
        return new VisualStyle(bg, edges);
    }

    // ---- grid ------------------------------------------------------------

    /**
     * The chosen layout.
     *
     * @param cols       number of columns
     * @param rows       number of rows
     * @param tokenCount the token count the grid was sized for
     */
    record Grid(int cols, int rows, int tokenCount) {
    }

    /**
     * Selects the layout whose aspect ratio is closest to (but not below) the
     * target, with at least 2 columns and 2 rows.
     */
    static Grid chooseGrid(int tokenCount, double targetAr) {
        // rows -> tightest (smallest) cols for that row count.
        java.util.TreeMap<Integer, Integer> tightest = new java.util.TreeMap<>();
        for (int cols = 2; cols <= tokenCount; cols++) {
            int rows = (tokenCount + cols - 1) / cols; // ceil
            if (rows >= 2) {
                Integer existing = tightest.get(rows);
                if (existing == null || cols < existing) {
                    tightest.put(rows, cols);
                }
            }
        }
        record Cand(int cols, int rows, double ar) {
        }
        List<Cand> candidates = new ArrayList<>();
        for (var e : tightest.entrySet()) {
            int rows = e.getKey();
            int cols = e.getValue();
            candidates.add(new Cand(cols, rows, (double) (cols * 3) / (double) (rows * 2)));
        }
        if (candidates.isEmpty()) {
            return new Grid(2, 2, tokenCount);
        }
        Cand chosen = null;
        for (Cand c : candidates) {
            if (c.ar() >= targetAr) {
                if (chosen == null || (c.ar() - targetAr) < (chosen.ar() - targetAr)) {
                    chosen = c;
                }
            }
        }
        if (chosen == null) {
            for (Cand c : candidates) {
                if (chosen == null || c.ar() > chosen.ar()) {
                    chosen = c;
                }
            }
        }
        return new Grid(chosen.cols(), chosen.rows(), tokenCount);
    }

    // ---- util ------------------------------------------------------------

    /** Counts each of the four 2-bit patterns across the 256 disjoint 2-bit slices. */
    static int[] twoBitCounts(byte[] digest) {
        int[] counts = new int[4];
        for (byte by : digest) {
            int b = by & 0xFF;
            for (int shift : new int[] {0, 2, 4, 6}) {
                counts[(b >> shift) & 0x03]++;
            }
        }
        return counts;
    }

    /** Returns the single-letter mnemonic for a palette color, or "" if not a palette color. */
    static String bandLetter(String color) {
        return switch (color) {
            case "#ffffff" -> "W";
            case "#e7be00" -> "G";
            case "#ff3f2f" -> "R";
            case "#2f3fbf" -> "B";
            case "#000000" -> "K";
            default -> "";
        };
    }

    /**
     * Maps each token's index to a cell index on the grid, inserting up to three
     * fingerprint-driven blanks (median cell, then the ASCII-sort last and first
     * cells) when the grid has spare cells.
     */
    static int[] assignCellIndices(List<Token> tokens, Grid grid, Token median, List<Token> sortKeys) {
        int tokenCount = tokens.size();
        int cellCount = grid.cols() * grid.rows();
        int[] ci = new int[tokenCount];
        for (int i = 0; i < ci.length; i++) {
            ci[i] = i;
        }
        if (tokenCount >= cellCount || tokenCount == 0) {
            return ci;
        }

        if (median != null) {
            shift(ci, median.index());
        }

        List<Token> sorted = new ArrayList<>(sortKeys);
        sorted.sort((a, b) -> {
            int c = a.text().compareTo(b.text());
            return c != 0 ? c : Integer.compare(a.index(), b.index());
        });

        if (tokenCount + 1 < cellCount) {
            shift(ci, sorted.get(sorted.size() - 1).index());
        }
        if (tokenCount + 2 < cellCount) {
            shift(ci, sorted.get(0).index());
        }
        return ci;
    }

    private static void shift(int[] ci, int start) {
        for (int t = 0; t < ci.length; t++) {
            if (t >= start) {
                ci[t]++;
            }
        }
    }
}
