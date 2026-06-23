package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Byte-for-byte comparison against the shared conformance corpus golden SVGs.
 *
 * <p>The corpus lives in the sibling {@code ../entviz} reference checkout, which
 * is present in dev environments and CI (where it is checked out under a known
 * path) but may be absent elsewhere — in that case these tests are skipped via
 * {@link org.junit.jupiter.api.Assumptions}. The only permitted difference from
 * the golden is the per-impl {@code data-entviz-lib} stamp, which is normalized
 * before comparison.
 */
class GoldenTest {

    /** Candidate locations of the reference corpus directory. */
    private static final String[] CORPUS_CANDIDATES = {
            "../entviz/compliance/corpus",
            "../../entviz/compliance/corpus",
            "entviz-ref/compliance/corpus",
    };

    private static Path corpusDir() {
        String env = System.getenv("ENTVIZ_CORPUS");
        if (env != null && Files.isDirectory(Paths.get(env))) {
            return Paths.get(env);
        }
        for (String c : CORPUS_CANDIDATES) {
            Path p = Paths.get(c);
            if (Files.isDirectory(p)) {
                return p.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static String normalize(String svg) {
        return svg.replaceAll("data-entviz-lib=\"[^\"]*\"", "data-entviz-lib=\"X\"");
    }

    private void assertMatchesGolden(String vid) throws IOException {
        Path corpus = corpusDir();
        assumeTrue(corpus != null, "reference corpus not available; skipping golden comparison");
        Path dir = corpus.resolve(vid);
        assumeTrue(Files.isDirectory(dir), "vector " + vid + " not present in corpus");

        String inputJson = Files.readString(dir.resolve("input.json"), StandardCharsets.UTF_8);
        String golden = Files.readString(dir.resolve("golden.svg"), StandardCharsets.UTF_8);

        Vector v = Vector.parse(inputJson);
        String actual = Entviz.render(v.entropy, new RenderOptions(v.targetAr, v.fontSizePt, v.note));
        assertEquals(normalize(golden), normalize(actual), "golden mismatch for " + vid);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "hex-64", "hex-128", "hex-256", "hex-512",
            "uuid-dashed", "uuid-undashed", "uuid-nil", "uuid-max",
            "eth-lower", "eth-checksummed",
            "ulid-canonical", "ulid-lowercase",
            "btc-legacy", "ripple", "btc-segwit", "litecoin", "bitcoincash",
            "cosmos", "stellar", "cid-v1", "cid-v0",
            "lei-bloomberg", "snowflake-discord",
            "cesr-aid-d", "ssh-ed25519", "swhid-rev", "gitoid-blob-sha256",
            "did-web", "did-web-path", "did-web-port", "did-web-urldrop",
            "did-key-ed25519", "did-key-secp256k1", "did-key-fragment",
            "did-peer-2", "did-ion", "did-ethr-network", "did-pkh",
            "did-webvh", "did-keri", "did-prism", "did-jwk-large",
            "urn-isbn", "urn-isbn-upper", "urn-oid", "urn-uuid",
            "urn-nss-slash", "urn-base", "urn-components",
            "text-hello", "text-lorem", "hex-1024", "b64-large",
            "ar-1x1", "ar-2x1", "ar-1x2", "fs-6", "fs-24",
            "note-space", "note-punct",
    })
    void rendersMatchGolden(String vid) throws IOException {
        assertMatchesGolden(vid);
    }

    /** A minimal view over a corpus {@code input.json}. */
    private record Vector(String entropy, double targetAr, double fontSizePt, String note) {
        static Vector parse(String json) {
            // Extremely small extraction: rely on the fields' fixed shape in the
            // corpus. We avoid a JSON dependency in tests, but the corpus inputs
            // are well-formed objects with a "params" sub-object.
            String entropy = jsonStringField(json, "entropy");
            double targetAr = jsonNumberField(json, "target_ar", 1.0);
            double fontSizePt = jsonNumberField(json, "font_size_pt", 12.0);
            String note = jsonNullableStringField(json, "note");
            return new Vector(entropy, targetAr, fontSizePt, note);
        }
    }

    // --- tiny JSON field extractors (corpus inputs only) ------------------

    private static String jsonStringField(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) {
            throw new IllegalArgumentException("missing field " + key);
        }
        int colon = json.indexOf(':', i + key.length() + 2);
        int q = json.indexOf('"', colon + 1);
        return readJsonString(json, q);
    }

    private static String jsonNullableStringField(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) {
            return null;
        }
        int colon = json.indexOf(':', i + key.length() + 2);
        int j = colon + 1;
        while (j < json.length() && Character.isWhitespace(json.charAt(j))) {
            j++;
        }
        if (json.startsWith("null", j)) {
            return null;
        }
        int q = json.indexOf('"', colon + 1);
        return readJsonString(json, q);
    }

    private static double jsonNumberField(String json, String key, double dflt) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) {
            return dflt;
        }
        int colon = json.indexOf(':', i + key.length() + 2);
        int j = colon + 1;
        while (j < json.length() && Character.isWhitespace(json.charAt(j))) {
            j++;
        }
        int start = j;
        while (j < json.length() && "-+.0123456789eE".indexOf(json.charAt(j)) >= 0) {
            j++;
        }
        return Double.parseDouble(json.substring(start, j));
    }

    private static String readJsonString(String json, int openQuote) {
        StringBuilder sb = new StringBuilder();
        int k = openQuote + 1;
        while (k < json.length()) {
            char c = json.charAt(k);
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                char e = json.charAt(k + 1);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'u' -> {
                        sb.append((char) Integer.parseInt(json.substring(k + 2, k + 6), 16));
                        k += 4;
                    }
                    default -> sb.append(e);
                }
                k += 2;
            } else {
                sb.append(c);
                k++;
            }
        }
        return sb.toString();
    }
}
