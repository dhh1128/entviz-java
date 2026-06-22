package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * The algorithm must be byte-identical regardless of the JVM's default locale.
 * Java's no-arg {@code String.toLowerCase()}/{@code toUpperCase()} fold under
 * {@code Locale.getDefault()}: under a Turkish/Azeri locale the uppercase
 * {@code 'I'} folds to dotless {@code 'ı'} (U+0131) rather than {@code 'i'}.
 * Every case fold in the port must therefore pass {@link Locale#ROOT}; these
 * tests pin that by exercising the i-bearing paths under {@code tr-TR}.
 */
class LocaleRobustnessTest {

    private static final Locale TURKISH = Locale.forLanguageTag("tr-TR");

    /** Runs {@code body} with the default locale temporarily set to {@code loc}. */
    private static <T> T withLocale(Locale loc, java.util.function.Supplier<T> body) {
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(loc);
            return body.get();
        } finally {
            Locale.setDefault(saved);
        }
    }

    @Test
    void tokenizationOfLowercaseIInBase32IsLocaleIndependent() {
        // base32's canonical chars are uppercase and include 'I'; a lowercase
        // 'i' input reaches charValue's lower-case fallback, which is exactly
        // where a default-locale fold corrupts the alphabet under tr-TR.
        List<Token> root = withLocale(Locale.ROOT, () -> Core.tokenize("iiiii", Alphabet.BASE32));
        List<Token> turkish = withLocale(TURKISH, () -> Core.tokenize("iiiii", Alphabet.BASE32));
        assertEquals(root.get(0).quant(), turkish.get(0).quant(),
                "tr-TR tokenization of 'i' must match Locale.ROOT");
        // And it must be the real value for 'i' (index 8), not the cv=0 fallback
        // a corrupted alphabet would produce.
        assertNotEquals(0, root.get(0).quant(), "'i' must map to a non-zero base32 value");
    }

    @Test
    void renderIsLocaleIndependent() {
        // Inputs whose parsing/tokenization touches case folding: a UUID (hex),
        // a base64url-ish core with i/I, and a generic phrase.
        String[] inputs = {
            "9f2c1e7a-3b4d-4f6a-8c1d-2e5f7a9b0c3d",
            "IiIiIiIiIiIiIiIiIiIi",
            "the quick brown fox jumps over",
        };
        for (String in : inputs) {
            String root = withLocale(Locale.ROOT, () -> Entviz.render(in));
            String turkish = withLocale(TURKISH, () -> Entviz.render(in));
            assertEquals(root, turkish, "render must be byte-identical across locales for: " + in);
        }
    }
}
