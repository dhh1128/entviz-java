package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CoreTest {

    // ---- tokenization / quant --------------------------------------------

    @Test
    void hexTokenizesSixCharsPerToken() {
        // hex is 4 bits/char => 24/4 = 6 chars per token.
        List<Token> toks = Core.tokenize("abcdef012345", Alphabet.HEX);
        assertEquals(2, toks.size());
        assertEquals("abcdef", toks.get(0).text());
        assertEquals("012345", toks.get(1).text());
        assertEquals(0xabcdef, toks.get(0).quant());
        assertEquals(0x012345, toks.get(1).quant());
    }

    @Test
    void shortTrailingChunkExtendedByBitRepeat() {
        // A single hex char (4 bits) must be extended to a 24-bit quant by the
        // bit-repeat rule rather than left as 4 bits.
        List<Token> toks = Core.tokenize("a", Alphabet.HEX);
        assertEquals(1, toks.size());
        int q = toks.get(0).quant();
        assertTrue(q >= 0 && q <= 0xFFFFFF);
        // 0xa = 1010 repeated to 24 bits => 1010 1010 ... = 0xAAAAAA.
        assertEquals(0xAAAAAA, q);
    }

    @Test
    void quantAlwaysFitsIn24Bits() {
        List<Token> toks = Core.tokenize("ZZZZ", Alphabet.BASE64URL);
        for (Token t : toks) {
            assertTrue(t.quant() >= 0 && t.quant() <= 0xFFFFFF, "quant out of 24-bit range: " + t.quant());
        }
    }

    // ---- fingerprint ------------------------------------------------------

    @Test
    void fingerprintIs64Bytes() {
        byte[] fp = Core.computeFingerprint("hello");
        assertEquals(64, fp.length);
    }

    @Test
    void fingerprintTokenizesTo22Ftoks() {
        byte[] fp = Core.computeFingerprint("any input");
        List<Token> ftoks = Core.tokenizeFingerprint(fp);
        assertEquals(22, ftoks.size());
    }

    @Test
    void secondDigestDiffersFromPrimary() {
        byte[] primary = Core.computeFingerprint("x");
        byte[] second = Core.secondDigest("x");
        assertEquals(64, second.length);
        // Domain separation: the two digests must not coincide.
        assertTrue(!java.util.Arrays.equals(primary, second));
    }

    // ---- grid -------------------------------------------------------------

    @Test
    void gridHasAtLeastTwoByTwo() {
        Core.Grid g = Core.chooseGrid(4, 1.0);
        assertTrue(g.cols() >= 2);
        assertTrue(g.rows() >= 2);
        assertTrue(g.cols() * g.rows() >= 4);
    }

    @Test
    void gridAspectRatioFavorsTarget() {
        Core.Grid wide = Core.chooseGrid(8, 2.0);
        Core.Grid tall = Core.chooseGrid(8, 0.5);
        // A wider target should not produce fewer columns than a taller one.
        assertTrue(wide.cols() >= tall.cols());
    }

    // ---- palette / CVD pins ----------------------------------------------

    @Test
    void paletteColorsArePinned() {
        assertEquals("#ffffff", Core.POSSIBLE_EDGE_COLORS[0]);
        assertEquals("#e7be00", Core.POSSIBLE_EDGE_COLORS[1]);
        assertEquals("#ff3f2f", Core.POSSIBLE_EDGE_COLORS[2]);
        assertEquals("#2f3fbf", Core.POSSIBLE_EDGE_COLORS[3]);
        assertEquals("#000000", Core.POSSIBLE_EDGE_COLORS[4]);
    }

    @Test
    void bandLettersPinned() {
        assertEquals("W", Core.bandLetter("#ffffff"));
        assertEquals("G", Core.bandLetter("#e7be00"));
        assertEquals("R", Core.bandLetter("#ff3f2f"));
        assertEquals("B", Core.bandLetter("#2f3fbf"));
        assertEquals("K", Core.bandLetter("#000000"));
        assertEquals("", Core.bandLetter("#123456"));
    }

    @Test
    void nucleusForegroundContrastsDarkBackgrounds() {
        // A near-black background must get a white foreground.
        String[] dark = Core.nucleusColors(0x000000);
        assertEquals("#000000", dark[0]);
        assertEquals("#ffffff", dark[1]);
        // A near-white background must get a black foreground.
        String[] light = Core.nucleusColors(0xffffff);
        assertEquals("#ffffff", light[0]);
        assertEquals("#000000", light[1]);
    }

    @Test
    void closestPaletteColorPicksNearest() {
        List<String> palette = List.of("#ffffff", "#000000");
        assertEquals("#000000", Core.closestPaletteColor("#101010", palette));
        assertEquals("#ffffff", Core.closestPaletteColor("#f0f0f0", palette));
    }

    @Test
    void visualStyleExcludesBackgroundFromEdges() {
        // median ftok low 2 bits select the background index.
        Token median = new Token("AAAA", 0, 0); // low 2 bits = 0 -> white bg
        Core.VisualStyle style = Core.selectVisualStyle(median);
        assertEquals("#ffffff", style.bgColor());
        assertEquals(4, style.edgeColors().size());
        assertTrue(!style.edgeColors().contains("#ffffff"));
    }

    // ---- median / quartiles ----------------------------------------------

    @Test
    void medianOfSingleTokenIsItself() {
        Token only = new Token("zzz", 0, 1);
        Token median = Core.medianToken(List.of(only));
        assertNotNull(median);
        assertEquals(only, median);
    }

    @Test
    void quartileTokensHasFourSlots() {
        List<Token> toks = Core.tokenizeFingerprint(Core.computeFingerprint("grid input here"));
        Token[] q = Core.quartileTokens(toks);
        assertEquals(4, q.length);
        for (Token t : q) {
            assertNotNull(t);
        }
    }
}
