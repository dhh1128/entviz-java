package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PipelineTest {

    // ---- numeric serialization -------------------------------------------

    @Test
    void numericSerializationCompactRules() {
        assertEquals("0", Pipeline.n(0.0));
        assertEquals("0", Pipeline.n(-0.0));
        assertEquals("1", Pipeline.n(1.0));
        assertEquals("12", Pipeline.n(12.0));
        assertEquals("1.5", Pipeline.n(1.5));
        assertEquals("0.123", Pipeline.n(0.123));
        // <=3 fractional digits, half-to-even rounding.
        assertEquals("0.124", Pipeline.n(0.1235)); // 0.1235 -> nearest even at 3dp
        // No exponent for tiny magnitudes that round to zero.
        assertEquals("0", Pipeline.n(0.0000001));
        // No trailing zeros.
        assertEquals("2.5", Pipeline.n(2.50));
        // Negative.
        assertEquals("-3.25", Pipeline.n(-3.25));
    }

    @Test
    void everyNumericAttributeIsCompact() {
        // Render a vector at a fractional font size that forces fractional
        // coordinates, then assert every numeric attribute respects the rule:
        // no exponent, <=3 fractional digits, no trailing zeros, no "-0".
        String svg = Entviz.render("deadbeefdeadbeefdeadbeefdeadbeef",
                new RenderOptions(1.0, 7.0, null));
        // Match attr="...numeric..." for the geometry-bearing attributes.
        Pattern p = Pattern.compile(
                "(?:x|y|x1|y1|x2|y2|cx|cy|r|rx|ry|width|height|stroke-width|font-size|fill-opacity|stroke-opacity)"
                        + "=\"(-?[0-9][0-9.]*)\"");
        Matcher m = p.matcher(svg);
        int count = 0;
        while (m.find()) {
            String v = m.group(1);
            count++;
            assertFalse(v.contains("e") || v.contains("E"), "exponent in " + v);
            assertFalse(v.equals("-0"), "negative zero: " + v);
            int dot = v.indexOf('.');
            if (dot >= 0) {
                String frac = v.substring(dot + 1);
                assertTrue(frac.length() <= 3, "too many fractional digits: " + v);
                assertFalse(frac.endsWith("0"), "trailing zero: " + v);
            }
        }
        assertTrue(count > 20, "expected many numeric attributes, saw " + count);
    }

    // ---- note sanitize ----------------------------------------------------

    @Test
    void noteNullAndEmptyBecomeAbsent() {
        assertEquals(null, Pipeline.sanitizeNote(null));
        assertEquals(null, Pipeline.sanitizeNote(""));
    }

    @Test
    void noteAtMostTenCodePoints() {
        assertEquals("0123456789", Pipeline.sanitizeNote("0123456789"));
        RenderException ex = assertThrows(RenderException.class,
                () -> Pipeline.sanitizeNote("01234567890"));
        assertEquals(RenderException.Kind.NOTE, ex.kind());
    }

    @Test
    void noteRejectsControlCharacters() {
        RenderException ex = assertThrows(RenderException.class,
                () -> Pipeline.sanitizeNote("a\tb"));
        assertEquals(RenderException.Kind.NOTE, ex.kind());
    }

    @Test
    void noteRejectsNonAscii() {
        assertThrows(RenderException.class, () -> Pipeline.sanitizeNote("café"));
    }

    @Test
    void noteXmlEscapedInAttributeAndText() {
        String svg = Entviz.render("deadbeef", new RenderOptions(1.0, 12.0, "<a&b>\""));
        // The note appears both in the data-user-note attribute (with &quot;)
        // and in the (..) text node.
        assertTrue(svg.contains("data-user-note=\"&lt;a&amp;b&gt;&quot;\""),
                "attribute escaping missing: " + extractNote(svg));
        assertTrue(svg.contains(">(&lt;a&amp;b&gt;\")</tspan>"),
                "text escaping missing: " + extractNote(svg));
    }

    private static String extractNote(String svg) {
        int i = svg.indexOf("data-user-note");
        return i < 0 ? "<none>" : svg.substring(i, Math.min(i + 80, svg.length()));
    }

    // ---- option rejection -------------------------------------------------

    @Test
    void fontSizeOutOfRangeRejected() {
        RenderException low = assertThrows(RenderException.class,
                () -> Entviz.render("deadbeef", new RenderOptions(1.0, 5.0, null)));
        assertEquals(RenderException.Kind.FONT_SIZE, low.kind());
        RenderException high = assertThrows(RenderException.class,
                () -> Entviz.render("deadbeef", new RenderOptions(1.0, 31.0, null)));
        assertEquals(RenderException.Kind.FONT_SIZE, high.kind());
    }

    @Test
    void aspectRatioOutOfRangeRejected() {
        assertThrows(RenderException.class,
                () -> Entviz.render("deadbeef", new RenderOptions(0.0, 12.0, null)));
        assertThrows(RenderException.class,
                () -> Entviz.render("deadbeef", new RenderOptions(101.0, 12.0, null)));
    }

    @Test
    void eip55BadChecksumRejectedByRender() {
        Eip55RenderException ex = assertThrows(Eip55RenderException.class,
                () -> Entviz.render("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        assertEquals(2, ex.position());
        assertEquals(RenderException.Kind.EIP55, ex.kind());
    }

    // ---- determinism ------------------------------------------------------

    @Test
    void renderIsDeterministic() {
        String a = Entviz.render("hello world");
        String b = Entviz.render("hello world");
        assertEquals(a, b);
    }

    @Test
    void renderIncludesVersionStamps() {
        String svg = Entviz.render("deadbeef");
        assertTrue(svg.contains("data-entviz-version=\"" + Entviz.SPEC_VERSION + "\""));
        assertTrue(svg.contains("data-entviz-lib=\"" + Entviz.LIB_VERSION + "\""));
    }

    @Test
    void rendersWellFormedSvgRoot() {
        String svg = Entviz.render("deadbeef");
        assertTrue(svg.startsWith("<svg "));
        assertTrue(svg.endsWith("</svg>"));
    }
}
