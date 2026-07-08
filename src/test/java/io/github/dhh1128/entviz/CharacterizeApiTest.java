package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Exercises the public {@link Entviz#characterize(String)} API and the public
 * {@link Characterization} / {@link Part} types, confirming cross-language
 * parity with the sibling implementations (entviz-rs, entviz-js, entviz-go, and
 * the reference {@code characterize.py}).
 */
class CharacterizeApiTest {

    @Test
    void cesrDigestIsClassified() {
        // CESR-E SAID (spec corpus vector cesr-said-e).
        Characterization c = Entviz.characterize("EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv");
        assertEquals("cesr", c.scheme());
        assertEquals("digest", c.role());
        assertEquals(264, c.sizeBits());
        assertEquals("cesr", c.entropyType());
        assertEquals("decoded", c.sizeBasis());
        assertNotNull(c.qualifiers());
        assertNotNull(c.parts());
    }

    @Test
    void bareHexHasNoSchemeOrRole() {
        // spec corpus vector ar-1x1: a bare 64-hex-char string.
        Characterization c =
                Entviz.characterize("deadbeefcafebabe1234567890abcdef0fedcba9876543210123456789abcdef");
        assertEquals("hex", c.encoding());
        assertNull(c.scheme());
        assertNull(c.role());
        assertEquals(256, c.sizeBits());
        assertEquals("hex", c.entropyType());
    }

    @Test
    void didKeyIsAnIdentifier() {
        // spec corpus vector did-key-ed25519.
        Characterization c =
                Entviz.characterize("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assertEquals("did", c.scheme());
        assertEquals("identifier", c.role());
        assertEquals("key", c.qualifiers().get("method"));
        assertEquals("utf8", c.sizeBasis());
    }

    @Test
    void inputIsStrippedAndPartsCoverTheCore() {
        // Leading/trailing whitespace is stripped, mirroring render().
        Characterization c = Entviz.characterize("  9f86d081884c7d659a2feaa0c55ad015  ");
        assertEquals("hex", c.encoding());
        assertEquals(1, c.parts().size());
        Part core = c.parts().get(0);
        assertEquals("core", core.bind());
        assertEquals("9f86d081884c7d659a2feaa0c55ad015", core.text());
    }
}
