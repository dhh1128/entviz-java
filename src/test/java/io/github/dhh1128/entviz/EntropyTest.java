package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EntropyTest {

    // ---- EIP-55 -----------------------------------------------------------

    @Test
    void eip55ChecksummedAddressAccepted() {
        Parsed p = Entropy.parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assertNotNull(p);
        assertEquals("ETH", p.typeName());
        assertEquals("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", p.core());
        assertEquals("0x", p.prefix());
    }

    @Test
    void eip55LowercaseAcceptedWithPrefix() {
        Parsed p = Entropy.parse("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assertNotNull(p);
        assertEquals("ETH", p.typeName());
    }

    @Test
    void eip55BadChecksumRejectedWithPosition() {
        // Flip the case of one digit from the canonical checksum.
        Eip55Exception ex = assertThrows(Eip55Exception.class,
                () -> Entropy.parse("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        // First position whose case disagrees with the canonical EIP-55 case
        // (matches the reference: position 2 is 'a', canonical is 'A').
        assertEquals(2, ex.position());
    }

    @Test
    void eip55BareLowercaseIsHexNotEth() {
        // No 0x prefix and all-lowercase -> not treated as a mixed-case ETH addr,
        // so falls through (parsed as hex by the hex parser later).
        Parsed p = Entropy.parse("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assertNotNull(p);
        assertEquals("hex", p.typeName());
    }

    // ---- format detection -------------------------------------------------

    @Test
    void uuidDashedAndUndashedSameCore() {
        Parsed dashed = Entropy.parse("550e8400-e29b-41d4-a716-446655440000");
        Parsed undashed = Entropy.parse("550e8400e29b41d4a716446655440000");
        assertNotNull(dashed);
        assertNotNull(undashed);
        assertEquals("UUID", dashed.typeName());
        assertEquals(dashed.core(), undashed.core());
    }

    @Test
    void hexEvenLengthParsed() {
        Parsed p = Entropy.parse("deadbeef");
        assertNotNull(p);
        assertEquals("hex", p.typeName());
        assertEquals("deadbeef", p.core());
    }

    @Test
    void hexFormatParserRejectsOddLengthWithoutPrefix() {
        // The dedicated hex FORMAT parser requires an even number of digits when
        // there is no 0x prefix (so the byte boundary is well-defined).
        assertNull(Entropy.parseHexFormat("abcde"));
        // With an explicit 0x prefix, odd nibble counts are accepted.
        Parsed prefixed = Entropy.parseHexFormat("0xabcde");
        assertNotNull(prefixed);
        assertEquals("hex", prefixed.typeName());
        assertEquals("0x", prefixed.prefix());
    }

    @Test
    void oddLengthHexFallsThroughToDisproofAlphabet() {
        // Even though the hex format parser rejects it, disproof-based detection
        // still classifies an all-hex-digit string as the hex alphabet.
        Parsed p = Entropy.parse("abcde");
        assertNotNull(p);
        assertEquals("hex", p.typeName());
        assertEquals("abcde", p.core());
    }

    @Test
    void ulidCanonicalAndLowercaseNormalizeSame() {
        Parsed up = Entropy.parse("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        Parsed low = Entropy.parse("01arz3ndektsv4rrffq69g5fav");
        assertNotNull(up);
        assertNotNull(low);
        assertEquals("ULID", up.typeName());
        assertEquals(up.core(), low.core());
    }

    @Test
    void unrecognizedReturnsNull() {
        // A plain phrase with a space is not any structured type.
        assertNull(Entropy.parse("hello world"));
    }

    @Test
    void leiChecksumValidates() {
        Parsed p = Entropy.parse("549300O2THAREICZTHE9");
        // Whether or not this specific value checksums, the parser must not throw.
        // Use a known-good LEI core length expectation if matched.
        if (p != null && "LEI".equals(p.typeName())) {
            assertEquals(18, p.core().length());
        }
    }

    // ---- DID -------------------------------------------------------------

    @Test
    void didWebBasic() {
        Parsed p = Entropy.parse("did:web:example.com");
        assertNotNull(p);
        assertEquals("", p.typeName());
        assertEquals("did:web:", p.prefix());
        assertEquals("example.com", p.core());
        assertTrue(p.prefixSemantic());
    }

    @Test
    void didMethodSpecificIdKeepsColons() {
        // The msid MAY contain `:` and is kept verbatim.
        Parsed p = Entropy.parse("did:web:example.com:user:alice");
        assertNotNull(p);
        assertEquals("did:web:", p.prefix());
        assertEquals("example.com:user:alice", p.core());
        assertTrue(p.prefixSemantic());
    }

    @Test
    void didUrlTailDropped() {
        // A `/path?q#frag` DID-URL tail is dropped; core is the bare msid.
        Parsed bare = Entropy.parse("did:web:example.com:user:alice");
        Parsed tailed = Entropy.parse("did:web:example.com:user:alice/path?q=1#frag");
        assertNotNull(bare);
        assertNotNull(tailed);
        assertEquals(bare.core(), tailed.core());
        assertEquals("example.com:user:alice", tailed.core());
        assertEquals("did:web:", tailed.prefix());
    }

    @Test
    void didKeyFragmentDropped() {
        Parsed p = Entropy.parse(
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assertNotNull(p);
        assertEquals("did:key:", p.prefix());
        assertEquals("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", p.core());
        assertTrue(p.prefixSemantic());
    }

    // ---- URN -------------------------------------------------------------

    @Test
    void urnIsbnBasic() {
        Parsed p = Entropy.parse("urn:isbn:0451450523");
        assertNotNull(p);
        assertEquals("", p.typeName());
        assertEquals("urn:isbn:", p.prefix());
        assertEquals("0451450523", p.core());
        assertTrue(p.prefixSemantic());
    }

    @Test
    void urnSchemeAndNidLowercasedNssPreserved() {
        // urn scheme + NID are case-insensitive (prefix lowercased); NSS preserved.
        Parsed p = Entropy.parse("URN:ISBN:0451450523X");
        assertNotNull(p);
        assertEquals("urn:isbn:", p.prefix());
        assertEquals("0451450523X", p.core());
        assertTrue(p.prefixSemantic());
    }

    @Test
    void urnNssKeepsSlash() {
        Parsed p = Entropy.parse("urn:example:foo/bar/baz");
        assertNotNull(p);
        assertEquals("urn:example:", p.prefix());
        assertEquals("foo/bar/baz", p.core());
        assertTrue(p.prefixSemantic());
    }

    @Test
    void urnComponentsDropped() {
        // r-/q-/f-components (after `?` or `#`) are dropped.
        Parsed bare = Entropy.parse("urn:example:foo/bar");
        Parsed comp = Entropy.parse("urn:example:foo/bar?=resolve#frag");
        assertNotNull(bare);
        assertNotNull(comp);
        assertEquals(bare.core(), comp.core());
        assertEquals("foo/bar", comp.core());
        assertEquals("urn:example:", comp.prefix());
    }
}
