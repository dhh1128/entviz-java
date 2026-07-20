package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Issue #36 — the CESR recognizer must cover the Indexer table (indexed
 * signatures) and the Dater (datetime) Matter code, instead of dropping them to
 * the {@code raw} base64url fallback.
 *
 * <p>Scope decisions (see {@code this.i:idxs1gs0} and docs/spec.md role
 * principle):
 *
 * <ul>
 *   <li><b>Indexed signatures ARE in scope</b> — a 64-byte controller/witness
 *   signature is exactly the high-entropy cryptographic material entviz exists
 *   to compare. Every IdrDex variant of one algorithm (current-only "crt",
 *   "big" dual-index) collapses to ONE label; the code+index chars stay in the
 *   core, so they still drive the cells. Role -> {@code signature}.</li>
 *   <li><b>The Dater is recognized only to LABEL it correctly, not to endorse
 *   visualizing a datetime as entropy.</b> A datetime is low-entropy and
 *   directly human-readable, so it carries NO role in the closed enum:
 *   {@code role} is {@code null}, NOT the {@code key} default.</li>
 * </ul>
 *
 * <p>Vectors are authoritative — generated from keripy 1.1.33
 * ({@code keri.core.coring} {@code Siger} / {@code Dater}), hardcoded here so
 * the test has no keripy dependency. Mirrors the reference
 * {@code tests/test_issue36_indexer_dater.py}.
 */
class Issue36IndexerDaterTest {

    // (qb64, expected CESR label) — one per length class and per algorithm,
    // small + big variants.
    private static final String[][] INDEXED_SIGS = {
            // small (hs1/hs2), fs 88 / 156
            {"ABCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},
            {"BDCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},
            {"CCCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256k1 idx sig"},
            {"EFCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256r1 idx sig"},
            {"0ACCAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5", "Ed448 idx sig"},
            // big (hs2), fs 92 / 160
            {"2AAFAFCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},
            {"2CABABCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256k1 idx sig"},
            {"2EAHAHCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256r1 idx sig"},
            {"3AAADAADAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5", "Ed448 idx sig"},
    };

    // keri.core.coring.Dater(dts="2020-08-22T17:50:09.988921+00:00").qb64
    private static final String DATER = "1AAG2020-08-22T17c50c09d988921p00c00";

    @Test
    void indexedSigsRecognizedNotRaw() {
        for (String[] vec : INDEXED_SIGS) {
            String qb64 = vec[0];
            String label = vec[1];
            Parsed answer = Entropy.parseCesr(qb64);
            assertNotNull(answer, "indexed sig fell through to raw: " + qb64);
            assertEquals("CESR " + label, answer.typeName(), qb64);
            // The derivation code + index stay IN the core (rendered in cells and
            // hashed), like every other CESR primitive; nothing goes to prefix.
            assertNull(answer.prefix());
            assertEquals(qb64, answer.core());
        }
    }

    @Test
    void indexedSigsDispatchViaParse() {
        for (String[] vec : INDEXED_SIGS) {
            String qb64 = vec[0];
            String label = vec[1];
            Parsed answer = Entropy.parse(qb64);
            assertNotNull(answer);
            assertEquals("CESR " + label, answer.typeName());
        }
    }

    @Test
    void indexedSigRoleIsSignature() {
        for (String[] vec : INDEXED_SIGS) {
            String qb64 = vec[0];
            String label = vec[1];
            Characterization ch = Entviz.characterize(qb64);
            assertEquals("cesr", ch.scheme());
            assertEquals("signature", ch.role());
            assertEquals(label, ch.qualifiers().get("algorithm"));
        }
    }

    @Test
    void indexedSigLabelProjection() {
        // Top strip reads "CESR, <algo> idx sig"; there is no " pubkey" to strip.
        Characterization ch = Entviz.characterize(INDEXED_SIGS[0][0]);
        String[] label = Characterize.renderLabel(ch, false, null, null);
        assertEquals("CESR, Ed25519 idx sig", label[0]);
    }

    @Test
    void matterVsIndexerDisambiguationByLength() {
        // A 44-char 'A...' is the Matter Ed25519 SEED; an 88-char 'A...' is the
        // Indexer signature. Length must decide, not the leading char alone.
        String seed = "A" + "A".repeat(43); // 44 chars, base64url
        assertEquals("CESR Ed25519 seed", Entropy.parseCesr(seed).typeName());
        String sig = INDEXED_SIGS[0][0];
        assertTrue(sig.length() == 88 && sig.charAt(0) == 'A');
        assertEquals("CESR Ed25519 idx sig", Entropy.parseCesr(sig).typeName());
    }

    @Test
    void daterRecognizedNotRaw() {
        Parsed answer = Entropy.parseCesr(DATER);
        assertNotNull(answer, "Dater fell through to raw");
        assertEquals("CESR datetime", answer.typeName());
        assertEquals(DATER, answer.core());
    }

    @Test
    void daterRoleIsNullNotKey() {
        Characterization ch = Entviz.characterize(DATER);
        assertEquals("cesr", ch.scheme());
        // A datetime is recognized but carries NO closed-enum role — it MUST NOT
        // default to "key" (the reason we special-case it).
        assertNull(ch.role());
        assertEquals("datetime", ch.qualifiers().get("algorithm"));
    }

    @Test
    void daterLabelProjection() {
        Characterization ch = Entviz.characterize(DATER);
        String[] label = Characterize.renderLabel(ch, false, null, null);
        assertEquals("CESR, datetime", label[0]);
    }
}
