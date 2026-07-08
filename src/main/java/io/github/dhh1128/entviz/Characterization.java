package io.github.dhh1128.entviz;

import java.util.List;
import java.util.Map;

/**
 * The structured eight-field entropy characterization (spec v13).
 *
 * <p>This is the public, reporting-only recognition of an entropy string along
 * independent axes, so downstream consumers read structured fields instead of
 * string-parsing a label. It is identical in shape for every input and mirrors
 * the certified reference {@code characterize.py} and the sibling ports
 * (entviz-rs, entviz-js, entviz-go). Obtain one via
 * {@link Entviz#characterize(String)}.
 *
 * <p>The characterization changes no rendered pixel, no fingerprint input, and
 * no label string; {@link Entviz#render(String)} emits the same eight fields
 * onto the root {@code <svg>} as {@code data-*} attributes.
 *
 * @param encoding    the alphabet the core is encoded in (e.g. {@code "hex"}, {@code "base64url"})
 * @param scheme      the recognized scheme (e.g. {@code "cesr"}, {@code "did"}), or null when absent
 * @param role        the semantic role: one of {@code "key"}, {@code "signature"},
 *                    {@code "digest"}, {@code "address"}, {@code "identifier"}, or null
 * @param qualifiers  scheme-specific facts, insertion-ordered; values are String or Integer
 * @param sizeBasis   {@code "decoded"} or {@code "utf8"}
 * @param sizeBits    reporting-only size in bits (a multiple of 8)
 * @param parts       ordered reading-order parts ({@code [{text, bind}]})
 * @param entropyType a convenience label equal to {@code scheme} if present, else {@code encoding}
 */
public record Characterization(
        String encoding,
        String scheme,
        String role,
        Map<String, Object> qualifiers,
        String sizeBasis,
        long sizeBits,
        List<Part> parts,
        String entropyType) {
}
