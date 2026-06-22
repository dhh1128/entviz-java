package io.github.dhh1128.entviz;

/**
 * A recognized entropy classification.
 *
 * @param typeName       human-readable type label (may be empty for semantic-prefix folds)
 * @param alphabet       the alphabet the core is encoded in
 * @param prefix         an optional leading marker (e.g. {@code "0x"}), or null
 * @param core           the entropy core to tokenize and fingerprint
 * @param suffix         an optional trailing marker (e.g. an LEI checksum), or null
 * @param prefixSemantic whether the prefix participates in the fingerprint
 */
record Parsed(String typeName, Alphabet alphabet, String prefix, String core, String suffix, boolean prefixSemantic) {

    static Parsed of(String typeName, Alphabet alphabet, String prefix, String core, String suffix) {
        return new Parsed(typeName, alphabet, prefix, core, suffix, false);
    }

    Parsed semantic() {
        return new Parsed(typeName, alphabet, prefix, core, suffix, true);
    }
}
