package io.github.dhh1128.entviz;

/**
 * A hard rejection: a bound checksum that is SHOWN in the label (the base58check
 * {@code ...<suffix>} bottom strip, a bech32/CashAddr address body, or an LEI
 * MOD 97-10 pair) failed to verify (spec v14).
 *
 * <p>v14 rule: a parser may surface a bound checksum only if it VERIFIED it; a
 * structural match with a bad checksum is an error, not a value to render with a
 * bad checksum on display — matching the existing EIP-55 behavior. The
 * {@link #kind()} names which scheme rejected. Like {@link Eip55Exception} this
 * is a {@link RuntimeException}, so the render pipeline / conformance CLI reject
 * the input as an error vector. See docs/spec.md "Checksum verification" and
 * reviews/v14-label-redesign.md.
 */
public final class ChecksumException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String kind;

    ChecksumException(String kind, String message) {
        super(message);
        this.kind = kind;
    }

    /** The scheme whose checksum failed (e.g. {@code "Bitcoin legacy"}, {@code "LEI"}). */
    public String kind() {
        return kind;
    }
}
