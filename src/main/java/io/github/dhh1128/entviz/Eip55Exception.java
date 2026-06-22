package io.github.dhh1128.entviz;

/**
 * A hard rejection: an EIP-55 mixed-case checksum mismatch. The
 * {@link #position()} is the 0-based index (within the 40-hex body) of the
 * first digit whose case disagrees with the canonical case.
 */
public final class Eip55Exception extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int position;

    Eip55Exception(int position) {
        super("EIP-55 checksum mismatch at position " + position);
        this.position = position;
    }

    /** The 0-based index of the first mismatched case digit. */
    public int position() {
        return position;
    }
}
