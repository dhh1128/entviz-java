package io.github.dhh1128.entviz;

/**
 * A {@link RenderException} raised when the input is a mixed-case Ethereum
 * address whose EIP-55 checksum is invalid. {@link #position()} is the 0-based
 * index of the first hex digit whose case disagrees with the canonical case.
 */
public final class Eip55RenderException extends RenderException {

    private static final long serialVersionUID = 1L;

    private final transient int position;

    Eip55RenderException(int position) {
        super(Kind.EIP55, "EIP-55 checksum mismatch at position " + position);
        this.position = position;
    }

    /** The 0-based index of the first mismatched case digit. */
    public int position() {
        return position;
    }
}
