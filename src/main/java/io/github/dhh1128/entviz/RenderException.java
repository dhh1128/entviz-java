package io.github.dhh1128.entviz;

/**
 * Signals that an entviz render was rejected. {@link #kind()} discriminates the
 * reason; EIP-55 checksum failures are reported via the {@link Eip55Exception}
 * subtype instead.
 */
public sealed class RenderException extends RuntimeException permits Eip55RenderException {

    private static final long serialVersionUID = 1L;

    /** The category of rejection. */
    public enum Kind {
        /** The note was too long, non-printable, or otherwise invalid. */
        NOTE,
        /** The input exceeded the maximum length. */
        INPUT_TOO_LONG,
        /** The font size was out of the permitted range. */
        FONT_SIZE,
        /** The target aspect ratio was out of the permitted range. */
        ASPECT_RATIO,
        /** The input produced no tokens. */
        NO_TOKENS,
        /** An EIP-55 mixed-case checksum mismatch (see {@link Eip55RenderException}). */
        EIP55
    }

    private final transient Kind kind;

    RenderException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    /** The category of this rejection. */
    public Kind kind() {
        return kind;
    }
}
