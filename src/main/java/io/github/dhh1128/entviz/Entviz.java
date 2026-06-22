package io.github.dhh1128.entviz;

/**
 * Renders high-entropy values as comparable SVG fingerprints (entviz, spec
 * {@value Core#SPEC_VERSION}).
 *
 * <p>This is the public entry point. It is a Java port of the certified
 * reference implementation; the canonical algorithm and spec live in
 * <a href="https://github.com/dhh1128/entviz">dhh1128/entviz</a>. The renderer
 * is pure and deterministic: it takes an entropy string plus rendering options
 * and returns an SVG string, performing no I/O.
 *
 * <pre>{@code
 * String svg = Entviz.render("hello world");
 * String wide = Entviz.render(entropy, new RenderOptions(2.0, 12.0, "label"));
 * }</pre>
 */
public final class Entviz {

    private Entviz() {
    }

    /** The entviz spec level this library implements (e.g. {@code "v10"}). */
    public static final String SPEC_VERSION = Core.SPEC_VERSION;

    /** This library's own version stamp (emitted as {@code data-entviz-lib}). */
    public static final String LIB_VERSION = Core.LIB_VERSION;

    /**
     * Renders {@code entropy} with the conventional defaults (aspect ratio 1.0,
     * 12pt, no note).
     *
     * @param entropy the entropy string to visualize
     * @return the entviz SVG document as a string
     * @throws RenderException if the input or options are rejected (e.g. an
     *                         invalid EIP-55 checksum, an over-long note, or an
     *                         out-of-range option)
     */
    public static String render(String entropy) {
        return render(entropy, RenderOptions.DEFAULTS);
    }

    /**
     * Renders {@code entropy} with the given {@link RenderOptions}.
     *
     * @param entropy the entropy string to visualize
     * @param opts    the rendering parameters
     * @return the entviz SVG document as a string
     * @throws RenderException if the input or options are rejected
     */
    public static String render(String entropy, RenderOptions opts) {
        return Pipeline.render(entropy, opts.targetAspectRatio(), opts.fontSizePt(), opts.note());
    }
}
