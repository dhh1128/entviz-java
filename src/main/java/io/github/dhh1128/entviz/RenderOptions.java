package io.github.dhh1128.entviz;

/**
 * Rendering parameters for {@link Entviz#render(String, RenderOptions)}.
 *
 * @param targetAspectRatio the desired width:height ratio of the grid (default 1.0; range 0.01..100)
 * @param fontSizePt        the base font size in points (default 12; range 6..30)
 * @param note              an optional user note (printable ASCII, ≤10 code points), or null
 */
public record RenderOptions(double targetAspectRatio, double fontSizePt, String note) {

    /** The conventional defaults: aspect ratio 1.0, 12pt, no note. */
    public static final RenderOptions DEFAULTS = new RenderOptions(1.0, 12.0, null);

    /** Returns a copy of these options with a different target aspect ratio. */
    public RenderOptions withTargetAspectRatio(double ar) {
        return new RenderOptions(ar, fontSizePt, note);
    }

    /** Returns a copy of these options with a different font size. */
    public RenderOptions withFontSizePt(double pt) {
        return new RenderOptions(targetAspectRatio, pt, note);
    }

    /** Returns a copy of these options with a different note. */
    public RenderOptions withNote(String n) {
        return new RenderOptions(targetAspectRatio, fontSizePt, n);
    }
}
