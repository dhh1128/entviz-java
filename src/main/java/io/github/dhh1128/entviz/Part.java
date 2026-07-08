package io.github.dhh1128.entviz;

/**
 * A reading-order part of a characterized entropy string: its {@code text} plus
 * a {@code bind} classification in {@code {none, fold, core}} describing whether
 * (and how) the text participates in the fingerprint.
 *
 * @param text the literal substring (prefix, core, or suffix)
 * @param bind one of {@code "none"}, {@code "fold"}, {@code "core"}
 */
public record Part(String text, String bind) {
}
