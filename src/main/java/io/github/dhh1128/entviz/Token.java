package io.github.dhh1128.entviz;

/**
 * One rendered chunk of entropy (or one ftok of a fingerprint).
 *
 * @param text  the literal character chunk
 * @param index the token's position in its sequence
 * @param quant the 24-bit quantized value derived from the chunk
 */
public record Token(String text, int index, int quant) {
}
