package io.github.dhh1128.entviz;

/**
 * Describes a character set and its tokenization density.
 *
 * @param name        the alphabet's stable name (e.g. {@code "hex"})
 * @param chars       the canonical (upper- or canonical-case) character set
 * @param bitsPerChar the number of bits each character contributes
 */
public record Alphabet(String name, String chars, int bitsPerChar) {

    /** Canonical hexadecimal alphabet (4 bits/char). */
    public static final Alphabet HEX = new Alphabet("hex", "0123456789ABCDEF", 4);

    /** RFC 4648 base64url alphabet (6 bits/char). */
    public static final Alphabet BASE64URL =
            new Alphabet("base64url", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 6);

    /** Bitcoin base58 alphabet (6 bits/char). */
    public static final Alphabet BASE58 =
            new Alphabet("base58", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 6);

    /** Standard base64 alphabet (6 bits/char). */
    public static final Alphabet BASE64 =
            new Alphabet("base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 6);

    /** RFC 4648 base32 alphabet (5 bits/char). */
    public static final Alphabet BASE32 =
            new Alphabet("base32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5);

    /** Bech32 alphabet (5 bits/char). */
    public static final Alphabet BECH32 =
            new Alphabet("bech32", "qpzry9x8gf2tvdw0s3jn54khce6mua7l", 5);

    /** Crockford base32 alphabet (5 bits/char). */
    public static final Alphabet CROCKFORD32 =
            new Alphabet("crockford32", "0123456789ABCDEFGHJKMNPQRSTVWXYZ", 5);

    /** Base36 alphabet (6 bits/char). */
    public static final Alphabet BASE36 =
            new Alphabet("base36", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6);

    /** Decimal alphabet (4 bits/char). */
    public static final Alphabet DECIMAL = new Alphabet("decimal", "0123456789", 4);
}
