package io.github.dhh1128.entviz;

/**
 * Minimal pure-Java Keccak-256 (the original Keccak, <em>not</em> NIST
 * SHA3-256).
 *
 * <p>EIP-55 Ethereum address checksums use Keccak-256, which uses the original
 * Keccak padding ({@code 0x01 … 0x80}). NIST SHA3-256 uses a different padding
 * ({@code 0x06 … 0x80}) and produces a different digest, so it cannot be used
 * here. Faithful port of the reference {@code keccak.py} (via
 * {@code keccak.rs} / {@code keccak.go}).
 */
final class Keccak {

    private Keccak() {
    }

    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    /** Rho rotation offsets, indexed {@code ROT[y][x]}. */
    private static final int[][] ROT = {
            {0, 1, 62, 28, 27},
            {36, 44, 6, 55, 20},
            {3, 10, 43, 25, 39},
            {41, 45, 15, 21, 8},
            {18, 2, 61, 56, 14},
    };

    private static final int RATE = 136;

    private static void keccakF1600(long[][] state) {
        for (long rc : RC) {
            // Theta
            long[] c = new long[5];
            for (int x = 0; x < 5; x++) {
                c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
            }
            long[] d = new long[5];
            for (int x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x][y] ^= d[x];
                }
            }

            // Rho + Pi
            long[][] b = new long[5][5];
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    b[y][(2 * x + 3 * y) % 5] = Long.rotateLeft(state[x][y], ROT[y][x] & 63);
                }
            }

            // Chi
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
                }
            }

            // Iota
            state[0][0] ^= rc;
        }
    }

    private static void absorbBlock(long[][] state, byte[] block, int off, int len) {
        for (int i = 0; i < len; i++) {
            int laneIndex = i / 8;
            int x = laneIndex % 5;
            int y = laneIndex / 5;
            int byteInLane = i % 8;
            state[x][y] ^= (((long) (block[off + i] & 0xFF)) << (8 * byteInLane));
        }
    }

    /** Returns the 32-byte Keccak-256 digest of {@code data}. */
    static byte[] keccak256(byte[] data) {
        long[][] state = new long[5][5];

        int offset = 0;
        int n = data.length;
        while (n - offset >= RATE) {
            absorbBlock(state, data, offset, RATE);
            keccakF1600(state);
            offset += RATE;
        }

        // Final block: 0x01 … 0x80 padding.
        byte[] last = new byte[RATE];
        int rem = n - offset;
        System.arraycopy(data, offset, last, 0, rem);
        last[rem] = 0x01;
        last[RATE - 1] |= (byte) 0x80;
        absorbBlock(state, last, 0, RATE);
        keccakF1600(state);

        byte[] out = new byte[32];
        for (int i = 0; i < out.length; i++) {
            int laneIndex = i / 8;
            int x = laneIndex % 5;
            int y = laneIndex / 5;
            int byteInLane = i % 8;
            out[i] = (byte) ((state[x][y] >>> (8 * byteInLane)) & 0xFF);
        }
        return out;
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Returns the lowercase hex of the Keccak-256 digest of {@code data}. */
    static String keccak256Hex(byte[] data) {
        byte[] d = keccak256(data);
        char[] out = new char[d.length * 2];
        for (int i = 0; i < d.length; i++) {
            int v = d[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
