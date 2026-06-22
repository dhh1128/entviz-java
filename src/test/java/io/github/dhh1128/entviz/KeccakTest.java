package io.github.dhh1128.entviz;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class KeccakTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    void emptyInput() {
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                Keccak.keccak256Hex(ascii("")));
    }

    @Test
    void abc() {
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
                Keccak.keccak256Hex(ascii("abc")));
    }

    @Test
    void eip55Body() {
        assertEquals("d385650ce8fdc6db7ee3a091d34814dbc4ce18219ffae52182efff4034d707e5",
                Keccak.keccak256Hex(ascii("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")));
    }

    @Test
    void multiBlock200a() {
        // 200 bytes exceeds the 136-byte rate, exercising multi-block absorb.
        byte[] in = new byte[200];
        Arrays.fill(in, (byte) 'a');
        assertEquals("96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",
                Keccak.keccak256Hex(in));
    }

    @Test
    void isNotNistSha3() {
        // NIST SHA3-256("") would be a7ffc6f8...; the original Keccak padding
        // gives a different digest. Guards against a padding regression.
        String keccak = Keccak.keccak256Hex(ascii(""));
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", keccak);
    }
}
