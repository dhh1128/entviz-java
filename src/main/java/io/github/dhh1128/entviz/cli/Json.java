package io.github.dhh1128.entviz.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A tiny, dependency-free JSON parser — just enough to read a conformance
 * vector's {@code input.json} from stdin. Supports objects, arrays, strings
 * (with full {@code \\uXXXX} / escape handling, including surrogate pairs),
 * numbers, booleans, and null. Not a general-purpose library.
 */
final class Json {

    /** Recursion cap; a deeper document throws cleanly instead of overflowing the stack. */
    private static final int MAX_DEPTH = 200;

    private final String src;
    private int pos;
    private int depth;

    private Json(String src) {
        this.src = src;
    }

    /** Parses a JSON document into Map/List/String/Double/Boolean/null. */
    static Object parse(String src) {
        Json j = new Json(src);
        j.skipWs();
        Object v = j.parseValue();
        j.skipWs();
        if (j.pos != j.src.length()) {
            throw new IllegalArgumentException("trailing content at " + j.pos);
        }
        return v;
    }

    private Object parseValue() {
        if (++depth > MAX_DEPTH) {
            throw err("nesting too deep");
        }
        try {
            char c = peek();
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f' -> parseBool();
                case 'n' -> parseNull();
                default -> parseNumber();
            };
        } finally {
            depth--;
        }
    }

    private Map<String, Object> parseObject() {
        Map<String, Object> map = new LinkedHashMap<>();
        expect('{');
        skipWs();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            String key = parseString();
            skipWs();
            expect(':');
            skipWs();
            map.put(key, parseValue());
            skipWs();
            char c = next();
            if (c == '}') {
                break;
            }
            if (c != ',') {
                throw err("expected , or }");
            }
        }
        return map;
    }

    private List<Object> parseArray() {
        List<Object> list = new ArrayList<>();
        expect('[');
        skipWs();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipWs();
            list.add(parseValue());
            skipWs();
            char c = next();
            if (c == ']') {
                break;
            }
            if (c != ',') {
                throw err("expected , or ]");
            }
        }
        return list;
    }

    private String parseString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> sb.append(parseUnicodeEscape());
                    default -> throw err("invalid escape \\" + e);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private char parseUnicodeEscape() {
        int code = 0;
        for (int i = 0; i < 4; i++) {
            char c = next();
            int d;
            if (c >= '0' && c <= '9') {
                d = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                d = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                d = c - 'A' + 10;
            } else {
                throw err("invalid \\u hex digit");
            }
            code = (code << 4) | d;
        }
        return (char) code;
    }

    private Boolean parseBool() {
        if (src.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (src.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        throw err("invalid literal");
    }

    private Object parseNull() {
        if (src.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw err("invalid literal");
    }

    private Double parseNumber() {
        int start = pos;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                pos++;
            } else {
                break;
            }
        }
        if (pos == start) {
            throw err("invalid number");
        }
        return Double.parseDouble(src.substring(start, pos));
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= src.length()) {
            throw err("unexpected end of input");
        }
        return src.charAt(pos);
    }

    private char next() {
        if (pos >= src.length()) {
            throw err("unexpected end of input");
        }
        return src.charAt(pos++);
    }

    private void expect(char c) {
        char got = next();
        if (got != c) {
            throw err("expected '" + c + "' but got '" + got + "'");
        }
    }

    private IllegalArgumentException err(String msg) {
        return new IllegalArgumentException("JSON parse error at " + pos + ": " + msg);
    }
}
