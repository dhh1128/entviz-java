package io.github.dhh1128.entviz.cli;

import io.github.dhh1128.entviz.Entviz;
import io.github.dhh1128.entviz.RenderOptions;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The conformance CLI: read one vector's JSON on stdin, write the entviz SVG to
 * stdout (exit 0), or exit non-zero to reject (the stdin→stdout contract in the
 * entviz repo's {@code compliance/README.md}).
 *
 * <p>Exit codes: {@code 0} success, {@code 1} the render was rejected (an error
 * vector), {@code 2} a malformed request.
 */
public final class Conformance {

    private Conformance() {
    }

    /**
     * Entry point.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        byte[] buf;
        try {
            buf = System.in.readAllBytes();
        } catch (IOException e) {
            err("entviz-java: failed to read stdin");
            System.exit(2);
            return;
        }
        String entropy;
        double targetAr = 1.0;
        double fontSizePt = 12.0;
        String note = null;
        try {
            String text = new String(buf, StandardCharsets.UTF_8);
            Object root = Json.parse(text);
            if (!(root instanceof Map<?, ?> obj)) {
                throw new IllegalArgumentException("request must be a JSON object");
            }
            Object entropyVal = obj.get("entropy");
            entropy = entropyVal == null ? "" : (String) entropyVal;
            Object paramsVal = obj.get("params");
            if (paramsVal instanceof Map<?, ?> params) {
                Object ar = params.get("target_ar");
                if (ar instanceof Double d) {
                    targetAr = d;
                }
                Object fs = params.get("font_size_pt");
                if (fs instanceof Double d) {
                    fontSizePt = d;
                }
                Object nt = params.get("note");
                if (nt instanceof String str) {
                    note = str;
                }
            }
        } catch (RuntimeException e) {
            err("entviz-java: invalid request JSON: " + e.getMessage());
            System.exit(2);
            return;
        }

        String svg;
        try {
            svg = Entviz.render(entropy, new RenderOptions(targetAr, fontSizePt, note));
        } catch (RuntimeException e) {
            err("entviz-java: rejected: " + e.getMessage());
            System.exit(1);
            return;
        }

        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        out.print(svg);
        out.flush();
    }

    private static void err(String msg) {
        PrintStream e = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        e.println(msg);
    }
}
