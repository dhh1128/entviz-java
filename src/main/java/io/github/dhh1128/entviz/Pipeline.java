package io.github.dhh1128.entviz;

import io.github.dhh1128.entviz.Core.Grid;
import io.github.dhh1128.entviz.Core.VisualStyle;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Full render pipeline: entropy string → SVG string.
 *
 * <p>Faithful port of {@code pipeline.rs} / {@code pipeline.go} (themselves
 * ports of {@code pipeline.py} + {@code renderer.py} + {@code shapes.py}).
 * Produces an SVG whose normative {@code data-*} attributes and geometry let the
 * conformance Tier-A extractor recover the golden render model, and whose
 * non-text pixels match the golden Tier-B raster.
 */
final class Pipeline {

    private Pipeline() {
    }

    private static final double DPI = 96.0;
    /** Transparent quiet ring (user units) around the frame so it never sits on the canvas edge. */
    private static final double MARGIN = 1.0;
    private static final int NOTE_MAX_LEN = 10;
    private static final int MAX_INPUT_CHARS = 65536;
    private static final String MONOSPACE_FONT_FAMILY =
            "\"JetBrains Mono\", \"Menlo\", \"Consolas\", \"DejaVu Sans Mono\", "
            + "\"Liberation Mono\", \"Roboto Mono\", \"Noto Sans Mono\", monospace";

    // ---- note sanitization ----------------------------------------------

    static String sanitizeNote(String note) {
        if (note == null) {
            return null;
        }
        if (note.isEmpty()) {
            return null;
        }
        int count = note.codePointCount(0, note.length());
        if (count > NOTE_MAX_LEN) {
            throw new RenderException(RenderException.Kind.NOTE,
                    "note must be at most " + NOTE_MAX_LEN + " characters (got " + count + ")");
        }
        int[] cps = note.codePoints().toArray();
        for (int c : cps) {
            if (c < ' ' || c > '~') {
                throw new RenderException(RenderException.Kind.NOTE,
                        "note must be printable ASCII (U+0020-U+007E); no control or non-ASCII characters");
            }
        }
        return note;
    }

    // ---- XML helpers -----------------------------------------------------

    static String escAttr(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String escText(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * Serializes a coordinate per the spec's numeric rule: a finite plain
     * decimal, never exponential, ≤3 fractional digits, no trailing zeros,
     * integers without a decimal point, -0 as 0. Rounding is half-to-even.
     */
    static String n(double x) {
        if (Double.isInfinite(x) || Double.isNaN(x)) {
            return "0";
        }
        // Match Go's roundHalfEven: round-half-to-even at 3 places by scaling,
        // then emit the shortest plain decimal that round-trips (Go's
        // FormatFloat(_, 'f', -1, 64)).
        double rounded = Math.rint(x * 1000.0) / 1000.0;
        if (rounded == 0.0) {
            return "0"; // collapses -0.0 too
        }
        // BigDecimal.valueOf uses Double.toString (shortest round-trip), and
        // toPlainString avoids exponential notation.
        String s = BigDecimal.valueOf(rounded).stripTrailingZeros().toPlainString();
        if (s.equals("-0") || s.isEmpty()) {
            s = "0";
        }
        return s;
    }

    // ---- characterize (structured, no render) ----------------------------

    /**
     * Parses {@code entropyText} and returns its structured characterization,
     * reusing the exact strip / input-length / parse prelude that {@link
     * #render} performs. See {@link Entviz#characterize(String)}.
     */
    static Characterization characterize(String entropyText) {
        if (entropyText.codePointCount(0, entropyText.length()) > MAX_INPUT_CHARS) {
            throw new RenderException(RenderException.Kind.INPUT_TOO_LONG, "input too long");
        }
        String rawInput = entropyText.strip();
        Parsed parsed;
        try {
            parsed = Entropy.parse(rawInput);
        } catch (Eip55Exception e) {
            throw new Eip55RenderException(e.position());
        }
        String fallbackCore =
                Core.b64urlEncode(rawInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Characterize.characterize(rawInput, parsed, fallbackCore);
    }

    // ---- main render -----------------------------------------------------

    static String render(String entropyText, double targetAr, double fontSizePt, String note) {
        String sanitized = sanitizeNote(note);
        if (entropyText.codePointCount(0, entropyText.length()) > MAX_INPUT_CHARS) {
            throw new RenderException(RenderException.Kind.INPUT_TOO_LONG, "input too long");
        }
        if (fontSizePt < 6.0 || fontSizePt > 30.0) {
            throw new RenderException(RenderException.Kind.FONT_SIZE, "font size out of range");
        }
        if (targetAr < 0.01 || targetAr > 100.0) {
            throw new RenderException(RenderException.Kind.ASPECT_RATIO, "aspect ratio out of range");
        }

        String rawInput = entropyText.strip();
        Parsed parsed;
        try {
            parsed = Entropy.parse(rawInput);
        } catch (Eip55Exception e) {
            throw new Eip55RenderException(e.position());
        }

        String core;
        Alphabet alphabet;
        String prefix = null;
        String suffix = null;
        boolean prefixSemantic = false;

        String fallbackCore = Core.b64urlEncode(rawInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        if (parsed == null) {
            core = fallbackCore;
            alphabet = Alphabet.BASE64URL;
        } else {
            core = parsed.core();
            alphabet = parsed.alphabet();
            prefix = parsed.prefix();
            suffix = parsed.suffix();
            prefixSemantic = parsed.prefixSemantic();
        }

        Entropy.TokenizeResult tr = Entropy.tokenizeEntropy(core, alphabet);
        List<Token> tokens = tr.tokens();
        boolean isTruncated = tr.truncated();
        if (tokens.isEmpty()) {
            throw new RenderException(RenderException.Kind.NO_TOKENS, "no tokens");
        }
        int rawInputBytes = rawInput.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        int truncatedBytes = isTruncated ? rawInputBytes : -1;
        int tokenCount = tokens.size();

        String fingerprintCore = core;
        if (prefix != null && prefixSemantic) {
            fingerprintCore = prefix + core;
        }

        byte[] primary = Core.computeFingerprint(fingerprintCore);
        List<Token> ftoksAll = Core.tokenizeFingerprint(primary);
        List<Token> usedFtoks = new ArrayList<>(ftoksAll.subList(0, tokenCount));

        int gridTokenCount = isTruncated ? 22 : tokenCount;
        Grid grid = Core.chooseGrid(gridTokenCount, targetAr);
        Token medianFtok = Core.medianToken(usedFtoks);
        Token[] quartileFtoks = Core.quartileTokens(usedFtoks);
        VisualStyle style = Core.selectVisualStyle(medianFtok);

        int[] cellIndices = Core.assignCellIndices(tokens, grid, medianFtok, usedFtoks);

        // --- geometry ---
        double fontPx = fontSizePt * DPI / 72.0;
        double nucleusW = fontPx * 3.0;
        double nucleusH = fontPx * 1.25;
        double boxW = nucleusW / 8.0;
        double boxH = nucleusH / 2.0;
        double cellW = nucleusW + 2.0 * boxW;
        double cellH = nucleusH + 2.0 * boxH;
        double gm = boxH / 2.0;
        double barW = 2.0 * boxH;
        double gridW = cellW * grid.cols();
        double gridH = cellH * grid.rows();

        double innerW = 1.0 + barW + 1.0 + gm + gridW + gm + 1.0;
        boolean hasBottomLabel = suffix != null || sanitized != null;
        double bottomRegion = hasBottomLabel ? nucleusH + gm : gm;
        double innerH = 1.0 + gm + nucleusH + gridH + bottomRegion + 1.0;
        double boundingW = innerW + 2.0 * MARGIN;
        double boundingH = innerH + 2.0 * MARGIN;

        double gridLeft = MARGIN + 1.0 + barW + 1.0 + gm;
        double gridTop = MARGIN + 1.0 + gm + nucleusH;
        double gridRight = gridLeft + gridW;
        double gridBottom = gridTop + gridH;

        int cellCount = grid.cols() * grid.rows();
        boolean[] usedCells = new boolean[cellCount];
        for (int ci : cellIndices) {
            usedCells[ci] = true;
        }

        // --- cell text sizes (keyed on the input alphabet, applied to every
        // cell of it including a short final token; the Crockford middle cells
        // are sized from their own 5-char alphabet below) ---
        double cellTextPt = alphabet.bitsPerChar() == 4 ? Math.rint(fontSizePt * 0.75) : fontSizePt;
        double cellTextPx = cellTextPt * DPI / 72.0;
        double labelTextPx = Math.rint(fontSizePt * 0.75) * DPI / 72.0;
        double fpMiddleTextPx = Math.rint(fontSizePt * 0.80) * DPI / 72.0;

        // --- fingerprint-edge cells ---
        boolean[] fpEdgeCells = new boolean[cellCount];
        if (usedCells[0]) {
            fpEdgeCells[0] = true;
        }
        for (int qi = 0; qi < 2 && qi < quartileFtoks.length; qi++) {
            Token q = quartileFtoks[qi];
            if (q != null) {
                fpEdgeCells[cellIndices[q.index()]] = true;
            }
        }

        // --- nucleus bg per token ---
        record TokenCell(Token token, Token ftok, int ci, String nucleusBg) {
        }
        List<TokenCell> tokenCells = new ArrayList<>(tokenCount);
        for (Token token : tokens) {
            int ci = cellIndices[token.index()];
            String nucleusBg;
            if (isTruncated && token.index() >= 8 && token.index() <= 11) {
                nucleusBg = style.bgColor();
            } else {
                nucleusBg = Core.nucleusColors(token.quant())[0];
            }
            tokenCells.add(new TokenCell(token, usedFtoks.get(token.index()), ci, nucleusBg));
        }

        // ===================== build SVG =====================
        StringBuilder s = new StringBuilder(8192);

        String truncAttr = isTruncated ? " data-truncated=\"true\"" : "";

        // entropy characterization: reporting-only structured fields emitted
        // as root data-* attributes (no ink). Null scheme/role -> empty string;
        // qualifiers/parts as compact JSON (XML-escaped). See Characterize.
        Characterization ch = Characterize.characterize(rawInput, parsed, fallbackCore);
        StringBuilder chAttrs = new StringBuilder();
        chAttrs.append(" data-encoding=\"").append(escAttr(ch.encoding()))
                .append("\" data-scheme=\"").append(escAttr(ch.scheme() == null ? "" : ch.scheme()))
                .append("\" data-role=\"").append(escAttr(ch.role() == null ? "" : ch.role()))
                .append("\" data-size-basis=\"").append(escAttr(ch.sizeBasis()))
                .append("\" data-entropy-type=\"").append(escAttr(ch.entropyType()))
                .append("\" data-size-bits=\"").append(ch.sizeBits())
                .append("\" data-qualifiers=\"").append(escAttr(Characterize.qualifiersJson(ch.qualifiers())))
                .append("\" data-parts=\"").append(escAttr(Characterize.partsJson(ch.parts())))
                .append('"');

        s.append("<svg width=\"").append(n(boundingW)).append("\" height=\"").append(n(boundingH))
                .append("\" viewBox=\"0 0 ").append(n(boundingW)).append(' ').append(n(boundingH))
                .append("\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"")
                .append(escAttr(MONOSPACE_FONT_FAMILY))
                .append("\" data-entviz-version=\"").append(Core.SPEC_VERSION)
                .append("\" data-entviz-lib=\"").append(Core.LIB_VERSION)
                .append("\" data-input-bytes=\"").append(rawInputBytes)
                .append("\" data-cols=\"").append(grid.cols())
                .append("\" data-rows=\"").append(grid.rows())
                .append('"').append(truncAttr).append(chAttrs).append('>');

        // defs + clipPath
        StringBuilder digestHexB = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            digestHexB.append(String.format("%02x", primary[i] & 0xFF));
        }
        String clipID = "grid-clip-" + digestHexB + "-" + grid.cols() + "x" + grid.rows();
        s.append("<defs><clipPath id=\"").append(escAttr(clipID)).append("\"><rect x=\"")
                .append(n(gridLeft)).append("\" y=\"").append(n(gridTop)).append("\" width=\"")
                .append(n(gridW)).append("\" height=\"").append(n(gridH)).append("\"/></clipPath></defs>");

        // bounding white background (inner field only; outer MARGIN ring stays transparent)
        s.append("<rect x=\"").append(n(MARGIN)).append("\" y=\"").append(n(MARGIN))
                .append("\" width=\"").append(n(boundingW - 2.0 * MARGIN)).append("\" height=\"")
                .append(n(boundingH - 2.0 * MARGIN)).append("\" fill=\"#ffffff\"/>");

        // grid channel
        s.append("<g data-channel=\"grid\">");
        s.append("<rect x=\"").append(n(gridLeft)).append("\" y=\"").append(n(gridTop))
                .append("\" width=\"").append(n(gridW)).append("\" height=\"").append(n(gridH))
                .append("\" fill=\"").append(escAttr(style.bgColor())).append("\"/>");

        // Layer 1: surround edges.
        Map<Integer, int[]> surroundBitsByCell = new HashMap<>();
        Map<Integer, String> surroundEdgeByCell = new HashMap<>();
        s.append("<g>");
        for (TokenCell tc : tokenCells) {
            Token ftok = tc.ftok();
            int ci = tc.ci();
            String edgeColor;
            if (fpEdgeCells[ci]) {
                edgeColor = style.edgeColors().get(ftok.quant() & 0b11);
            } else {
                edgeColor = Core.closestPaletteColor(tc.nucleusBg(), style.edgeColors());
            }
            int col = ci % grid.cols();
            int row = ci / grid.cols();
            double cellLeft = gridLeft + col * cellW;
            double cellTop = gridTop + row * cellH;
            int bits = 0;
            StringBuilder d = new StringBuilder();
            for (int i = 0; i < 24; i++) {
                if (((ftok.quant() >> i) & 1) == 0) {
                    continue;
                }
                bits |= 1 << i;
                double[] origin = boxOrigin(i, cellLeft, cellTop, boxW, boxH);
                d.append('M').append(n(origin[0])).append(' ').append(n(origin[1]))
                        .append('h').append(n(boxW)).append('v').append(n(boxH))
                        .append("h-").append(n(boxW)).append('z');
            }
            if (d.length() > 0) {
                s.append("<path fill=\"").append(escAttr(edgeColor)).append("\" d=\"").append(d).append("\"/>");
            }
            surroundBitsByCell.put(ci, new int[] {bits});
            surroundEdgeByCell.put(ci, edgeColor);
        }
        s.append("</g>");

        // Layer 2: ellipse overlay
        drawEllipseOverlay(s, primary, grid, gridLeft, gridTop, gridW, gridH, cellW, cellH, style.bgColor(), clipID);

        // --- min/max ftok cells for the blank map ---
        int minCellQ = -1; // sentinel: unset (use unsigned max comparison)
        boolean minSet = false;
        int minCellIdx = 0;
        int maxCellQ = 0;
        int maxCellIdx = 0;
        for (Token token : tokens) {
            int q = usedFtoks.get(token.index()).quant();
            int ci = cellIndices[token.index()];
            if (!minSet || Integer.compareUnsigned(q, minCellQ) < 0
                    || (q == minCellQ && ci > minCellIdx)) {
                minCellQ = q;
                minCellIdx = ci;
                minSet = true;
            }
            if (Integer.compareUnsigned(q, maxCellQ) > 0 || (q == maxCellQ && ci > maxCellIdx)) {
                maxCellQ = q;
                maxCellIdx = ci;
            }
        }

        // --- blanks + fills ---
        List<Integer> blankIndices = new ArrayList<>();
        for (int ci = 0; ci < cellCount; ci++) {
            if (!usedCells[ci]) {
                blankIndices.add(ci);
            }
        }
        int mapCellIdx = -1;
        if (!blankIndices.isEmpty()) {
            mapCellIdx = blankIndices.get(0);
            for (int bi : blankIndices) {
                if (bi < mapCellIdx) {
                    mapCellIdx = bi;
                }
            }
        }
        boolean soleBlank = blankIndices.size() == 1;
        String mapFill = style.bgColor().equals("#ffffff") ? "#e7be00" : "#ffffff";
        Map<Integer, String> blankFillColor = new HashMap<>();
        int j = 0;
        for (int bi : blankIndices) {
            if (bi != mapCellIdx || soleBlank) {
                String color = style.edgeColors().get(primary[32 + j] & 0b11);
                blankFillColor.put(bi, color);
                j++;
            }
        }

        // --- quartile marks per cell ---
        Map<Integer, Token> tokenByIndex = new HashMap<>();
        for (Token t : tokens) {
            tokenByIndex.put(t.index(), t);
        }
        Map<Integer, int[]> quartileQIdxOfCell = new HashMap<>();
        Map<Integer, String> quartileFgOfCell = new HashMap<>();
        for (int qIdx = 0; qIdx < quartileFtoks.length; qIdx++) {
            Token qFtok = quartileFtoks[qIdx];
            if (qFtok != null) {
                int ci = cellIndices[qFtok.index()];
                Token token = tokenByIndex.get(qFtok.index());
                if (token != null) {
                    String fg = Core.nucleusColors(token.quant())[1];
                    quartileQIdxOfCell.put(ci, new int[] {qIdx});
                    quartileFgOfCell.put(ci, fg);
                }
            }
        }

        // fingerprint cells (token indices 8..11) for tagging
        boolean[] fingerprintCells = new boolean[cellCount];
        if (isTruncated) {
            for (int t = 8; t < 12; t++) {
                fingerprintCells[cellIndices[t]] = true;
            }
        }

        // Layer 3+: per-cell groups in cell-index order
        s.append("<g>");
        String fpBorder = style.bgColor().equals("#ffffff") ? "#e7be00" : "#ffffff";
        double cornerRadius = nucleusH / 2.0;
        for (int ci = 0; ci < cellCount; ci++) {
            int col = ci % grid.cols();
            int row = ci / grid.cols();
            StringBuilder attrs = new StringBuilder();
            attrs.append(" data-channel=\"cell\" data-cell-index=\"").append(ci)
                    .append("\" data-cell-row=\"").append(row)
                    .append("\" data-cell-col=\"").append(col).append('"');
            boolean isBlank = !usedCells[ci];
            if (isBlank) {
                attrs.append(" data-cell-blank=\"true\"");
            }
            if (fingerprintCells[ci]) {
                attrs.append(" data-cell-fingerprint=\"true\"");
            }
            boolean isMap = isBlank && ci == mapCellIdx;
            if (isMap) {
                attrs.append(" data-cell-blank-map=\"true\"");
            }
            int[] si = surroundBitsByCell.get(ci);
            if (si != null) {
                attrs.append(" data-surround-bits=\"0x").append(Integer.toHexString(si[0])).append('"');
                if (si[0] != 0) {
                    attrs.append(" data-edge-color=\"").append(escAttr(surroundEdgeByCell.get(ci))).append('"');
                }
            }
            int[] qOfCell = quartileQIdxOfCell.get(ci);
            if (qOfCell != null) {
                attrs.append(" data-cell-quartile=\"").append(qOfCell[0] + 1).append('"');
            }
            s.append("<g").append(attrs).append('>');

            if (isBlank) {
                double nx = gridLeft + col * cellW + boxW;
                double ny = gridTop + row * cellH + boxH;
                String blankFill;
                if (isMap && !soleBlank) {
                    blankFill = mapFill;
                } else {
                    blankFill = blankFillColor.get(ci);
                }
                s.append("<rect x=\"").append(n(nx)).append("\" y=\"").append(n(ny))
                        .append("\" width=\"").append(n(nucleusW)).append("\" height=\"").append(n(nucleusH))
                        .append("\" rx=\"").append(n(cornerRadius)).append("\" ry=\"").append(n(cornerRadius))
                        .append("\" fill=\"").append(escAttr(blankFill))
                        .append("\" stroke=\"#000000\" stroke-width=\"1\"/>");
                if (isMap) {
                    double subW = nucleusW / grid.cols();
                    double subH = nucleusH / grid.rows();
                    double dotR = nucleusH / 8.0 + fontPx / 16.0;
                    double[] maxC = subCenter(maxCellIdx, nx, ny, grid, subW, subH);
                    double[] minC = subCenter(minCellIdx, nx, ny, grid, subW, subH);
                    int maxRow = maxCellIdx / grid.cols();
                    int maxCol = maxCellIdx % grid.cols();
                    int minRow = minCellIdx / grid.cols();
                    int minCol = minCellIdx % grid.cols();
                    double plusArm = dotR * 1.2;
                    double plusW = Math.max(dotR * 0.55, 1.0);
                    String minColor;
                    String maxColor;
                    if (soleBlank) {
                        String f = blankFillColor.get(mapCellIdx);
                        int quant = Core.parseHexByte(f.substring(1, 3))
                                | (Core.parseHexByte(f.substring(3, 5)) << 8)
                                | (Core.parseHexByte(f.substring(5, 7)) << 16);
                        String mc = Core.nucleusColors(quant)[1];
                        minColor = mc;
                        maxColor = mc;
                    } else {
                        minColor = "#1d4ed8";
                        maxColor = "#d62828";
                    }
                    s.append("<circle cx=\"").append(n(minC[0])).append("\" cy=\"").append(n(minC[1]))
                            .append("\" r=\"").append(n(dotR)).append("\" fill=\"").append(escAttr(minColor))
                            .append("\" data-blank-map-min=\"").append(minRow).append(',').append(minCol)
                            .append("\"/>");
                    s.append("<path d=\"M ").append(n(maxC[0] - plusArm)).append(',').append(n(maxC[1]))
                            .append(" H ").append(n(maxC[0] + plusArm))
                            .append(" M ").append(n(maxC[0])).append(',').append(n(maxC[1] - plusArm))
                            .append(" V ").append(n(maxC[1] + plusArm))
                            .append("\" fill=\"none\" stroke=\"").append(escAttr(maxColor))
                            .append("\" stroke-width=\"").append(n(plusW))
                            .append("\" stroke-linecap=\"butt\" data-blank-map-max=\"")
                            .append(maxRow).append(',').append(maxCol).append("\"/>");
                }
            } else {
                TokenCell tc = null;
                for (TokenCell t : tokenCells) {
                    if (t.ci() == ci) {
                        tc = t;
                        break;
                    }
                }
                Token token = tc.token();
                boolean isFpMiddle = isTruncated && token.index() >= 8 && token.index() <= 11;
                int r = Core.parseHexByte(tc.nucleusBg().substring(1, 3));
                int g = Core.parseHexByte(tc.nucleusBg().substring(3, 5));
                int b = Core.parseHexByte(tc.nucleusBg().substring(5, 7));
                String[] bgFg = Core.nucleusColors(r | (g << 8) | (b << 16));
                String bgColor = bgFg[0];
                String fgColor = bgFg[1];
                double nx = gridLeft + col * cellW + boxW;
                double ny = gridTop + row * cellH + boxH;
                s.append("<rect x=\"").append(n(nx)).append("\" y=\"").append(n(ny))
                        .append("\" width=\"").append(n(nucleusW)).append("\" height=\"").append(n(nucleusH))
                        .append("\" fill=\"").append(escAttr(bgColor)).append("\"/>");
                if (isFpMiddle) {
                    s.append("<rect x=\"").append(n(nx + 0.5)).append("\" y=\"").append(n(ny + 0.5))
                            .append("\" width=\"").append(n(nucleusW - 1.0)).append("\" height=\"")
                            .append(n(nucleusH - 1.0)).append("\" fill=\"none\" stroke=\"")
                            .append(escAttr(fpBorder)).append("\" stroke-width=\"1\"/>");
                }
                double textPx = isFpMiddle ? fpMiddleTextPx : cellTextPx;
                double cx = nx + nucleusW / 2.0;
                double cy = ny + nucleusH / 2.0;
                s.append("<text x=\"").append(n(cx)).append("\" y=\"").append(n(cy))
                        .append("\" fill=\"").append(escAttr(fgColor)).append("\" font-size=\"").append(n(textPx))
                        .append("\" text-anchor=\"middle\" dominant-baseline=\"central\">")
                        .append(escText(token.text())).append("</text>");
                int[] qc = quartileQIdxOfCell.get(ci);
                if (qc != null) {
                    String poly = quartilePolygon(qc[0], nx, ny, nucleusW, nucleusH);
                    s.append("<polygon points=\"").append(poly).append("\" fill=\"")
                            .append(escAttr(quartileFgOfCell.get(ci))).append("\"/>");
                }
            }
            s.append("</g>");
        }
        s.append("</g>"); // nuclei group
        s.append("</g>"); // grid channel

        // color bar
        byte[] second = Core.secondDigest(core);
        drawColorBar(s, primary, second, style, barW, boundingH, cellTextPx);

        // labels: the visible top strip is a pure projection of the
        // characterization through one grammar (renderLabel), NOT a per-parser
        // typeName/prefix fusing. `ch` is the same characterization already
        // emitted as data-* attributes above. renderLabel prepends the "+hash "
        // marker when truncated; drawLabelStrips re-applies it structurally
        // (bold dark-red tspan), so we pass the marker-free top.
        //
        // The top strip has a trailing slot echoing the stripped front prefix
        // (0x, bc1, cosmos1, the SSH header, …). The prefix is the only elastic
        // element and is truncated to the character budget the grid leaves on
        // the label line: lineChars = floor(gridW / (labelPx * LABEL_ADVANCE_EM)).
        // LABEL_ADVANCE_EM is a fixed spec constant (NOT the renderer's real font
        // metric) so every implementation truncates identically and the Tier-A
        // label string is reproducible.
        int labelLineChars = (int) Math.floor(gridW / (labelTextPx * Characterize.LABEL_ADVANCE_EM));
        String labelTop = Characterize.renderLabel(ch, isTruncated, null, null, labelLineChars)[0];
        final String TRUNC_MARKER = Characterize.TRUNC_MARKER;
        if (isTruncated && labelTop.startsWith(TRUNC_MARKER)) {
            labelTop = labelTop.substring(TRUNC_MARKER.length());
        }
        drawLabelStrips(s, gridLeft, gridRight, gridTop, gridBottom, nucleusH,
                labelTop, suffix, labelTextPx, truncatedBytes, sanitized);

        // borders
        appendBorderLine(s, MARGIN, MARGIN + 0.5, boundingW - MARGIN, MARGIN + 0.5);
        appendBorderLine(s, boundingW - MARGIN - 0.5, MARGIN, boundingW - MARGIN - 0.5, boundingH - MARGIN);
        appendBorderLine(s, MARGIN, boundingH - MARGIN - 0.5, boundingW - MARGIN, boundingH - MARGIN - 0.5);
        appendBorderLine(s, MARGIN + 0.5, MARGIN, MARGIN + 0.5, boundingH - MARGIN);
        appendBorderLine(s, MARGIN + 1.0 + barW + 0.5, MARGIN, MARGIN + 1.0 + barW + 0.5, boundingH - MARGIN);

        s.append("</svg>");
        return s.toString();
    }

    private static void appendBorderLine(StringBuilder s, double x1, double y1, double x2, double y2) {
        s.append("<line x1=\"").append(n(x1)).append("\" y1=\"").append(n(y1))
                .append("\" x2=\"").append(n(x2)).append("\" y2=\"").append(n(y2))
                .append("\" stroke=\"#808080\" stroke-width=\"1\" shape-rendering=\"crispEdges\"/>");
    }

    private static double[] boxOrigin(int i, double cellLeft, double cellTop, double bw, double bh) {
        if (i < 10) {
            return new double[] {cellLeft + i * bw, cellTop};
        } else if (i < 12) {
            return new double[] {cellLeft + 9.0 * bw, cellTop + bh + (i - 10) * bh};
        } else if (i < 22) {
            return new double[] {cellLeft + (21 - i) * bw, cellTop + 3.0 * bh};
        } else {
            return new double[] {cellLeft, cellTop + bh + (23 - i) * bh};
        }
    }

    private static double[] subCenter(int cellIdx, double nx, double ny, Grid grid, double subW, double subH) {
        return new double[] {
                nx + (cellIdx % grid.cols()) * subW + 0.5 * subW,
                ny + (cellIdx / grid.cols()) * subH + 0.5 * subH,
        };
    }

    private static String quartilePolygon(int qIdx, double nx, double ny, double w, double h) {
        double leg = h / 2.0;
        double left = nx;
        double top = ny;
        double right = nx + w;
        double bottom = ny + h;
        double[][] pts;
        switch (qIdx) {
            case 0 -> pts = new double[][] {{left, top}, {left + leg, top}, {left, top + leg}};
            case 1 -> pts = new double[][] {{right, top}, {right - leg, top}, {right, top + leg}};
            case 2 -> pts = new double[][] {{right, bottom}, {right, bottom - leg}, {right - leg, bottom}};
            default -> pts = new double[][] {{left, bottom}, {left, bottom - leg}, {left + leg, bottom}};
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pts.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(n(pts[i][0])).append(',').append(n(pts[i][1]));
        }
        return sb.toString();
    }

    // --- ellipse overlay ---

    private static void drawEllipseOverlay(StringBuilder s, byte[] digest, Grid grid,
            double gridLeft, double gridTop, double gridW, double gridH, double cellW, double cellH,
            String bgColor, String clipID) {
        int interiorCount = saturatingSub(grid.cols(), 1) * saturatingSub(grid.rows(), 1);
        List<double[]> points = new ArrayList<>();
        if (interiorCount >= 6) {
            for (int r = 1; r < grid.rows(); r++) {
                for (int c = 1; c < grid.cols(); c++) {
                    points.add(new double[] {gridLeft + c * cellW, gridTop + r * cellH});
                }
            }
        } else {
            for (int c = 0; c <= grid.cols(); c++) {
                points.add(new double[] {gridLeft + c * cellW, gridTop});
            }
            for (int r = 1; r < grid.rows(); r++) {
                points.add(new double[] {gridLeft, gridTop + r * cellH});
                points.add(new double[] {gridLeft + grid.cols() * cellW, gridTop + r * cellH});
            }
            for (int c = 0; c <= grid.cols(); c++) {
                points.add(new double[] {gridLeft + c * cellW, gridTop + grid.rows() * cellH});
            }
        }
        if (points.isEmpty()) {
            return;
        }
        double[] anchor = points.get((digest[60] & 0xFF) % points.size());
        double gridRight = gridLeft + gridW;
        double gridBottom = gridTop + gridH;
        double[][] corners = {
                {gridLeft, gridTop}, {gridRight, gridTop}, {gridLeft, gridBottom}, {gridRight, gridBottom},
        };
        double dFar = 0.0;
        for (double[] c : corners) {
            double d = Math.sqrt(Math.pow(c[0] - anchor[0], 2) + Math.pow(c[1] - anchor[1], 2));
            if (d > dFar) {
                dFar = d;
            }
        }
        double rMin = 0.22 * dFar;
        double rMax = 0.58 * dFar;
        if (rMax <= rMin) {
            return;
        }
        double rx = rMin + ((digest[61] & 0xFF) % 16 / 15.0) * (rMax - rMin);
        double ry = rMin + ((digest[62] & 0xFF) % 16 / 15.0) * (rMax - rMin);
        double rotation = ((digest[63] & 0xFF) % 16 / 15.0) * 180.0;
        double[] overlay = overlayForBg(bgColor);
        String fill = overlay[0] == 0 ? "#000000" : "#ffffff";
        double fillOp = overlay[1];
        double edgeOp = overlay[2];
        double strokeW = cellH / 20.0;
        s.append("<g clip-path=\"url(#").append(clipID).append(")\" data-channel=\"ellipse\" data-ellipse-anchor-x=\"")
                .append(n(anchor[0])).append("\" data-ellipse-anchor-y=\"").append(n(anchor[1]))
                .append("\" data-ellipse-rx=\"").append(n(rx)).append("\" data-ellipse-ry=\"").append(n(ry))
                .append("\" data-ellipse-rotation-deg=\"").append(n(rotation)).append("\">");
        s.append("<ellipse cx=\"").append(n(anchor[0])).append("\" cy=\"").append(n(anchor[1]))
                .append("\" rx=\"").append(n(rx)).append("\" ry=\"").append(n(ry))
                .append("\" transform=\"rotate(").append(n(rotation)).append(' ').append(n(anchor[0]))
                .append(' ').append(n(anchor[1])).append(")\" fill=\"").append(fill)
                .append("\" stroke=\"").append(fill).append("\" fill-opacity=\"").append(n(fillOp))
                .append("\" stroke-opacity=\"").append(n(edgeOp)).append("\" stroke-width=\"")
                .append(n(strokeW)).append("\"/>");
        s.append("</g>");
    }

    private static int saturatingSub(int a, int b) {
        return a < b ? 0 : a - b;
    }

    /** Returns {fillIsBlackFlag(0=black,1=white), fillOpacity, strokeOpacity}. */
    private static double[] overlayForBg(String bg) {
        return switch (bg) {
            case "#ffffff" -> new double[] {0, 0.20, 0.30};
            case "#e7be00" -> new double[] {0, 0.20, 0.30};
            case "#ff3f2f" -> new double[] {0, 0.25, 0.35};
            case "#2f3fbf" -> new double[] {1, 0.35, 0.45};
            default -> new double[] {0, 0.20, 0.30};
        };
    }

    // --- color bar ---

    private static int[] firstAppearance(byte[] digest) {
        int[] first = {-1, -1, -1, -1};
        int idx = 0;
        for (byte by : digest) {
            int b = by & 0xFF;
            for (int shift : new int[] {0, 2, 4, 6}) {
                int p = (b >> shift) & 3;
                if (first[p] == -1) {
                    first[p] = idx;
                }
                idx++;
            }
        }
        Integer[] order = {0, 1, 2, 3};
        java.util.Arrays.sort(order, (a, b) -> {
            if (first[a] != first[b]) {
                return Integer.compare(first[a], first[b]);
            }
            return Integer.compare(a, b);
        });
        return new int[] {order[0], order[1], order[2], order[3]};
    }

    private static void drawColorBar(StringBuilder s, byte[] digest, byte[] second, VisualStyle style,
            double barW, double boundingH, double cellTextPx) {
        double barLeft = MARGIN + 1.0;
        double barTop = MARGIN + 1.0;
        double barHeight = boundingH - 2.0 * MARGIN - 2.0;
        int[] counts = Core.twoBitCounts(digest);
        List<String> edge = style.edgeColors();
        int[] order = firstAppearance(digest);
        Map<String, Integer> orderPos = new HashMap<>();
        for (int i = 0; i < order.length; i++) {
            orderPos.put(edge.get(order[i]), i);
        }
        Map<String, Integer> colorOrder = new HashMap<>();
        for (int i = 0; i < edge.size(); i++) {
            colorOrder.put(edge.get(i), i);
        }

        record Band(String color, int count) {
        }
        List<Band> used = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            if (counts[i] > 0) {
                used.add(new Band(edge.get(i), counts[i]));
            }
        }
        if (used.isEmpty()) {
            return;
        }
        used.sort((a, b) -> {
            int opA = orderPos.getOrDefault(a.color(), 4);
            int opB = orderPos.getOrDefault(b.color(), 4);
            if (opA != opB) {
                return Integer.compare(opA, opB);
            }
            int coA = colorOrder.getOrDefault(a.color(), 4);
            int coB = colorOrder.getOrDefault(b.color(), 4);
            return Integer.compare(coA, coB);
        });
        double total = 0.0;
        for (Band b : used) {
            total += Math.pow(b.count(), 4);
        }

        int k = (int) Math.floor(barHeight / 12.0);
        if (k < 4) {
            k = 4;
        }
        if (k > 16) {
            k = 16;
        }
        int leftSlot = (second[12] & 0xFF) % k;
        int rightSlot = (second[13] & 0xFF) % k;

        s.append("<g data-channel=\"color-bar\" data-bar-slots=\"").append(k)
                .append("\" data-bar-marker-left=\"").append(leftSlot)
                .append("\" data-bar-marker-right=\"").append(rightSlot).append("\">");
        double barCx = barLeft + barW / 2.0;
        double y = barTop;
        int last = used.size() - 1;
        for (int i = 0; i < used.size(); i++) {
            Band b = used.get(i);
            double h;
            if (i == last) {
                h = (barTop + barHeight) - y;
            } else {
                h = barHeight * Math.pow(b.count(), 4) / total;
            }
            String letter = Core.bandLetter(b.color());
            if (!letter.isEmpty()) {
                s.append("<g data-color-bar-rank=\"").append(i).append("\" data-color-bar-band=\"")
                        .append(letter).append("\">");
            } else {
                s.append("<g data-color-bar-rank=\"").append(i).append("\">");
            }
            s.append("<rect x=\"").append(n(barLeft)).append("\" y=\"").append(n(y))
                    .append("\" width=\"").append(n(barW)).append("\" height=\"").append(n(h))
                    .append("\" fill=\"").append(escAttr(b.color())).append("\"/>");
            if (!letter.isEmpty()) {
                int r = Core.parseHexByte(b.color().substring(1, 3));
                int g = Core.parseHexByte(b.color().substring(3, 5));
                int bb = Core.parseHexByte(b.color().substring(5, 7));
                String fg = Core.nucleusColors(r | (g << 8) | (bb << 16))[1];
                double fontSize = cellTextPx;
                double baselineY = (y + h) - 0.22 * fontSize;
                s.append("<text x=\"").append(n(barCx)).append("\" y=\"").append(n(baselineY))
                        .append("\" fill=\"").append(escAttr(fg)).append("\" font-size=\"").append(n(fontSize))
                        .append("\" text-anchor=\"middle\" data-color-bar-letter=\"true\">")
                        .append(escText(letter.toLowerCase(Locale.ROOT))).append("</text>");
            }
            s.append("</g>");
            y += h;
        }

        // markers
        double slotH = barHeight / k;
        double radius = barW * 0.17;
        double inset = barW * 0.06;
        appendMarker(s, "left", leftSlot, barTop, slotH, barLeft, inset, radius, barW);
        appendMarker(s, "right", rightSlot, barTop, slotH, barLeft, inset, radius, barW);
        s.append("</g>");
    }

    private static void appendMarker(StringBuilder s, String name, int slot, double barTop, double slotH,
            double barLeft, double inset, double radius, double barW) {
        double cy = barTop + (slot + 0.5) * slotH;
        double cx;
        if (name.equals("left")) {
            cx = barLeft + inset + radius;
        } else {
            cx = barLeft + barW - inset - radius;
        }
        s.append("<circle cx=\"").append(n(cx)).append("\" cy=\"").append(n(cy))
                .append("\" r=\"").append(n(radius))
                .append("\" fill=\"#ffffff\" stroke=\"#000000\" stroke-width=\"0.75\" data-bar-marker=\"")
                .append(name).append("\"/>");
    }

    private static void drawLabelStrips(StringBuilder s, double gridLeft, double gridRight, double gridTop,
            double gridBottom, double nucleusH, String topText, String suffix, double textPx,
            int truncatedBytes, String note) {
        String fontSizeAttr = "font-size=\"" + n(textPx) + "\"";
        // `topText` is the projected top-strip label (marker-free); the
        // "+hash " marker is applied structurally below when truncated.
        String restText = topText;
        double topCy = gridTop - nucleusH / 2.0;
        s.append("<g data-channel=\"label-top\">");
        if (truncatedBytes >= 0) {
            s.append("<text x=\"").append(n(gridLeft)).append("\" y=\"").append(n(topCy))
                    .append("\" fill=\"#666666\" ").append(fontSizeAttr)
                    .append(" dominant-baseline=\"central\"><tspan fill=\"#a00000\" font-weight=\"bold\">"
                            + "+hash </tspan>")
                    .append(escText(restText)).append("</text>");
        } else {
            s.append("<text x=\"").append(n(gridLeft)).append("\" y=\"").append(n(topCy))
                    .append("\" fill=\"#666666\" ").append(fontSizeAttr)
                    .append(" dominant-baseline=\"central\">").append(escText(restText)).append("</text>");
        }
        s.append("</g>");

        if (suffix != null || note != null) {
            double bottomCy = gridBottom + nucleusH / 2.0;
            s.append("<g data-channel=\"label-bottom\">");
            s.append("<text x=\"").append(n(gridRight)).append("\" y=\"").append(n(bottomCy))
                    .append("\" fill=\"#666666\" ").append(fontSizeAttr)
                    .append(" text-anchor=\"end\" dominant-baseline=\"central\">");
            if (suffix != null && note != null) {
                s.append("<tspan>...").append(escText(suffix)).append(" </tspan>");
                s.append("<tspan fill=\"#808080\" data-user-note=\"").append(escAttr(note)).append("\">(")
                        .append(escText(note)).append(")</tspan>");
            } else if (suffix != null) {
                s.append("...").append(escText(suffix));
            } else {
                s.append("<tspan fill=\"#808080\" data-user-note=\"").append(escAttr(note)).append("\">(")
                        .append(escText(note)).append(")</tspan>");
            }
            s.append("</text></g>");
        }
    }
}
