package com.andlua.decryptor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class Lua53Source {
    private static final String[] OP = {
            "MOVE", "LOADK", "LOADKX", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETTABUP",
            "GETTABLE", "SETTABUP", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF",
            "ADD", "SUB", "MUL", "MOD", "POW", "DIV", "IDIV", "BAND", "BOR", "BXOR",
            "SHL", "SHR", "UNM", "BNOT", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT",
            "LE", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP",
            "FORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARG", "EXTRAARG"
    };

    private Lua53Source() {}

    static String decompile(byte[] chunk) {
        if (chunk == null || chunk.length < 12) {
            return null;
        }
        if (chunk[0] != 0x1b || chunk[1] != 'L' || chunk[2] != 'u' || chunk[3] != 'a') {
            return null;
        }
        try {
            Reader r = new Reader(chunk);
            r.skipHeader();
            r.u8();
            Proto main = r.proto();
            StringBuilder out = new StringBuilder();
            emit(main, out, 0, "main");
            String src = out.toString();
            if (src.trim().length() < 8) {
                return null;
            }
            return src;
        } catch (Exception e) {
            return null;
        }
    }

    private static void emit(Proto p, StringBuilder out, int depth, String name) {
        String ind = indent(depth);
        String[] reg = new String[Math.max(p.maxstack, 8)];
        for (int i = 0; i < p.locs.size(); i++) {
            String loc = p.locs.get(i);
            if (loc != null && loc.length() > 0) {
                reg[i] = loc;
            }
        }
        for (int i = 0; i < p.protos.size(); i++) {
            Proto sub = p.protos.get(i);
            String fn = "fn_" + i;
            if (sub.source != null && sub.source.length() > 0 && !sub.source.startsWith("@")
                    && !sub.source.startsWith("=")) {
                fn = sub.source;
            }
            out.append(ind).append("local function ").append(safeIdent(fn)).append("(");
            for (int a = 0; a < sub.params; a++) {
                if (a > 0) {
                    out.append(", ");
                }
                String pn = a < sub.locs.size() && sub.locs.get(a) != null ? sub.locs.get(a) : ("a" + a);
                out.append(pn);
            }
            if (sub.vararg != 0) {
                if (sub.params > 0) {
                    out.append(", ");
                }
                out.append("...");
            }
            out.append(")\n");
            emit(sub, out, depth + 1, fn);
            out.append(ind).append("end\n");
        }
        for (int pc = 0; pc < p.code.length; pc++) {
            int ins = p.code[pc];
            int op = ins & 0x3f;
            int a = (ins >>> 6) & 0xff;
            int c = (ins >>> 14) & 0x1ff;
            int b = (ins >>> 23) & 0x1ff;
            int bx = (ins >>> 14) & 0x3ffff;
            int sbx = bx - 131071;
            String opcode = op < OP.length ? OP[op] : ("OP" + op);
            String ra = rname(reg, a);
            if ("MOVE".equals(opcode)) {
                line(out, ind, ra + " = " + rname(reg, b));
            } else if ("LOADK".equals(opcode)) {
                line(out, ind, ra + " = " + kst(p, bx));
            } else if ("LOADKX".equals(opcode)) {
                line(out, ind, ra + " = " + kst(p, extra(p, pc)));
            } else if ("LOADBOOL".equals(opcode)) {
                line(out, ind, ra + " = " + (b != 0 ? "true" : "false"));
            } else if ("LOADNIL".equals(opcode)) {
                for (int i = a; i <= a + b; i++) {
                    line(out, ind, rname(reg, i) + " = nil");
                }
            } else if ("GETUPVAL".equals(opcode)) {
                line(out, ind, ra + " = " + uv(p, b));
            } else if ("GETTABUP".equals(opcode)) {
                line(out, ind, ra + " = " + index(uv(p, b), rk(p, reg, c)));
            } else if ("GETTABLE".equals(opcode)) {
                line(out, ind, ra + " = " + index(rname(reg, b), rk(p, reg, c)));
            } else if ("SETTABUP".equals(opcode)) {
                line(out, ind, index(uv(p, a), rk(p, reg, b)) + " = " + rk(p, reg, c));
            } else if ("SETUPVAL".equals(opcode)) {
                line(out, ind, uv(p, b) + " = " + ra);
            } else if ("SETTABLE".equals(opcode)) {
                line(out, ind, index(ra, rk(p, reg, b)) + " = " + rk(p, reg, c));
            } else if ("NEWTABLE".equals(opcode)) {
                line(out, ind, ra + " = {}");
            } else if ("SELF".equals(opcode)) {
                line(out, ind, rname(reg, a + 1) + " = " + rname(reg, b));
                line(out, ind, ra + " = " + index(rname(reg, b), rk(p, reg, c)));
            } else if (isArith(opcode)) {
                line(out, ind, ra + " = " + rk(p, reg, b) + " " + arith(opcode) + " " + rk(p, reg, c));
            } else if ("UNM".equals(opcode)) {
                line(out, ind, ra + " = -" + rname(reg, b));
            } else if ("BNOT".equals(opcode)) {
                line(out, ind, ra + " = ~" + rname(reg, b));
            } else if ("NOT".equals(opcode)) {
                line(out, ind, ra + " = not " + rname(reg, b));
            } else if ("LEN".equals(opcode)) {
                line(out, ind, ra + " = #" + rname(reg, b));
            } else if ("CONCAT".equals(opcode)) {
                StringBuilder parts = new StringBuilder();
                for (int i = b; i <= c; i++) {
                    if (i > b) {
                        parts.append(" .. ");
                    }
                    parts.append(rname(reg, i));
                }
                line(out, ind, ra + " = " + parts);
            } else if ("EQ".equals(opcode) || "LT".equals(opcode) || "LE".equals(opcode)) {
                String[] pair = cmp(opcode, a == 0);
                line(out, ind, "if " + rk(p, reg, b) + " " + pair[0] + " " + rk(p, reg, c) + " then");
            } else if ("TEST".equals(opcode)) {
                line(out, ind, "if " + (c != 0 ? "" : "not ") + ra + " then");
            } else if ("TESTSET".equals(opcode)) {
                line(out, ind, "if " + (c != 0 ? "" : "not ") + rname(reg, b) + " then");
                line(out, ind, "  " + ra + " = " + rname(reg, b));
            } else if ("CALL".equals(opcode) || "TAILCALL".equals(opcode)) {
                int narg = b == 0 ? -1 : b - 1;
                StringBuilder call = new StringBuilder(ra);
                call.append("(");
                if (narg < 0) {
                    call.append("...");
                } else {
                    for (int i = 1; i <= narg; i++) {
                        if (i > 1) {
                            call.append(", ");
                        }
                        call.append(rname(reg, a + i));
                    }
                }
                call.append(")");
                if (c == 1) {
                    line(out, ind, call.toString());
                } else {
                    line(out, ind, ra + " = " + call);
                }
            } else if ("RETURN".equals(opcode)) {
                if (b == 1) {
                    line(out, ind, "return");
                } else if (b == 0) {
                    line(out, ind, "return ...");
                } else {
                    StringBuilder ret = new StringBuilder("return ");
                    for (int i = 0; i < b - 1; i++) {
                        if (i > 0) {
                            ret.append(", ");
                        }
                        ret.append(rname(reg, a + i));
                    }
                    line(out, ind, ret.toString());
                }
            } else if ("FORPREP".equals(opcode)) {
                line(out, ind, "for " + rname(reg, a + 3) + " = " + ra + ", " + rname(reg, a + 1)
                        + ", " + rname(reg, a + 2) + " do");
            } else if ("FORLOOP".equals(opcode) || "TFORLOOP".equals(opcode)) {
                line(out, ind, "end");
            } else if ("TFORCALL".equals(opcode)) {
                line(out, ind, "-- iterator");
            } else if ("CLOSURE".equals(opcode)) {
                line(out, ind, ra + " = fn_" + bx);
            } else if ("VARARG".equals(opcode)) {
                line(out, ind, ra + " = ...");
            } else if ("JMP".equals(opcode)) {
                if (sbx < 0) {
                    line(out, ind, "-- loop");
                }
            } else if ("SETLIST".equals(opcode) || "EXTRAARG".equals(opcode) || "NEWTABLE".equals(opcode)) {
                // already handled / structural
            } else {
                line(out, ind, "-- " + opcode);
            }
        }
    }

    private static int extra(Proto p, int pc) {
        if (pc + 1 >= p.code.length) {
            return 0;
        }
        return (p.code[pc + 1] >>> 6);
    }

    private static void line(StringBuilder out, String ind, String s) {
        out.append(ind).append(s).append('\n');
    }

    private static String indent(int depth) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            sb.append("    ");
        }
        return sb.toString();
    }

    private static String rname(String[] reg, int i) {
        if (i >= 0 && i < reg.length && reg[i] != null) {
            return reg[i];
        }
        return "v" + i;
    }

    private static String uv(Proto p, int i) {
        if (i >= 0 && i < p.upnames.size() && p.upnames.get(i) != null
                && p.upnames.get(i).length() > 0) {
            return p.upnames.get(i);
        }
        return "_ENV";
    }

    private static String kst(Proto p, int i) {
        if (i < 0 || i >= p.consts.size()) {
            return "nil";
        }
        Object v = p.consts.get(i);
        if (v == null) {
            return "nil";
        }
        if (v instanceof Boolean) {
            return ((Boolean) v) ? "true" : "false";
        }
        if (v instanceof Long) {
            return Long.toString((Long) v);
        }
        if (v instanceof Double) {
            double d = (Double) v;
            if (d == (long) d) {
                return Long.toString((long) d);
            }
            return Double.toString(d);
        }
        String s = String.valueOf(v);
        return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + '"';
    }

    private static String rk(Proto p, String[] reg, int x) {
        if (x >= 256) {
            return kst(p, x - 256);
        }
        return rname(reg, x);
    }

    private static String index(String tab, String key) {
        if ("_ENV".equals(tab) && isQuotedIdent(key)) {
            return unquote(key);
        }
        if (isQuotedIdent(key)) {
            return tab + "." + unquote(key);
        }
        return tab + "[" + key + "]";
    }

    private static boolean isQuotedIdent(String key) {
        if (key.length() < 3 || key.charAt(0) != '"' || key.charAt(key.length() - 1) != '"') {
            return false;
        }
        String inner = unquote(key);
        if (inner.length() == 0 || !Character.isJavaIdentifierStart(inner.charAt(0))) {
            return false;
        }
        for (int i = 1; i < inner.length(); i++) {
            if (!Character.isJavaIdentifierPart(inner.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static String unquote(String key) {
        return key.substring(1, key.length() - 1);
    }

    private static boolean isArith(String op) {
        return "ADD".equals(op) || "SUB".equals(op) || "MUL".equals(op) || "MOD".equals(op)
                || "POW".equals(op) || "DIV".equals(op) || "IDIV".equals(op) || "BAND".equals(op)
                || "BOR".equals(op) || "BXOR".equals(op) || "SHL".equals(op) || "SHR".equals(op);
    }

    private static String arith(String op) {
        if ("ADD".equals(op)) {
            return "+";
        }
        if ("SUB".equals(op)) {
            return "-";
        }
        if ("MUL".equals(op)) {
            return "*";
        }
        if ("MOD".equals(op)) {
            return "%";
        }
        if ("POW".equals(op)) {
            return "^";
        }
        if ("DIV".equals(op)) {
            return "/";
        }
        if ("IDIV".equals(op)) {
            return "//";
        }
        if ("BAND".equals(op)) {
            return "&";
        }
        if ("BOR".equals(op)) {
            return "|";
        }
        if ("BXOR".equals(op)) {
            return "~";
        }
        if ("SHL".equals(op)) {
            return "<<";
        }
        if ("SHR".equals(op)) {
            return ">>";
        }
        return op;
    }

    private static String[] cmp(String op, boolean pos) {
        if ("EQ".equals(op)) {
            return pos ? new String[]{"=="} : new String[]{"~="};
        }
        if ("LT".equals(op)) {
            return pos ? new String[]{"<"} : new String[]{">="};
        }
        return pos ? new String[]{"<="} : new String[]{">"};
    }

    private static String safeIdent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (Character.isLetterOrDigit(ch) || ch == '_') {
                sb.append(ch);
            } else {
                sb.append('_');
            }
        }
        if (sb.length() == 0) {
            return "fn";
        }
        return sb.toString();
    }

    static byte[] decryptStr(byte[] enc) {
        int n = enc.length;
        if (n == 0) {
            return enc;
        }
        int key = n;
        int step = ((enc[0] & 0xff) ^ key) + n;
        step &= 0xff;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) ((enc[i] & 0xff) ^ key);
            int total = key + step;
            if (total >= 256) {
                key = (total & 0xff) + 1;
            } else {
                key = total;
            }
        }
        return out;
    }

    static String maybeDecrypt(byte[] enc) {
        if (enc == null || enc.length == 0) {
            return "";
        }
        String raw = decode(enc);
        byte[] plain = decryptStr(enc);
        String dec = decode(plain);
        if (score(dec) > score(raw) + 1) {
            return dec;
        }
        return raw;
    }

    private static String decode(byte[] data) {
        try {
            return new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return new String(data, StandardCharsets.ISO_8859_1);
        }
    }

    private static int score(String s) {
        if (s == null || s.length() == 0) {
            return 0;
        }
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) {
                n++;
            }
        }
        if (s.contains("require") || s.contains("import") || s.contains("function")
                || s.contains("android.") || s.contains("activity")) {
            n += 20;
        }
        return n * 10 / Math.max(1, s.length());
    }

    private static final class Proto {
        String source;
        int params;
        int vararg;
        int maxstack;
        int[] code = new int[0];
        final List<Object> consts = new ArrayList<>();
        final List<Proto> protos = new ArrayList<>();
        final List<String> locs = new ArrayList<>();
        final List<String> upnames = new ArrayList<>();
    }

    private static final class Reader {
        private final byte[] d;
        private int p;
        private int sizeInt = 4;
        private int sizeSizeT = 8;
        private int sizeInstr = 4;
        private int sizeInteger = 8;
        private int sizeNumber = 8;

        Reader(byte[] d) {
            this.d = d;
        }

        void skipHeader() {
            p = 4;
            u8();
            u8();
            p += 6;
            sizeInt = u8();
            sizeSizeT = u8();
            sizeInstr = u8();
            sizeInteger = u8();
            sizeNumber = u8();
            p += sizeInteger;
            p += sizeNumber;
            if (sizeInt <= 0 || sizeInt > 8) {
                sizeInt = 4;
            }
            if (sizeSizeT <= 0 || sizeSizeT > 8) {
                sizeSizeT = 8;
            }
        }

        Proto proto() {
            Proto pr = new Proto();
            pr.source = str();
            i32();
            i32();
            pr.params = u8();
            pr.vararg = u8();
            pr.maxstack = u8();
            int ncode = i32();
            pr.code = new int[Math.max(ncode, 0)];
            for (int i = 0; i < pr.code.length; i++) {
                pr.code[i] = instr();
            }
            int nk = i32();
            for (int i = 0; i < nk; i++) {
                pr.consts.add(constant());
            }
            int nup = i32();
            for (int i = 0; i < nup; i++) {
                u8();
                u8();
            }
            int np = i32();
            for (int i = 0; i < np; i++) {
                pr.protos.add(proto());
            }
            int nline = i32();
            for (int i = 0; i < nline; i++) {
                i32();
            }
            int nloc = i32();
            for (int i = 0; i < nloc; i++) {
                pr.locs.add(str());
                i32();
                i32();
            }
            int nun = i32();
            for (int i = 0; i < nun; i++) {
                pr.upnames.add(str());
            }
            return pr;
        }

        Object constant() {
            int tag = u8();
            int t = tag & 0x0f;
            if (t == 0) {
                return null;
            }
            if (t == 1) {
                return u8() != 0;
            }
            if (t == 3) {
                if (tag == 19) {
                    return integer();
                }
                return number();
            }
            if (t == 4) {
                return str();
            }
            return null;
        }

        String str() {
            long size = u8() & 0xffL;
            if (size == 0xff) {
                size = sizeT();
            }
            if (size == 0) {
                return null;
            }
            int n = (int) (size - 1);
            if (n < 0 || p + n > d.length) {
                return "";
            }
            byte[] raw = new byte[n];
            System.arraycopy(d, p, raw, 0, n);
            p += n;
            return maybeDecrypt(raw);
        }

        int u8() {
            if (p >= d.length) {
                return 0;
            }
            return d[p++] & 0xff;
        }

        int i32() {
            return (int) uint(sizeInt);
        }

        int instr() {
            return (int) uint(sizeInstr);
        }

        long sizeT() {
            return uint(sizeSizeT);
        }

        long integer() {
            return uint(sizeInteger);
        }

        double number() {
            if (sizeNumber == 4) {
                int bits = (int) uint(4);
                return Float.intBitsToFloat(bits);
            }
            long bits = uint(8);
            return Double.longBitsToDouble(bits);
        }

        long uint(int n) {
            long v = 0;
            for (int i = 0; i < n && p < d.length; i++) {
                v |= (long) (d[p++] & 0xff) << (8 * i);
            }
            return v;
        }
    }
}
