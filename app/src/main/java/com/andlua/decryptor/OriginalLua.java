package com.andlua.decryptor;

import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Inflater;

final class OriginalLua {
    private static final byte[] LUA_MAGIC = new byte[]{0x1b, 'L', 'u', 'a'};
    private static final byte[][] PREFIXES = {
            new byte[]{'H'},
            new byte[]{'h'},
            new byte[]{'I'},
            new byte[]{'G'},
            new byte[]{'J'},
            new byte[]{'A'}
    };

    static final class Result {
        final byte[] data;
        final String kind;
        final boolean changed;

        Result(byte[] data, String kind, boolean changed) {
            this.data = data;
            this.kind = kind;
            this.changed = changed;
        }
    }

    private OriginalLua() {}

    static Result open(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return null;
        }
        if (startsWith(raw, LUA_MAGIC)) {
            return new Result(raw, "bytecode", false);
        }
        if (looksLikeSource(raw)) {
            return new Result(raw, "source", false);
        }
        byte[] decoded = decodeAndLua(raw);
        if (decoded == null) {
            return null;
        }
        if (startsWith(decoded, LUA_MAGIC)) {
            return new Result(decoded, "bytecode", true);
        }
        if (looksLikeSource(decoded)) {
            return new Result(decoded, "source", true);
        }
        return new Result(decoded, "opened", true);
    }

    static String peek(byte[] data) {
        if (data == null || data.length == 0) {
            return "(empty)";
        }
        int n = Math.min(16, data.length);
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xff;
            if (b >= 32 && b < 127) {
                ascii.append((char) b);
            } else {
                ascii.append('.');
            }
        }
        return ascii + " " + data.length + "b";
    }

    private static byte[] decodeAndLua(byte[] raw) {
        byte[] trimmed = rstrip(raw);
        if (trimmed.length < 8) {
            return null;
        }
        byte first = trimmed[0];
        if (first != '=' && first != 'H' && first != 'h' && !isBase64Char(first)) {
            return null;
        }
        for (int p = 0; p < PREFIXES.length; p++) {
            byte[] modified = new byte[trimmed.length];
            modified[0] = PREFIXES[p][0];
            System.arraycopy(trimmed, 1, modified, 1, trimmed.length - 1);
            byte[] decoded = base64(modified);
            if (decoded == null || decoded.length < 4) {
                continue;
            }
            byte[] out = tryInflateVariants(decoded);
            if (out != null) {
                return fixLuaMagic(out);
            }
        }
        byte[] decoded = base64(trimmed);
        if (decoded != null && decoded.length >= 4) {
            byte[] out = tryInflateVariants(decoded);
            if (out != null) {
                return fixLuaMagic(out);
            }
        }
        return null;
    }

    private static byte[] tryInflateVariants(byte[] decoded) {
        byte[] xored = rollingXor(decoded);
        byte[][] candidates = new byte[][]{xored, decoded};
        for (int i = 0; i < candidates.length; i++) {
            byte[] cur = candidates[i];
            if (cur == null || cur.length < 4) {
                continue;
            }
            byte[] zlib = cur.clone();
            zlib[0] = 0x78;
            byte[] inflated = inflate(zlib);
            if (inflated != null) {
                return inflated;
            }
            inflated = inflate(cur);
            if (inflated != null) {
                return inflated;
            }
        }
        return null;
    }

    private static byte[] rollingXor(byte[] src) {
        byte[] data = new byte[src.length];
        int v = 0;
        for (int i = 0; i < src.length; i++) {
            v ^= src[i] & 0xff;
            data[i] = (byte) v;
        }
        return data;
    }

    private static byte[] inflate(byte[] data) {
        Inflater inf = new Inflater();
        try {
            inf.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n > 0) {
                    out.write(buf, 0, n);
                } else if (inf.needsInput() || inf.needsDictionary()) {
                    break;
                } else if (n == 0) {
                    break;
                }
            }
            if (out.size() < 4) {
                return null;
            }
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        } finally {
            inf.end();
        }
    }

    private static byte[] fixLuaMagic(byte[] data) {
        if (data.length >= 4 && (data[0] & 0xff) == 0x1c && data[1] == 'L' && data[2] == 'u' && data[3] == 'a') {
            byte[] out = data.clone();
            out[0] = 0x1b;
            return out;
        }
        return data;
    }

    private static byte[] base64(byte[] data) {
        try {
            return Base64.decode(data, Base64.DEFAULT);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean looksLikeSource(byte[] data) {
        if (data.length < 8) {
            return false;
        }
        int n = Math.min(data.length, 256);
        int printable = 0;
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xff;
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) {
                printable++;
            }
        }
        if (printable * 10 < n * 8) {
            return false;
        }
        String head = new String(data, 0, Math.min(data.length, 400), StandardCharsets.ISO_8859_1);
        return head.contains("function")
                || head.contains("require")
                || head.contains("local ")
                || head.contains("import ")
                || head.startsWith("--")
                || head.contains("\nfunction")
                || head.contains("\nlocal ");
    }

    static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean isBase64Char(byte b) {
        return (b >= 'A' && b <= 'Z')
                || (b >= 'a' && b <= 'z')
                || (b >= '0' && b <= '9')
                || b == '+' || b == '/' || b == '=' || b == '-';
    }

    private static byte[] rstrip(byte[] data) {
        int end = data.length;
        while (end > 0) {
            byte b = data[end - 1];
            if (b == '\n' || b == '\r' || b == ' ' || b == '\t') {
                end--;
            } else {
                break;
            }
        }
        if (end == data.length) {
            return data;
        }
        byte[] out = new byte[end];
        System.arraycopy(data, 0, out, 0, end);
        return out;
    }
}
