package com.andlua.decryptor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class DexSlots {
    static final String SA = "9F3C1A7E0B24D865E1A90C47B2F6583D";
    static final String SB = "C0A18B47D2E659F301847A5C9B3E12D6";
    static final String LC = "AXL_LCH_SLOT_v1_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    static final String GATE = "com.alpprotect.GateActivity";

    private DexSlots() {}

    static boolean looksLikeStub(byte[] dex) {
        if (dex == null || dex.length < 64) {
            return false;
        }
        return indexOf(dex, "com/alpprotect".getBytes(StandardCharsets.US_ASCII)) >= 0
                || indexOf(dex, GATE.getBytes(StandardCharsets.US_ASCII)) >= 0
                || indexOf(dex, SA.getBytes(StandardCharsets.US_ASCII)) >= 0
                || indexOf(dex, "AlpRuntime".getBytes(StandardCharsets.US_ASCII)) >= 0;
    }

    static byte[] recoverMaster(byte[] stubDex, String pkg, byte[] certDer, byte[] sampleWrapped)
            throws Exception {
        byte[] mask = SealCrypto.bindMask(pkg, certDer);
        List<String> hex = hex32(readStrings(stubDex));
        if (hex.isEmpty()) {
            hex = hex32Raw(stubDex);
        }
        hex.remove(SA);
        hex.remove(SB);
        for (int i = 0; i < hex.size(); i++) {
            for (int j = 0; j < hex.size(); j++) {
                if (i == j) {
                    continue;
                }
                byte[] material = concat(fromHex(hex.get(i)), fromHex(hex.get(j)));
                if (material.length != 32) {
                    continue;
                }
                byte[] master = SealCrypto.xor(material, mask);
                try {
                    SealCrypto.unwrap(master, sampleWrapped);
                    return master;
                } catch (Exception ignored) {
                }
            }
        }
        throw new IllegalStateException("This package cannot be decrypted");
    }

    static String originalLauncher(byte[] stubDex) {
        List<String> strings = readStrings(stubDex);
        for (String s : strings) {
            if (s == null) {
                continue;
            }
            if (s.equals(LC)) {
                continue;
            }
            if (s.length() == LC.length()) {
                String t = s.trim();
                if (isClassName(t) && !t.startsWith("com.alpprotect.")) {
                    return t;
                }
            }
        }
        for (String s : strings) {
            if (s == null) {
                continue;
            }
            String t = s.trim();
            if (isClassName(t) && t.endsWith("Activity") && !t.startsWith("com.alpprotect.")) {
                return t;
            }
        }
        return null;
    }

    private static boolean isClassName(String t) {
        if (t.length() < 3 || t.indexOf('.') < 0) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '$')) {
                return false;
            }
        }
        return true;
    }

    private static List<String> hex32(List<String> strings) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String s : strings) {
            if (s != null && s.length() == 32 && isHex(s) && seen.add(s)) {
                out.add(s);
            }
        }
        return out;
    }

    private static List<String> hex32Raw(byte[] dex) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int i = 0;
        while (i < dex.length) {
            if (isHexByte(dex[i])) {
                int j = i;
                while (j < dex.length && isHexByte(dex[j])) {
                    j++;
                }
                if (j - i == 32) {
                    String s = new String(dex, i, 32, StandardCharsets.US_ASCII);
                    if (seen.add(s)) {
                        out.add(s);
                    }
                }
                i = j;
            } else {
                i++;
            }
        }
        return out;
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!isHexChar(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHexByte(byte b) {
        return isHexChar((char) (b & 0xff));
    }

    private static boolean isHexChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    static List<String> readStrings(byte[] dex) {
        List<String> out = new ArrayList<>();
        if (dex.length < 112 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') {
            return out;
        }
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        if (stringIdsSize < 0 || stringIdsSize > 200000) {
            return out;
        }
        for (int i = 0; i < stringIdsSize; i++) {
            int pos = stringIdsOff + i * 4;
            if (pos < 0 || pos + 4 > dex.length) {
                break;
            }
            int off = buf.getInt(pos);
            String s = readMutf8(dex, off);
            if (s != null) {
                out.add(s);
            }
        }
        return out;
    }

    private static String readMutf8(byte[] dex, int off) {
        if (off < 0 || off >= dex.length) {
            return null;
        }
        int[] idx = new int[]{off};
        skipUleb(dex, idx);
        int start = idx[0];
        int end = start;
        while (end < dex.length && dex[end] != 0) {
            end++;
        }
        if (end > dex.length) {
            return null;
        }
        try {
            return new String(dex, start, end - start, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return new String(dex, start, end - start, StandardCharsets.ISO_8859_1);
        }
    }

    private static void skipUleb(byte[] dex, int[] idx) {
        while (idx[0] < dex.length) {
            int b = dex[idx[0]] & 0xff;
            idx[0]++;
            if ((b & 0x80) == 0) {
                return;
            }
        }
    }

    static byte[] fromHex(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int indexOf(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
