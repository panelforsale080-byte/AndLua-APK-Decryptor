package com.alpprotect;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class AlpCrypto {
    static final byte[] MAGIC = new byte[]{'A', 'X', 'L', '1'};
    static final byte[] MAGIC_LEGACY = new byte[]{'A', 'L', 'P', '2'};
    static final String MARKER = "\n<<<AXL1>>>\n";
    static final String SA = "9F3C1A7E0B24D865E1A90C47B2F6583D";
    static final String SB = "C0A18B47D2E659F301847A5C9B3E12D6";
    static final String LC = "AXL_LCH_SLOT_v1_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    private static final int NONCE_LEN = 12;
    private static final int SALT_LEN = 16;
    private static final int TAG_BITS = 128;
    private static final int ROUNDS = 24576;
    private static final int[] PEPPER = {
            0xA7, 0x31, 0xC4, 0x19, 0x8E, 0x5B, 0xF0, 0x62,
            0x3D, 0xAA, 0x07, 0xD1, 0x94, 0x2C, 0xE8, 0x51,
            0x6F, 0xB3, 0x0A, 0x77, 0xC9, 0x14, 0xDE, 0x38,
            0x91, 0x4F, 0xB8, 0x25, 0x6A, 0xE3, 0x0D, 0x7C
    };

    private AlpCrypto() {}

    static boolean isWrapped(byte[] data) {
        if (data == null) {
            return false;
        }
        if (indexOf(data, MARKER.getBytes(StandardCharsets.UTF_8)) >= 0) {
            return true;
        }
        return startsWith(data, MAGIC) || startsWith(data, MAGIC_LEGACY);
    }

    static String originalLauncher() {
        return LC.trim();
    }

    static byte[] recoverMaster(Context ctx) throws Exception {
        byte[] material = concat(fromHex(SA), fromHex(SB));
        String pkg = ctx.getPackageName();
        return xor(material, bindMask(pkg, apkCert(ctx)));
    }

    static byte[] unwrap(byte[] master, byte[] blob) throws Exception {
        byte[] payload = stripBanner(blob);
        if (startsWith(payload, MAGIC_LEGACY)) {
            return gcmDecryptLegacy(master, payload);
        }
        if (!startsWith(payload, MAGIC) || payload.length < MAGIC.length + 1 + SALT_LEN + 16) {
            return blob;
        }
        ByteBuffer buf = ByteBuffer.wrap(payload);
        buf.position(MAGIC.length);
        int version = buf.get() & 0xff;
        byte[] salt = new byte[SALT_LEN];
        buf.get(salt);
        byte[] outer = new byte[buf.remaining()];
        buf.get(outer);
        byte[] k1 = stretch(master, salt, "AXL-K1");
        byte[] k2 = stretch(master, salt, "AXL-K2");
        if (version == 3) {
            byte[] k3 = stretch(master, salt, "AXL-K3");
            byte[] mid = gcmDecryptRaw(k3, outer);
            byte[] inner = gcmDecryptRaw(k2, mid);
            return unpad(gcmDecryptRaw(k1, inner));
        }
        if (version == 2) {
            byte[] inner = gcmDecryptRaw(k2, outer);
            return unpad(gcmDecryptRaw(k1, inner));
        }
        throw new IllegalStateException("unsupported seal");
    }

    static byte[] bindMask(String packageName, byte[] certDer) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(pepper());
        sha.update("AXL1-BIND-v3".getBytes(StandardCharsets.UTF_8));
        sha.update(packageName.getBytes(StandardCharsets.UTF_8));
        if (certDer != null) {
            sha.update(certDer);
        }
        return sha.digest();
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return out;
    }

    static byte[] stripBanner(byte[] data) {
        byte[] mark = MARKER.getBytes(StandardCharsets.UTF_8);
        int idx = indexOf(data, mark);
        if (idx < 0) {
            return data;
        }
        int start = idx + mark.length;
        byte[] out = new byte[data.length - start];
        System.arraycopy(data, start, out, 0, out.length);
        return out;
    }

    private static byte[] apkCert(Context ctx) throws Exception {
        PackageManager pm = ctx.getPackageManager();
        if (Build.VERSION.SDK_INT >= 28) {
            PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] sigs = pi.signingInfo.getApkContentsSigners();
            return sigs[0].toByteArray();
        }
        PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNATURES);
        return pi.signatures[0].toByteArray();
    }

    private static byte[] gcmDecryptRaw(byte[] key, byte[] blob) throws Exception {
        if (blob.length < NONCE_LEN + 16) {
            throw new IllegalStateException("truncated seal");
        }
        byte[] nonce = new byte[NONCE_LEN];
        System.arraycopy(blob, 0, nonce, 0, NONCE_LEN);
        byte[] ct = new byte[blob.length - NONCE_LEN];
        System.arraycopy(blob, NONCE_LEN, ct, 0, ct.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        return cipher.doFinal(ct);
    }

    private static byte[] gcmDecryptLegacy(byte[] key, byte[] blob) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob);
        buf.position(MAGIC_LEGACY.length);
        buf.get();
        byte[] nonce = new byte[NONCE_LEN];
        buf.get(nonce);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        return cipher.doFinal(ct);
    }

    private static byte[] unpad(byte[] padded) {
        if (padded.length < 2) {
            return padded;
        }
        int n = ((padded[0] & 0xff) << 8) | (padded[1] & 0xff);
        if (n < 0 || 2 + n > padded.length) {
            return padded;
        }
        byte[] out = new byte[padded.length - 2 - n];
        System.arraycopy(padded, 2 + n, out, 0, out.length);
        return out;
    }

    private static byte[] stretch(byte[] master, byte[] salt, String info) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(master);
        sha.update(salt);
        sha.update(info.getBytes(StandardCharsets.UTF_8));
        sha.update(pepper());
        byte[] out = sha.digest();
        for (int i = 1; i < ROUNDS; i++) {
            sha.reset();
            sha.update(out);
            sha.update(salt);
            sha.update((byte) (i >>> 24));
            sha.update((byte) (i >>> 16));
            sha.update((byte) (i >>> 8));
            sha.update((byte) i);
            out = sha.digest();
        }
        return out;
    }

    private static byte[] pepper() {
        byte[] p = new byte[PEPPER.length];
        for (int i = 0; i < PEPPER.length; i++) {
            p[i] = (byte) PEPPER[i];
        }
        return p;
    }

    private static byte[] fromHex(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
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

    private static int indexOf(byte[] data, byte[] needle) {
        if (needle.length == 0 || data.length < needle.length) {
            return -1;
        }
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
