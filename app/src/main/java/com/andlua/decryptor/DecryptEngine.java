package com.andlua.decryptor;

import android.content.Context;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.archive.InputSource;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class DecryptEngine {
    static final String GATE = "com.alpprotect.GateActivity";

    private DecryptEngine() {}

    static File decrypt(Context ctx, File inputApk, File outputApk) throws Exception {
        ApkModule apk = ApkModule.loadApkFile(inputApk);
        try {
            AndroidManifestBlock manifest = apk.getAndroidManifest();
            if (manifest == null) {
                throw new IllegalStateException("This package cannot be decrypted");
            }
            String pkg = manifest.getPackageName();
            String currentLauncher = manifest.getMainActivityClassName();
            boolean hasGate = GATE.equals(currentLauncher);

            byte[] certDer = null;
            try {
                certDer = Signer.apkCertDer(inputApk);
            } catch (Exception ignored) {
            }

            byte[] keyFile = readOptional(apk, "assets/alpprotect.key");
            String fileLauncher = readOptionalString(apk, "assets/alpprotect.launcher");

            StubRef stub = findStub(apk);
            byte[] sampleWrapped = firstWrapped(apk);
            boolean anyWrapped = sampleWrapped != null;

            if (!anyWrapped && !hasGate && stub == null && keyFile == null) {
                throw new IllegalStateException("This package cannot be decrypted");
            }

            byte[] master = null;
            if (keyFile != null && keyFile.length == 32) {
                master = keyFile;
            }
            if (master == null && stub != null && sampleWrapped != null && certDer != null) {
                master = DexSlots.recoverMaster(stub.data, pkg, certDer, sampleWrapped);
            }

            String originalLauncher = fileLauncher;
            if ((originalLauncher == null || originalLauncher.length() == 0) && stub != null) {
                originalLauncher = DexSlots.originalLauncher(stub.data);
            }
            if ((originalLauncher == null || originalLauncher.length() == 0)
                    && currentLauncher != null && !GATE.equals(currentLauncher)) {
                originalLauncher = currentLauncher;
            }
            if (originalLauncher != null) {
                originalLauncher = originalLauncher.trim();
            }

            int stillWrapped = 0;
            List<String> luaPaths = luaPaths(apk);
            for (String path : luaPaths) {
                InputSource src = apk.getInputSource(path);
                byte[] raw = readSource(src);
                if (!SealCrypto.isWrapped(raw)) {
                    continue;
                }
                if (master == null) {
                    stillWrapped++;
                    continue;
                }
                try {
                    byte[] inner = SealCrypto.unwrap(master, raw);
                    apk.removeInputSource(path);
                    apk.add(new ByteInputSource(inner, path));
                } catch (Exception e) {
                    stillWrapped++;
                }
            }

            if (stillWrapped == 0) {
                if (hasGate) {
                    if (originalLauncher == null || originalLauncher.length() == 0) {
                        throw new IllegalStateException("This package cannot be decrypted");
                    }
                    manifest.setMainActivityClassName(originalLauncher);
                    apk.refreshManifest();
                }
                if (stub != null) {
                    apk.removeInputSource(stub.name);
                }
                apk.removeInputSource("assets/alpprotect.key");
                apk.removeInputSource("assets/alpprotect.launcher");
            } else {
                if (master == null || originalLauncher == null || originalLauncher.length() == 0) {
                    throw new IllegalStateException("This package cannot be decrypted");
                }
                byte[] stubDex = readAsset(ctx, "alpprotect-runtime.dex");
                if (stubDex.length < 64) {
                    throw new IllegalStateException("This package cannot be decrypted");
                }
                byte[] ourCert = Signer.certDer(ctx);
                byte[] material = SealCrypto.xor(master, SealCrypto.bindMask(pkg, ourCert));
                stubDex = patchDex(stubDex, material, originalLauncher);
                if (stub != null) {
                    apk.removeInputSource(stub.name);
                }
                injectRuntimeDex(apk, stubDex);
                manifest.setMainActivityClassName(GATE);
                apk.refreshManifest();
            }

            stripSignatures(apk);

            File unsigned = new File(ctx.getCacheDir(), "unsigned-" + outputApk.getName());
            if (unsigned.exists()) {
                unsigned.delete();
            }
            apk.writeApk(unsigned);
            Signer.sign(ctx, unsigned, outputApk);
            if (!unsigned.delete()) {
                unsigned.deleteOnExit();
            }
            return outputApk;
        } finally {
            apk.close();
        }
    }

    private static List<String> luaPaths(ApkModule apk) {
        List<String> luaPaths = new ArrayList<>();
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name != null && name.startsWith("assets/") && name.toLowerCase().endsWith(".lua")) {
                luaPaths.add(name);
            }
        }
        return luaPaths;
    }

    private static byte[] firstWrapped(ApkModule apk) throws Exception {
        for (String path : luaPaths(apk)) {
            byte[] raw = readSource(apk.getInputSource(path));
            if (SealCrypto.isWrapped(raw)) {
                return raw;
            }
        }
        return null;
    }

    private static StubRef findStub(ApkModule apk) throws Exception {
        StubRef found = null;
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name == null || !name.toLowerCase().endsWith(".dex")) {
                continue;
            }
            byte[] data = readSource(src);
            if (DexSlots.looksLikeStub(data)) {
                found = new StubRef(name, data);
            }
        }
        return found;
    }

    private static byte[] patchDex(byte[] dex, byte[] material, String launcher) {
        if (material.length != 32) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        byte[] a = toHex(material, 0, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] b = toHex(material, 16, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] out = dex;
        out = replaceOnce(out, DexSlots.SA.getBytes(StandardCharsets.US_ASCII), a);
        out = replaceOnce(out, DexSlots.SB.getBytes(StandardCharsets.US_ASCII), b);
        out = replaceOnce(out, DexSlots.LC.getBytes(StandardCharsets.US_ASCII),
                padAscii(launcher, DexSlots.LC.length()));
        return out;
    }

    private static byte[] replaceOnce(byte[] hay, byte[] needle, byte[] repl) {
        if (needle.length != repl.length) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        int at = indexOf(hay, needle);
        if (at < 0) {
            throw new IllegalStateException("This package cannot be decrypted");
        }
        byte[] out = new byte[hay.length];
        System.arraycopy(hay, 0, out, 0, hay.length);
        System.arraycopy(repl, 0, out, at, repl.length);
        return out;
    }

    private static byte[] padAscii(String value, int len) {
        String trimmed = value.length() > len ? value.substring(0, len) : value;
        StringBuilder sb = new StringBuilder(len);
        sb.append(trimmed);
        while (sb.length() < len) {
            sb.append(' ');
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static String toHex(byte[] data, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", data[off + i] & 0xff));
        }
        return sb.toString();
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

    private static void injectRuntimeDex(ApkModule apk, byte[] stubDex) {
        int max = 0;
        for (InputSource src : apk.getInputSources()) {
            int n = InputSource.getDexNumber(src.getName());
            if (n > max) {
                max = n;
            }
        }
        int next = max <= 0 ? 2 : max + 1;
        String name = "classes" + next + ".dex";
        apk.removeInputSource(name);
        apk.add(new ByteInputSource(stubDex, name));
    }

    private static void stripSignatures(ApkModule apk) {
        apk.setApkSignatureBlock(null);
        List<String> remove = new ArrayList<>();
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name == null) {
                continue;
            }
            String upper = name.toUpperCase();
            if (upper.startsWith("META-INF/") && (
                    upper.endsWith(".SF")
                            || upper.endsWith(".RSA")
                            || upper.endsWith(".DSA")
                            || upper.endsWith(".EC")
                            || upper.endsWith("MANIFEST.MF")
                            || upper.contains("SIG-"))) {
                remove.add(name);
            }
        }
        for (String name : remove) {
            apk.removeInputSource(name);
        }
    }

    private static byte[] readOptional(ApkModule apk, String path) {
        try {
            InputSource src = apk.getInputSource(path);
            if (src == null) {
                return null;
            }
            return readSource(src);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readOptionalString(ApkModule apk, String path) {
        byte[] data = readOptional(apk, path);
        if (data == null) {
            return null;
        }
        return new String(data, StandardCharsets.UTF_8).trim();
    }

    private static byte[] readSource(InputSource src) throws Exception {
        InputStream in = src.openStream();
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static final class StubRef {
        final String name;
        final byte[] data;

        StubRef(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }
}
